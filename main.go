package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	ctgo "github.com/google/certificate-transparency-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var CT_FETCH_INTERVAL = 1 * time.Minute

type Entry struct {
	LeafInput ctgo.LeafInput `json:"leaf_input"`
	ExtraData string         `json:"extra_data"`
}

type Message struct {
	Title   string
	Message string
}

type ConfigFormat struct {
	Logs    []string
	Queries []string
}

type NotifyInstruction struct {
	Certificate    *x509.Certificate
	Watchers       []WatcherConfig
	LogDescription string
}

var MessageQueue = make(chan Message)

func getSTH(root string) (int64, error) {
	req, err := http.NewRequest("GET", root+"ct/v1/get-sth", nil)
	req.Header.Add("user-agent", "github.com/janic0/certalert")

	if err != nil {
		return 0, err
	}
	rq, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}

	if rq.StatusCode > 299 {
		return 0, fmt.Errorf("log sth request failed with status %d", rq.StatusCode)
	}

	responseText, err := io.ReadAll(rq.Body)
	if err != nil {
		return 0, err
	}

	decodedResponse := struct {
		TreeSize int64 `json:"tree_size"`
	}{}
	err = json.Unmarshal(responseText, &decodedResponse)
	if err != nil {
		fmt.Println("log sth failed with status", rq.Status)
		return 0, err
	}
	return decodedResponse.TreeSize, nil
}

func getEntries(root string, start int64, end int64) ([]ctgo.LeafEntry, error) {
	req, err := http.NewRequest("GET", root+"ct/v1/get-entries", nil)
	req.Header.Add("user-agent", "github.com/janic0/certalert")
	if err != nil {
		return make([]ctgo.LeafEntry, 0), err
	}
	query := req.URL.Query()
	query.Add("start", strconv.Itoa(int(start)))
	query.Add("end", strconv.Itoa(int(end)))
	req.URL.RawQuery = query.Encode()
	rq, err := http.DefaultClient.Do(req)
	if err != nil {
		return make([]ctgo.LeafEntry, 0), err
	}
	responseText, err := io.ReadAll(rq.Body)
	if err != nil {
		return make([]ctgo.LeafEntry, 0), err
	}

	decodedResponse := struct {
		Entries []ctgo.LeafEntry `json:"entries"`
	}{}
	err = json.Unmarshal(responseText, &decodedResponse)
	if err != nil {
		fmt.Println("log entry failed with status", rq.Status)
		return decodedResponse.Entries, err
	}
	return decodedResponse.Entries, nil
}

func updateLog(ctx context.Context, log CtLogUpdateLog, lastTreeSizes *sync.Map, prometheusLabels prometheus.Labels, config Config, notifyInstructionChannel chan NotifyInstruction) bool {

	timeStart := time.Now()

	treeSize, err := getSTH(log.Url)
	if err != nil {
		fmt.Printf("Failed to get STH @ %s: %s\n", log, err.Error())
		return false
	}

	lastTreeSizeValue, hasTreeSize := lastTreeSizes.Swap(log.LogID, treeSize)

	prometheusLogTreeSize.With(prometheusLabels).Set(float64(treeSize))

	if !hasTreeSize || lastTreeSizeValue == nil || lastTreeSizeValue.(int64) == int64(0) {
		fmt.Println("skipping", log.Description, "due to low previous tree size (", lastTreeSizeValue, ")")

		return true
	}

	lastTreeSize := lastTreeSizeValue.(int64)

	gap := treeSize - lastTreeSize

	// gap of 10m is too big, so we bail
	if gap > config.LogCollection.MaxHandleableLogGap {
		prometheusLogIterationsSkipped.With(prometheusLabels).Inc()
		fmt.Println("skipping", log.Description, "due to low excessive gap (", gap, ")")
		return true
	}

	if gap == 0 {
		return true
	}

	entriesHandled := int64(0)

	for entriesHandled < gap {

		prometheusLogEntryRequest.With(prometheusLabels).Inc()
		currentEntries, err := getEntries(log.Url, lastTreeSize+entriesHandled, treeSize-1)

		if err != nil {
			fmt.Printf("Failed to get entries @ %s: %s\n", log, err.Error())
			break
		} else {
			// batchSize += int64(len(currentEntries))
			for _, entry := range currentEntries {

				prometheusLogCertsScanned.With(prometheusLabels).Inc()

				rle, err := ctgo.RawLogEntryFromLeaf(lastTreeSize+entriesHandled, &entry)
				entriesHandled++

				if err != nil {
					fmt.Println("Failed to decode entry", err.Error())
					continue
				}

				cert, err := x509.ParseCertificate(rle.Cert.Data)

				if err != nil {
					fmt.Println("Failed to parse certificate", err.Error())
					continue
				}

				watchers, _ := config.WatchersFor(cert.Subject.CommonName)

				for _, dnsName := range cert.DNSNames {

					prometheusLogDomainsScanned.With(prometheusLabels).Inc()

					dnsNameWatchers, matchedAny := config.WatchersFor(dnsName)
					if !matchedAny {
						continue
					}

					watchers = append(watchers, dnsNameWatchers...)

				}

				if len(watchers) > 0 {
					notifyInstructionChannel <- NotifyInstruction{
						Certificate:    cert,
						Watchers:       watchers,
						LogDescription: log.Description,
					}
				}

			}

		}
	}

	prometheusLogIngestDuration.With(prometheusLabels).Observe(time.Since(timeStart).Seconds())

	return true

}

func main() {

	config, err := LoadConfigFile("config/config.yml")
	if err != nil {
		panic(fmt.Errorf("failed to read config/config.yml: %s", err.Error()))
	}

	lastTreeSizes := sync.Map{}
	ctx, cancel := context.WithCancel(context.TODO())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case <-sigChan:
			{
				cancel()
				return
			}

		}
	}()

	logUpdate := CtLogUpdate{}
	if config.LogCollection.GoogleLogListURL != "" {
		logUpdate, err = getGoogleCTLogs(config.LogCollection.GoogleLogListURL, "")
		if err != nil {
			panic("failed to get log list: " + err.Error())
		}
	}

	lastLogUpdate := time.Now()
	metricsServer := http.Server{
		Addr: "0.0.0.0:2112",
	}

	if config.Prometheus.Enabled {

		metricsServer.Handler = promhttp.Handler()

		go func() {
			err := metricsServer.ListenAndServe()
			if err != nil {
				fmt.Println("failed to start http server: ", err.Error())
			}
		}()
	}

	// collect notifications centrally for deduplication
	notifyInstructionChannel := make(chan NotifyInstruction)
	defangReplacer := strings.NewReplacer(".", "[.]")
	go func() {

		coveredCertificateSerials := sync.Map{}

		for {
			select {

			case entry := <-notifyInstructionChannel:
				{

					certSerial := entry.Certificate.SerialNumber.String()
					_, isDuplicate := coveredCertificateSerials.LoadOrStore(certSerial, true)
					if isDuplicate {
						// skip
						continue
					}

					title := "Certalert: Found matching certificate"
					message := fmt.Sprintf(
						"Issuer: %s\nSubject: %s\nDNS Names: %s\nLog: %s\nValid after: %s\nValid until: %s\nSerial: %X",
						entry.Certificate.Issuer.String(),
						defangReplacer.Replace(entry.Certificate.Subject.String()),
						defangReplacer.Replace(strings.Join(entry.Certificate.DNSNames, ", ")),
						entry.LogDescription,
						entry.Certificate.NotBefore.String(),
						entry.Certificate.NotAfter.String(),
						entry.Certificate.SerialNumber,
					)

					for _, watcher := range entry.Watchers {
						errors := watcher.Notify(title, message)
						for _, err := range errors {
							if err == nil {
								continue
							}
							fmt.Println("failed to notify watcher", err)

						}

					}

				}
			case <-ctx.Done():
				{

					// graceful exit
					break
				}

			}
		}

	}()

	// monitor amount of buffered items
	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "certalert_instruction_channel_buffered_items",
		Help: "The amount of batches currently waiting to be completed",
	}, func() float64 {
		return float64(len(notifyInstructionChannel))
	})

	lockMap := map[string]*sync.Mutex{}
	failureStreak := sync.Map{}

	for {

		// reload configuration in every iteration
		config, err := LoadConfigFile("config/config.yml")
		if err != nil {
			fmt.Println("failed to load new config:", err.Error())
			time.Sleep(time.Second)
			continue
		}

		select {

		case <-ctx.Done():
			{
				fmt.Println("recevied shutdown signal, shutting down...")
				metricsServer.Shutdown(context.TODO())
				return
			}

		case <-time.After(config.LogCollection.LogRenewalInterval.Duration):
			{

				logsToUpdate := []CtLogUpdateLog{}

				if config.LogCollection.GoogleLogListURL != "" {

					// update if needed?
					if time.Now().Sub(lastLogUpdate).Minutes() > 5 {
						newLogUpdate, err := getGoogleCTLogs(config.LogCollection.GoogleLogListURL, logUpdate.LastModified)
						lastLogUpdate = time.Now()
						if err != nil {
							fmt.Println("failed to update ct logs. retrying at next iteration: ", err.Error())
						} else {
							logUpdate = newLogUpdate
						}
					}

					for _, log := range logUpdate.Logs {
						logsToUpdate = append(logsToUpdate, log)
					}

				}

				for _, customLogUrl := range config.LogCollection.LogsURLs {
					logsToUpdate = append(logsToUpdate, CtLogUpdateLog{
						OperatorName: "unknown",
						Description:  customLogUrl,
						Url:          customLogUrl,
						LogID:        customLogUrl,
					})
				}

				for _, log := range logUpdate.Logs {

					mutex, hasMutex := lockMap[log.LogID]
					if !hasMutex {
						mutex = &sync.Mutex{}
						lockMap[log.LogID] = mutex
					}

					canLock := mutex.TryLock()
					prometheusLabels := prometheus.Labels{"log_operator": log.OperatorName, "log_description": log.Description}

					// skip if last iteration is still processing
					if !canLock {
						prometheusLogIterationsMissed.With(prometheusLabels).Inc()
						continue
					}

					go func() {
						wasOk := updateLog(ctx, log, &lastTreeSizes, prometheusLabels, *config, notifyInstructionChannel)
						if !wasOk {

							value, loaded := failureStreak.LoadOrStore(log.LogID, int64(0))
							if loaded {
								failureStreak.Store(log.LogID, value.(int64)+1)
							}

							waitingCount := (value.(int64) * 5) + 1

							// fmt.Println(log.Description, "failed, waiting ", waitingCount*60, "s")
							time.Sleep(time.Duration(waitingCount) * time.Minute)
						} else {
							failureStreak.Delete(log.LogID)
						}

						mutex.Unlock()

					}()

				}

				prometheusIterationCount.Inc()

			}
		}
	}

}
