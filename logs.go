package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type CtLogListResponseOperatorLog struct {
	Description string `json:"description"`
	LogID       string `json:"log_id"`
	Key         string `json:"key"`
	Url         string `json:"url"`
	Mmd         int64  `json:"mmd"`
	State       struct {
		Rejected *struct {
			Timestamp string `json:"timestamp"`
		} `json:"rejected"`
		Usable *struct {
			Timestamp string `json:"timestamp"`
		} `json:"usable"`
	} `json:"state"`
	TemporalInterval struct {
		StartInclusive string `json:"start_inclusive"`
		EndExclusive   string `json:"end_exclusive"`
	} `json:"temporal_interval"`
}
type CtLogListResponseOperator struct {
	Name  string                         `json:"name"`
	Email []string                       `json:"email"`
	Logs  []CtLogListResponseOperatorLog `json:"logs"`
}

type CtLogListResponse struct {
	Version          string                      `json:"version"`
	LogListTimestamp string                      `json:"log_list_timestamp"`
	Operators        []CtLogListResponseOperator `json:"operators"`
}

type CtLogUpdateLog struct {
	OperatorName string
	Description  string
	Url          string
	LogID        string
}

type CtLogUpdate struct {
	Logs         []CtLogUpdateLog
	LastModified string
}

func getGoogleCTLogs(url string, lastModified string) (CtLogUpdate, error) {

	update := CtLogUpdate{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return update, fmt.Errorf("failed to request ct logs: %s", err.Error())
	}

	req.Header.Set("if-modified-since", lastModified)
	req.Header.Add("user-agent", "github.com/janic0/certalert")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return update, fmt.Errorf("failed to get ct logs: %s", err.Error())
	}

	if resp.StatusCode == 304 {
		return update, fmt.Errorf("no update required")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return update, fmt.Errorf("failed to read ct log response: %s", err.Error())
	}

	parsedResponse := CtLogListResponse{}

	err = json.Unmarshal(body, &parsedResponse)
	if err != nil {
		return update, fmt.Errorf("failed to parse ct log response: %s", err.Error())
	}

	update.LastModified = resp.Header.Get("Last-Modified")
	for _, operator := range parsedResponse.Operators {
		for _, log := range operator.Logs {

			if log.State.Usable == nil {
				continue
			}

			update.Logs = append(update.Logs, CtLogUpdateLog{
				OperatorName: operator.Name,
				Description:  log.Description,
				Url:          log.Url,
				LogID:        log.LogID,
			})

		}
	}

	return update, nil

}
