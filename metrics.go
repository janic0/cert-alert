package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var prometheusLogCertsScanned = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "certalert_log_certs_ingested_total",
	Help: "The number of certs observed per log",
}, []string{"log_operator", "log_description"})

var prometheusLogDomainsScanned = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "certalert_log_dns_names_ingested_total",
	Help: "The number of dns names observed per log",
}, []string{"log_operator", "log_description"})

var prometheusLogTreeSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "certalert_log_tree_size",
	Help: "The tree size of the log",
}, []string{"log_operator", "log_description"})

var prometheusLogEntryRequest = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "certalert_log_entry_request",
	Help: "The tree size of the log",
}, []string{"log_operator", "log_description"})

var prometheusLogIngestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "certalert_log_ingest_duration_seconds",
	Help:    "The time it took to update a specific log",
	Buckets: []float64{1, 10, 20, 30, 40, 50, 60, 90, 120, 240, 300},
}, []string{"log_operator", "log_description"})

var prometheusLogIterationsMissed = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "certalert_log_iterations_missed_count",
	Help: "The amount of missed iterations",
}, []string{"log_operator", "log_description"})

var prometheusLogIterationsSkipped = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "certalert_log_iterations_skipped_count",
	Help: "The amount of skipped iterations",
}, []string{"log_operator", "log_description"})

var prometheusIterationCount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "certalert_iteration_count",
	Help: "The amount of iterations",
})
