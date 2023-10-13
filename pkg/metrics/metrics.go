package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	ResultLabel     = "result"
	ResultCodeOK    = "ok"
	ResultCodeError = "error"

	RejectedDNSQueryCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "rejected_dns_query_count",
	}, []string{})

	DNSRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "dns_request_duration_seconds",
		Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25},
	}, []string{ResultLabel})

	DNSUpstreamDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "dns_request_upstream_duration_seconds",
		Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25},
	}, []string{ResultLabel})

	GCStaleDistributedState = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "gc_stale_distributed_state_duration_seconds",
		Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10, 20, 45},
	}, []string{ResultLabel})

	BPFReconcileMapsDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "bpf_reconcile_maps_duration_seconds",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5},
	}, []string{ResultLabel})
)

func init() {
	prometheus.MustRegister(DNSRequestDuration)
	prometheus.MustRegister(DNSUpstreamDuration)
}
