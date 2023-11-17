package metrics

import (
	"github.com/cilium/ebpf"
	"github.com/moolen/neuwerk/pkg/log"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	logger = log.DefaultLogger.WithName("metrics")

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

	DNSCacheMiss = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_cache_miss",
	}, []string{})

	DNSCacheHit = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_cache_hit",
	}, []string{})

	GCStaleDistributedState = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "gc_stale_distributed_state_duration_seconds",
		Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10, 20, 45},
	}, []string{ResultLabel})

	BPFReconcileMapsDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "bpf_reconcile_maps_duration_seconds",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10, 20, 30},
	}, []string{ResultLabel})

	PacketsProcessed = prometheus.NewDesc(
		"bpf_packets_processed",
		"Number of packets processed",
		[]string{"node", "type"}, nil,
	)
	RingbufDataAvailable    = prometheus.NewDesc("ringbuf_data_available", "", nil, nil)
	RingbufRingSize         = prometheus.NewDesc("ringbuf_ring_size", "", nil, nil)
	RingbufConsumerPosition = prometheus.NewDesc("ringbuf_consumer_position", "", nil, nil)
	RingbufProducerPosition = prometheus.NewDesc("ringbuf_producer_position", "", nil, nil)
)

var (
	// sync with ingress.c
	METRICS_PKT_ALLOWED         = uint32(1)
	METRICS_PKT_REDIRECT        = uint32(2)
	METRICS_PKT_BLOCKED         = uint32(3)
	METRICS_RINGBUF_AVAIL_DATA  = uint32(100)
	METRICS_RINGBUF_RING_SIZE   = uint32(101)
	METRICS_RINGBUF_CONS_POS    = uint32(102)
	METRICS_RINGBUF_PROD_POS    = uint32(103)
	METRICS_ERROR_RINGBUF_ALLOC = uint32(500)
)

func InitializeCollector(nodeName string, metricsMap *ebpf.Map) {
	prometheus.MustRegister(RejectedDNSQueryCount)
	prometheus.MustRegister(DNSRequestDuration)
	prometheus.MustRegister(DNSUpstreamDuration)
	prometheus.MustRegister(GCStaleDistributedState)
	prometheus.MustRegister(BPFReconcileMapsDuration)
	prometheus.MustRegister(&MetricsCollector{
		nodeName:   nodeName,
		metricsMap: metricsMap,
	})
}

type MetricsCollector struct {
	nodeName   string
	metricsMap *ebpf.Map
}

func (cc MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(cc, ch)
}

func (cc MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	// metric index in bpf map => label value
	// indices are defined in ingress.c
	metrics := map[uint32][]string{
		METRICS_PKT_ALLOWED:  {cc.nodeName, "allow"},
		METRICS_PKT_REDIRECT: {cc.nodeName, "redirect"},
		METRICS_PKT_BLOCKED:  {cc.nodeName, "block"},
	}

	for key, lblValues := range metrics {
		var val uint32
		err := cc.metricsMap.Lookup(key, &val)
		if err != nil && err != ebpf.ErrKeyNotExist {
			continue
		}
		ch <- prometheus.MustNewConstMetric(PacketsProcessed, prometheus.CounterValue, float64(val), lblValues...)
	}

	for key, gauge := range map[uint32]*prometheus.Desc{
		METRICS_RINGBUF_AVAIL_DATA: RingbufDataAvailable,
		METRICS_RINGBUF_RING_SIZE:  RingbufRingSize,
		METRICS_RINGBUF_CONS_POS:   RingbufConsumerPosition,
		METRICS_RINGBUF_PROD_POS:   RingbufProducerPosition,
	} {
		// ringbuf gauge values
		var val uint32
		err := cc.metricsMap.Lookup(key, &val)
		if err != nil && err != ebpf.ErrKeyNotExist {
			logger.V(1).Info("unable to lookup metric", "err", err, "key", key)
			continue
		}
		ch <- prometheus.MustNewConstMetric(gauge, prometheus.GaugeValue, float64(val))
	}
}
