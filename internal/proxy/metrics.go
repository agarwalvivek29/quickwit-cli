package proxy

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/agarwalvivek29/quickwit-cli/internal/audit"
)

// Metrics holds the Prometheus collectors for qwproxy. Construct with
// NewMetrics; pass nil into Options.Metrics to disable metrics (e.g. in tests).
type Metrics struct {
	requests     *prometheus.CounterVec
	duration     *prometheus.HistogramVec
	authFailures prometheus.Counter
}

// NewMetrics registers the proxy collectors (and audit-writer gauges) on reg.
func NewMetrics(reg prometheus.Registerer, w *audit.Writer) *Metrics {
	m := &Metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "qwproxy_requests_total",
			Help: "Proxied requests by method and response code.",
		}, []string{"method", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "qwproxy_request_duration_seconds",
			Help:    "End-to-end proxied request duration.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method"}),
		authFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "qwproxy_auth_failures_total",
			Help: "Requests rejected for missing/invalid tokens.",
		}),
	}
	reg.MustRegister(m.requests, m.duration, m.authFailures)

	if w != nil {
		reg.MustRegister(
			prometheus.NewCounterFunc(prometheus.CounterOpts{
				Name: "qwproxy_audit_dropped_total",
				Help: "Audit records dropped (buffer full or insert failed).",
			}, func() float64 { return float64(w.Dropped()) }),
			prometheus.NewCounterFunc(prometheus.CounterOpts{
				Name: "qwproxy_audit_written_total",
				Help: "Audit records successfully persisted.",
			}, func() float64 { return float64(w.Written()) }),
		)
	}
	return m
}

func (h *Handler) metricAuthFail() {
	if h.opts.Metrics != nil {
		h.opts.Metrics.authFailures.Inc()
	}
}

func (h *Handler) metricRequest(method string, code int, d time.Duration) {
	if h.opts.Metrics == nil {
		return
	}
	h.opts.Metrics.requests.WithLabelValues(method, strconv.Itoa(code)).Inc()
	h.opts.Metrics.duration.WithLabelValues(method).Observe(d.Seconds())
}
