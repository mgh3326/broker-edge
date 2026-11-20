package gatewayd

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const ensureMetricStateFailed = "failed"

// Fetch outcome labels are the closed set of HTTP results; the source label is
// the token source on success and "none" otherwise. The provider label is a
// known provider or "unknown": request-controlled text never becomes a label.
const (
	fetchOutcomeOK                           = "ok"
	fetchMetricNoSource                      = "none"
	fetchMetricUnknownProvider TokenProvider = "unknown"
)

var fetchFailureOutcomes = []string{"unauthenticated", "provider_not_allowed", "unknown_provider", "bad_request", "issue_unavailable"}

// Metrics owns gatewayd's daemon-local Prometheus registry. Like the edge
// registry, it includes standard Go and process collectors rather than relying
// on the process-global default registry.
type Metrics struct {
	registry       *prometheus.Registry
	ensureOutcomes *prometheus.CounterVec
	fetchOutcomes  *prometheus.CounterVec
}

// NewMetrics creates the bounded gatewayd metrics surface.
func NewMetrics() *Metrics {
	registry := prometheus.NewRegistry()
	metrics := &Metrics{
		registry: registry,
		ensureOutcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatewayd_ensure_results_total",
			Help: "Total token ensure outcomes by configured provider and result state.",
		}, []string{"provider", "state"}),
		fetchOutcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatewayd_fetch_results_total",
			Help: "Total token fetch outcomes by provider, outcome and token source.",
		}, []string{"provider", "outcome", "source"}),
	}
	registry.MustRegister(
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
		metrics.ensureOutcomes,
		metrics.fetchOutcomes,
	)
	for _, provider := range orderedProviders() {
		for _, state := range []string{string(EnsureStateFresh), string(EnsureStateIssued), ensureMetricStateFailed} {
			metrics.ensureOutcomes.WithLabelValues(string(provider), state)
		}
	}
	for _, provider := range append(orderedProviders(), fetchMetricUnknownProvider) {
		for _, source := range []FetchSource{FetchSourceMemory, FetchSourceRedis, FetchSourceIssued} {
			metrics.fetchOutcomes.WithLabelValues(string(provider), fetchOutcomeOK, string(source))
		}
		for _, outcome := range fetchFailureOutcomes {
			metrics.fetchOutcomes.WithLabelValues(string(provider), outcome, fetchMetricNoSource)
		}
	}
	return metrics
}

func (metrics *Metrics) handler() http.Handler {
	if metrics == nil || metrics.registry == nil {
		metrics = NewMetrics()
	}
	return promhttp.HandlerFor(metrics.registry, promhttp.HandlerOpts{})
}

func (metrics *Metrics) recordEnsure(provider TokenProvider, state EnsureState, failed bool) {
	if metrics == nil || metrics.ensureOutcomes == nil || !knownProvider(provider) {
		return
	}
	label := ensureMetricStateFailed
	if !failed {
		switch state {
		case EnsureStateFresh, EnsureStateIssued:
			label = string(state)
		}
	}
	metrics.ensureOutcomes.WithLabelValues(string(provider), label).Inc()
}

// recordFetch counts one /fetch result. outcome must be fetchOutcomeOK or one of
// fetchFailureOutcomes; anything else is dropped rather than creating a series.
func (metrics *Metrics) recordFetch(provider TokenProvider, outcome string, source FetchSource) {
	if metrics == nil || metrics.fetchOutcomes == nil {
		return
	}
	providerLabel := fetchMetricUnknownProvider
	if knownProvider(provider) {
		providerLabel = provider
	}
	sourceLabel := fetchMetricNoSource
	if outcome == fetchOutcomeOK {
		switch source {
		case FetchSourceMemory, FetchSourceRedis, FetchSourceIssued:
			sourceLabel = string(source)
		default:
			return
		}
	} else if !validFetchFailure(outcome) {
		return
	}
	metrics.fetchOutcomes.WithLabelValues(string(providerLabel), outcome, sourceLabel).Inc()
}

func validFetchFailure(outcome string) bool {
	for _, known := range fetchFailureOutcomes {
		if outcome == known {
			return true
		}
	}
	return false
}
