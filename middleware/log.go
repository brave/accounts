package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
)

type statusTrackingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *statusTrackingResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func LoggerMiddleware(prometheusRegistry *prometheus.Registry) func(next http.Handler) http.Handler {
	buckets := prometheus.ExponentialBuckets(0.1, 1.5, 5)
	requestsTotal := promauto.With(prometheusRegistry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Tracks the number of HTTP requests.",
		}, []string{"method", "code", "path"},
	)
	requestDuration := promauto.With(prometheusRegistry).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Tracks the latencies for HTTP requests.",
			Buckets: buckets,
		},
		[]string{"method", "code", "path"},
	)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Debug().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Msg("Start request")

			wrappedWriter := statusTrackingResponseWriter{w, http.StatusOK}

			startTime := time.Now()
			next.ServeHTTP(&wrappedWriter, r)
			duration := time.Since(startTime)

			method := r.Method
			status := strconv.Itoa(wrappedWriter.statusCode)
			path := r.URL.Path
			log.Debug().
				Str("method", method).
				Str("path", path).
				Str("status", status).
				Msg("Request finish")

			if strings.HasPrefix(path, "/v2/") {
				requestsTotal.WithLabelValues(method, status, path).Inc()
				requestDuration.WithLabelValues(method, status, path).Observe(duration.Seconds())
			}
		})
	}
}
