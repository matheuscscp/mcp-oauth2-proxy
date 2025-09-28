package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
)

func newServer(conf *config.Config, api http.Handler,
	promRegisterer prometheus.Registerer, promGatherer prometheus.Gatherer) *http.Server {

	if conf.Proxy.CORS {
		api = handleCORS(api)
	}

	promHandler := promhttp.HandlerFor(promGatherer, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
	requestDurationSecs := prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Name: "http_request_duration_seconds",
		Help: "Duration of HTTP requests in seconds",
	}, []string{"host", "method", "path", "status"})
	promRegisterer.MustRegister(requestDurationSecs)

	return &http.Server{
		Addr: conf.Server.Addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t := time.Now()
			sr := &statusRecorder{ResponseWriter: w}
			defer func() {
				status := fmt.Sprintf("%d", sr.getStatusCode())
				requestDurationSecs.
					WithLabelValues(r.Host, r.Method, r.URL.Path, status).
					Observe(time.Since(t).Seconds())
			}()

			w = sr
			r = intoRequest(r, logrus.WithField("http", logrus.Fields{
				"host":   r.Host,
				"method": r.Method,
				"path":   r.URL.Path,
			}))

			switch r.URL.Path {
			case "/readyz", "/healthz":
				w.WriteHeader(http.StatusOK)
			case "/metrics":
				promHandler.ServeHTTP(w, r)
			default:
				api.ServeHTTP(w, r)
			}
		}),
	}
}
