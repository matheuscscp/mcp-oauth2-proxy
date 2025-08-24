package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})
}

func getProviderAndConfig() (provider, *config) {
	conf, err := readConfig()
	if err != nil {
		logrus.WithError(err).Fatal("failed to read config")
	}
	p, err := newProvider(conf)
	if err != nil {
		logrus.WithError(err).Fatal("failed to create provider")
	}
	return p, conf
}

func main() {
	signalReceived := make(chan os.Signal, 2)
	signal.Notify(signalReceived, os.Interrupt, syscall.SIGTERM)

	p, conf := getProviderAndConfig()
	api := newAPI(p, conf, newSessionStore())

	addr := conf.Server.Addr
	if addr == "" {
		addr = ":8080"
	}
	if conf.Server.CORS {
		api = handleCORS(api)
	}
	promHandler := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
	requestDurationSecs := promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name: "http_request_duration_seconds",
		Help: "Duration of HTTP requests in seconds",
	}, []string{"host", "method", "path", "status"})
	s := &http.Server{
		Addr: addr,
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

	go func() {
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.WithError(err).Fatal("failed to start server")
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			logrus.WithError(err).Error("failed to shut down server")
		} else {
			logrus.Info("server shut down successfully")
		}
	}()

	logrus.Info("server started, waiting for signal")
	<-signalReceived
	logrus.Info("signal received, shutting down server")
}
