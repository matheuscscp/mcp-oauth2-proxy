package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})
}

func getProviderAndConfig() (provider, *config) {
	conf, err := newConfig()
	if err != nil {
		logrus.WithError(err).Fatal("failed to create config")
	}

	redactedConfig := *conf
	redactedConfig.Provider.ClientSecret = "redacted"
	logrus.WithField("config", redactedConfig).Info("config loaded")

	p, err := newProvider(conf)
	if err != nil {
		logrus.WithError(err).Fatal("failed to create provider")
	}

	return p, conf
}

func main() {
	signalReceived := make(chan os.Signal, 2)
	signal.Notify(signalReceived, os.Interrupt, syscall.SIGTERM)

	iss := newTokenIssuer()
	p, conf := getProviderAndConfig()
	api := newAPI(iss, p, conf, newMemorySessionStore(), time.Now)

	s := newServer(conf, api, prometheus.DefaultRegisterer, prometheus.DefaultGatherer)

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
