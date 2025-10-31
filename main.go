package main

import (
	"context"
	"crypto/fips140"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/logging"
	provider "github.com/matheuscscp/mcp-oauth2-proxy/internal/provider/factory"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/server"
)

func main() {
	// Load logging level.
	if err := logging.LoadLevel(); err != nil {
		logrus.WithError(err).Fatal("failed to initialize logger")
	}

	// Listen for termination signals.
	signalReceived := make(chan os.Signal, 2)
	signal.Notify(signalReceived, os.Interrupt, syscall.SIGTERM)

	// Check FIPS 140-3 mode.
	if !fips140.Enabled() {
		logrus.Fatal("FIPS not enabled")
	}

	// Load configuration.
	conf, err := config.Load()
	if err != nil {
		logrus.WithError(err).Fatal("failed to create config")
	}
	redactedConfig := *conf
	redactedConfig.Provider.ClientSecret = "redacted"
	logrus.WithField("config", redactedConfig).Info("config loaded")

	// Create provider.
	p, err := provider.New(&conf.Provider)
	if err != nil {
		logrus.WithError(err).Fatal("failed to create provider")
	}

	// Create server.
	s := server.New(conf, p)

	// Start server.
	go func() {
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.WithError(err).Fatal("failed to start server")
		}
	}()

	// Wait for termination signal.
	logrus.Info("server started, waiting for signal")
	<-signalReceived
	logrus.Info("signal received, shutting down server")

	// Shutdown server.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		logrus.WithError(err).Error("failed to shut down server")
	} else {
		logrus.Info("server shut down successfully")
	}
}
