package server

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/issuer"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/provider"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/store"
)

func New(conf *config.Config, p provider.Interface) *http.Server {
	iss := issuer.New()
	st := store.NewMemoryStore()
	api := newAPI(iss, p, conf, st, time.Now)
	return newServer(conf, api, prometheus.DefaultRegisterer, prometheus.DefaultGatherer)
}
