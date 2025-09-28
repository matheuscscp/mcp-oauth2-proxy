package factory

import (
	"fmt"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/provider"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/provider/github"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/provider/google"
)

const (
	providerGoogle = "google"
	providerGitHub = "github"
)

func New(conf *config.ProviderConfig) (provider.Interface, error) {
	switch conf.Name {
	case providerGoogle:
		return google.New(conf)
	case providerGitHub:
		return github.New(conf)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", conf.Name)
	}
}
