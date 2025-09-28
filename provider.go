package main

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
)

const (
	providerGoogle = "google"
	providerGitHub = "github"
)

type provider interface {
	oauth2Config() *oauth2.Config
	verifyUser(ctx context.Context, ts oauth2.TokenSource) (*userInfo, error)
}

func newProvider(conf *config.ProviderConfig) (provider, error) {
	switch conf.Name {
	case providerGoogle:
		return &googleProvider{validateEmailDomain: conf.ValidateEmailDomain}, nil
	case providerGitHub:
		return newGitHubProvider(conf)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", conf.Name)
	}
}
