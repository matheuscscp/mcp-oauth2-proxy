package main

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

const (
	providerGoogle = "google"
	providerGitHub = "github"
)

type provider interface {
	oauth2Config() *oauth2.Config
	verifyUser(ctx context.Context, ts oauth2.TokenSource) (string, error)
}

func newProvider(conf *config) (provider, error) {
	switch conf.Provider.Name {
	case providerGoogle:
		return &googleProvider{conf.Provider.validateEmailDomain}, nil
	case providerGitHub:
		return githubProvider{}, nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", conf.Provider.Name)
	}
}
