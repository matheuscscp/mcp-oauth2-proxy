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
	verifyUser(ctx context.Context, ts oauth2.TokenSource) (*userInfo, error)
}

func newProvider(conf *providerConfig) (provider, error) {
	switch conf.Name {
	case providerGoogle:
		return &googleProvider{validateEmailDomain: conf.validateEmailDomain}, nil
	case providerGitHub:
		return githubProvider{}, nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", conf.Name)
	}
}
