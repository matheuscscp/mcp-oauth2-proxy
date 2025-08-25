package main

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

type provider interface {
	oauth2Config(r *http.Request) *oauth2.Config
	verifyBearerToken(ctx context.Context, bearerToken string) error
	verifyAndRepackExchangedTokens(ctx context.Context, token *oauth2.Token) (any, error)
}

func newProvider(conf *config) (provider, error) {
	switch conf.Provider.Name {
	case "", "google":
		return &googleProvider{&conf.Provider}, nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", conf.Provider.Name)
	}
}
