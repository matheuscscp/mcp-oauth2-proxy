package provider

import (
	"context"

	"golang.org/x/oauth2"
)

type UserInfo struct {
	Username string
	Groups   []string
}

type Interface interface {
	OAuth2Config() *oauth2.Config
	VerifyUser(ctx context.Context, ts oauth2.TokenSource) (*UserInfo, error)
}
