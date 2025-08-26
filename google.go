package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type googleProvider struct {
	validateEmailDomain func(email string) bool
}

func (*googleProvider) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		Endpoint: google.Endpoint,
		Scopes:   []string{"email"},
	}
}

func (g *googleProvider) verifyUser(ctx context.Context, ts oauth2.TokenSource) (string, error) {
	// Call userinfo endpoint.
	client := oauth2.NewClient(ctx, ts)
	resp, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		return "", fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo: %s", resp.Status)
	}

	// Parse response.
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return "", fmt.Errorf("error unmarshaling claims from google userinfo response: %w", err)
	}
	email := claims.Email

	// Verify user.
	if !claims.EmailVerified {
		return "", fmt.Errorf("google email '%s' is not verified", email)
	}
	if !g.validateEmailDomain(email) {
		return "", fmt.Errorf("the domain of the email '%s' is not allowed", email)
	}

	// A user is their email.
	return email, nil
}
