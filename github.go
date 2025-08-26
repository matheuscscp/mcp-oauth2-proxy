package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type githubProvider struct{}

func (githubProvider) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		Endpoint: github.Endpoint,
	}
}

func (githubProvider) verifyUser(ctx context.Context, ts oauth2.TokenSource) (string, error) {
	// Call user endpoint.
	client := oauth2.NewClient(ctx, ts)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return "", fmt.Errorf("user request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("user: %s", resp.Status)
	}

	// Parse response.
	var claims struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return "", fmt.Errorf("error unmarshaling claims from github user response: %w", err)
	}

	return claims.Login, nil
}
