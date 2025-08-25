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
	*providerConfig
}

// oauth2Config implements provider.
func (g *googleProvider) oauth2Config(r *http.Request) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.ClientID,
		ClientSecret: g.ClientSecret,
		RedirectURL:  callbackURL(r),
		Endpoint:     google.Endpoint,
		Scopes:       []string{"email"},
	}
}

// verifyBearerToken implements provider.
func (g *googleProvider) verifyBearerToken(ctx context.Context, bearerToken string) error {
	src := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: bearerToken})
	client := oauth2.NewClient(ctx, src)

	resp, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		return fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("userinfo: %s", resp.Status)
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return fmt.Errorf("error unmarshaling claims from google id token: %w", err)
	}
	email := claims.Email

	if !claims.EmailVerified {
		return fmt.Errorf("google email '%s' is not verified", email)
	}

	if !g.validateEmailDomain(email) {
		return fmt.Errorf("the domain of the email '%s' is not allowed", email)
	}

	return nil
}

// verifyAndRepackExchangedTokens implements provider.
func (g *googleProvider) verifyAndRepackExchangedTokens(ctx context.Context, token *oauth2.Token) (any, error) {
	if err := g.verifyBearerToken(ctx, token.AccessToken); err != nil {
		return nil, err
	}

	// Recast token to map[string]any.
	b, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("error marshaling google oauth2 token to json: %w", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, fmt.Errorf("error unmarshaling google oauth2 token from json: %w", err)
	}
	if len(resp) == 0 {
		resp = make(map[string]any)
	}

	return resp, nil
}
