package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	githubv3 "github.com/google/go-github/v74/github"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type githubProvider struct {
	appClientID  string
	organization string
}

const (
	envGitHubAppPrivateKey = "GITHUB_APP_PRIVATE_KEY"
)

func newGitHubProvider(conf *providerConfig) (*githubProvider, error) {
	hasOrg := conf.Organization != ""
	hasAppPK := os.Getenv(envGitHubAppPrivateKey) != ""
	if hasAppPK != hasOrg {
		return nil, fmt.Errorf("both GitHub Organization and GitHub App private key must be set, or both must be unset")
	}
	return &githubProvider{
		appClientID:  conf.ClientID,
		organization: conf.Organization,
	}, nil
}

func (*githubProvider) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		Endpoint: github.Endpoint,
	}
}

func (g *githubProvider) verifyUser(ctx context.Context, ts oauth2.TokenSource) (*userInfo, error) {
	// Call user endpoint.
	client := oauth2.NewClient(ctx, ts)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("user request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user: %s", resp.Status)
	}

	// Parse response.
	var claims struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims from GitHub user response: %w", err)
	}
	username := claims.Login

	// Verify user in the GitHub Organization.
	groups, err := g.verifyGitHubOrganizationUser(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to verify GitHub Organization user info: %w", err)
	}

	return &userInfo{
		username: username,
		groups:   groups,
	}, nil
}

func (g *githubProvider) verifyGitHubOrganizationUser(ctx context.Context, username string) ([]string, error) {
	if g.organization == "" {
		// No organization configured, skip GitHub Organization verification.
		return nil, nil
	}

	// Create API clients for the organization.
	apiv3, apiv4, err := g.newOrganizationClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create API clients for GitHub Organization: %w", err)
	}

	// Verify user is a member of the organization and is not suspended or inactive.
	membership, _, err := apiv3.Organizations.GetOrgMembership(ctx, username, g.organization)
	if err != nil {
		return nil, fmt.Errorf("failed to get membership for user '%s' in the GitHub Organization: %w", username, err)
	}
	if membership.GetState() != "active" || !membership.GetUser().GetSuspendedAt().Time.IsZero() {
		return nil, fmt.Errorf("the user '%s' is suspended or not active in the GitHub Organization", username)
	}

	// List teams the user is a member of in the organization to use as groups.
	var q struct {
		Organization struct {
			Teams struct {
				Edges []struct {
					Node struct {
						Name githubv4.String
					}
				}
			} `graphql:"teams(first: $maxResults, userLogins: [$user], query: $query)"`
		} `graphql:"organization(login: $org)"`
	}
	variables := map[string]any{
		"org":        githubv4.String(g.organization),
		"user":       githubv4.String(username),
		"maxResults": githubv4.Int(maxGroups),
		"query":      githubv4.String(""),
	}
	if err := apiv4.Query(ctx, &q, variables); err != nil {
		return nil, fmt.Errorf("failed to list teams for user '%s' in the GitHub Organization: %w", username, err)
	}
	var groups []string
	for _, edge := range q.Organization.Teams.Edges {
		groups = append(groups, string(edge.Node.Name))
	}

	return groups, nil
}

func (g *githubProvider) newOrganizationClients(ctx context.Context) (*githubv3.Client, *githubv4.Client, error) {

	var hc *http.Client
	if v := ctx.Value(oauth2.HTTPClient); v != nil {
		hc = v.(*http.Client)
	}

	// Read and parse GitHub App private key.
	keyPath := os.Getenv(envGitHubAppPrivateKey)
	b, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read GitHub App private key from '%s': %w", keyPath, err)
	}
	key, err := jwk.ParseKey([]byte(b), jwk.WithPEM(true))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse GitHub App private key: %w", err)
	}

	// Mint a JWT for the GitHub App using the private key.
	now := time.Now()
	iss := g.appClientID
	iat := now
	exp := iat.Add(time.Minute)
	tok, err := jwt.NewBuilder().
		Issuer(iss).
		IssuedAt(iat).
		Expiration(exp).
		Build()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build GitHub App JWT: %w", err)
	}
	b, err = jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign GitHub App JWT: %w", err)
	}
	appToken := string(b)

	// Create a token for the GitHub App installation in the organization.
	appClient := githubv3.NewClient(hc).WithAuthToken(appToken)
	orgInstallation, _, err := appClient.Apps.FindOrganizationInstallation(ctx, g.organization)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find GitHub App Organization installation: %w", err)
	}
	installationTokenInfo, _, err := appClient.Apps.CreateInstallationToken(ctx, orgInstallation.GetID(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GitHub App installation token: %w", err)
	}
	installationToken := installationTokenInfo.GetToken()

	// Create and return API v3 and v4 clients authenticated as the GitHub App installation.
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: installationToken})
	tc := oauth2.NewClient(ctx, ts)
	if hc != nil {
		tc = hc
	}
	apiv3 := githubv3.NewClient(hc).WithAuthToken(installationToken)
	apiv4 := githubv4.NewClient(tc)

	return apiv3, apiv4, nil
}
