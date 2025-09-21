package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
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

func (g *googleProvider) verifyUser(ctx context.Context, ts oauth2.TokenSource) (*userInfo, error) {
	// Call userinfo endpoint.
	client := oauth2.NewClient(ctx, ts)
	resp, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		return nil, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo: %s", resp.Status)
	}

	// Parse response.
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims from Google userinfo response: %w", err)
	}
	email := claims.Email

	// Verify user.
	if !claims.EmailVerified {
		return nil, fmt.Errorf("the Google email '%s' is not verified", email)
	}
	if !g.validateEmailDomain(email) {
		return nil, fmt.Errorf("the domain of the email '%s' is not allowed", email)
	}

	// Verify user in the Google Workspace.
	groups, err := g.verifyGoogleWorkspaceUser(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to verify Google Workspace user info: %w", err)
	}

	return &userInfo{
		username: email,
		groups:   groups,
	}, nil
}

var googleWorkspaceScopes = strings.Join([]string{
	admin.AdminDirectoryUserReadonlyScope,
	admin.AdminDirectoryGroupReadonlyScope,
}, " ")

func (g *googleProvider) verifyGoogleWorkspaceUser(ctx context.Context, userEmail string) ([]string, error) {

	serviceAccountEmail, err := g.getServiceAccountEmailFromEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Google Service Account email from environment: %w", err)
	}
	if serviceAccountEmail == "" {
		// No Service Account email configured, skip Google Workspace verification.
		return nil, nil
	}

	// Create Google Admin API client with an OAuth2 token source using domain-wide delegation.
	svc, err := g.newUserClient(ctx, userEmail, serviceAccountEmail)
	if err != nil {
		return nil, fmt.Errorf("failed to create Google Admin API client for user %s: %w", userEmail, err)
	}

	// Verify user in the Google Workspace exists and is not suspended, archived or deleted.
	user, err := svc.Users.Get(userEmail).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get Google user '%s' in the Google Workspace: %w", userEmail, err)
	}
	if user.Archived || user.Suspended || user.DeletionTime != "" {
		return nil, fmt.Errorf("the Google user '%s' is archived, suspended or deleted in the Google Workspace", userEmail)
	}

	// List groups the user is a member of in the Google Workspace.
	resp, err := svc.
		Groups.
		List().
		Context(ctx).
		Domain(getEmailDomain(userEmail)).
		UserKey(userEmail).
		MaxResults(int64(maxGroups)).
		Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list groups for Google user '%s': %w", userEmail, err)
	}
	var groups []string
	for _, g := range resp.Groups {
		groups = append(groups, g.Email)
	}

	return groups, nil
}

var googleServiceAccountEmailRegex = regexp.MustCompile(
	`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

var googleServiceAccountImpersonationURLRegex = regexp.MustCompile(
	`^https://iamcredentials\.googleapis\.com/v1/projects/-/serviceAccounts/(.{1,100}):generateAccessToken$`)

func (*googleProvider) getServiceAccountEmailFromEnv(ctx context.Context) (string, error) {
	// Handle Google environments.
	mdClient := metadata.NewClient(&http.Client{})
	if mdClient.OnGCEWithContext(ctx) {
		email, err := mdClient.EmailWithContext(ctx, "default")
		if err != nil {
			return "", fmt.Errorf("failed to get default Service Account email from metadata server: %w", err)
		}
		if googleServiceAccountEmailRegex.MatchString(email) {
			return email, nil
		}
		return "", nil
	}

	// Handle Google Application Default Credentials.
	creds, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "could not find default credentials") {
			return "", nil
		}
		return "", fmt.Errorf("failed to find default credentials: %w", err)
	}
	var jsonConfig struct {
		ClientEmail                    string `json:"client_email"`
		ServiceAccountImpersonationURL string `json:"service_account_impersonation_url"`
	}
	if err := json.Unmarshal(creds.JSON, &jsonConfig); err != nil {
		return "", fmt.Errorf("failed to unmarshal Google Application Default Credentials JSON: %w", err)
	}
	switch {
	case jsonConfig.ClientEmail != "":
		return jsonConfig.ClientEmail, nil
	case jsonConfig.ServiceAccountImpersonationURL != "":
		matches := googleServiceAccountImpersonationURLRegex.FindStringSubmatch(jsonConfig.ServiceAccountImpersonationURL)
		if len(matches) != 2 {
			return "", fmt.Errorf("invalid Service Account impersonation URL in Application Default Credentials, must match %s",
				googleServiceAccountImpersonationURLRegex.String())
		}
		return matches[1], nil
	default:
		return "", nil
	}
}

func (*googleProvider) newUserClient(ctx context.Context, userEmail, serviceAccountEmail string) (*admin.Service, error) {

	var hc *http.Client
	if v := ctx.Value(oauth2.HTTPClient); v != nil {
		hc = v.(*http.Client)
	}

	// Construct JWT for domain-wide delegation impersonation.
	now := time.Now()
	jwtID := uuid.NewString()
	claims := map[string]any{
		"iss":   serviceAccountEmail,
		"aud":   google.JWTTokenURL,
		"sub":   userEmail,
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   now.Add(time.Minute).Unix(),
		"jti":   jwtID,
		"scope": googleWorkspaceScopes,
	}
	jwtClaimsBytes, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWT claims: %w", err)
	}

	// Sign JWT using Google IAM SignJWT API.
	var iamOpts []option.ClientOption
	if hc != nil {
		iamOpts = append(iamOpts, option.WithHTTPClient(hc))
	}
	iam, err := iamcredentials.NewService(ctx, iamOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Google IAM Credentials service: %w", err)
	}
	saName := fmt.Sprintf("projects/-/serviceAccounts/%s", serviceAccountEmail)
	jwtResp, err := iam.Projects.ServiceAccounts.SignJwt(saName, &iamcredentials.SignJwtRequest{
		Payload: string(jwtClaimsBytes),
	}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT using Google IAM Credentials API: %w", err)
	}
	signedJWT := jwtResp.SignedJwt

	// Exchange signed JWT for OAuth2 token.
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", signedJWT)
	req, err := http.NewRequestWithContext(ctx,
		http.MethodPost, google.JWTTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth2 token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	do := http.DefaultClient.Do
	if hc != nil {
		do = hc.Do
	}
	accessTokenResp, err := do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange signed JWT for OAuth2 token: %w", err)
	}
	defer accessTokenResp.Body.Close()
	if accessTokenResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to exchange signed JWT for OAuth2 token: %s", accessTokenResp.Status)
	}
	var token oauth2.Token
	if err := json.NewDecoder(accessTokenResp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode OAuth2 token response: %w", err)
	}
	if !token.Valid() {
		return nil, fmt.Errorf("received invalid OAuth2 token")
	}

	// Create Google Admin API client with the OAuth2 token source.
	ts := oauth2.StaticTokenSource(&token)
	tc := oauth2.NewClient(ctx, ts)
	if hc != nil {
		tc = hc
	}
	svc, err := admin.NewService(ctx, option.WithHTTPClient(tc))
	if err != nil {
		return nil, fmt.Errorf("failed to create Google Admin API client: %w", err)
	}

	return svc, nil
}
