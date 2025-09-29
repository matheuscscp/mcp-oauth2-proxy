package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/constants"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/issuer"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/logging"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/provider"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/store"
)

const (
	// Ping endpoint. Will respond WWW-Authenticate header if a valid bearer token is not provided.
	pathAuthenticate = "/authenticate"

	// OAuth 2.0 Dynamic Client Registration Protocol-compliant endpoints.
	pathOAuthProtectedResource   = "/.well-known/oauth-protected-resource"
	pathOAuthAuthorizationServer = "/.well-known/oauth-authorization-server"
	pathRegister                 = "/register"
	pathAuthorize                = "/authorize"
	pathCallback                 = "/callback"
	pathToken                    = "/token"

	// OIDC endpoints.
	pathOpenIDConfiguration = "/.well-known/openid-configuration"
	pathJWKS                = "/openid/v1/jwks"
)

func newAPI(ti issuer.Issuer, p provider.Interface, conf *config.Config,
	st store.Store, nowFunc func() time.Time) http.Handler {

	mux := http.NewServeMux()

	mux.HandleFunc(pathAuthenticate, func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)

		iss := baseURL(r)
		aud := baseURL(r)
		if !ti.Verify(token, nowFunc(), iss, aud) {
			respondWWWAuthenticate(w, r)
			return
		}

		logging.FromRequest(r).Debug("request authenticated")
	})

	mux.HandleFunc(pathOAuthProtectedResource, func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, r, http.StatusOK, map[string]any{
			"authorization_servers": []map[string]any{{
				"issuer":                 baseURL(r),
				"authorization_endpoint": fmt.Sprintf("%s%s", baseURL(r), pathAuthorize),
			}},
		})
	})

	mux.HandleFunc(pathOAuthAuthorizationServer, func(w http.ResponseWriter, r *http.Request) {
		supportedScopes, _, err := conf.Proxy.SupportedScopes(r.Context(), r.Host)
		if err != nil {
			logging.FromRequest(r).WithError(err).Error("failed to get supported scopes")
			http.Error(w, "Failed to get supported scopes", http.StatusInternalServerError)
			return
		}
		respondJSON(w, r, http.StatusOK, map[string]any{
			"issuer":                                baseURL(r),
			"authorization_endpoint":                fmt.Sprintf("%s%s", baseURL(r), pathAuthorize),
			"token_endpoint":                        fmt.Sprintf("%s%s", baseURL(r), pathToken),
			"registration_endpoint":                 fmt.Sprintf("%s%s", baseURL(r), pathRegister),
			"code_challenge_methods_supported":      []string{constants.AuthorizationServerCodeChallengeMethod},
			"grant_types_supported":                 []string{constants.AuthorizationServerGrantType},
			"response_modes_supported":              []string{constants.AuthorizationServerResponseMode},
			"response_types_supported":              []string{constants.AuthorizationServerResponseType},
			"scopes_supported":                      supportedScopes,
			"token_endpoint_auth_methods_supported": []string{constants.AuthorizationServerTokenEndpointAuthMethod},
		})
	})

	mux.HandleFunc(pathRegister, func(w http.ResponseWriter, r *http.Request) {
		l := logging.FromRequest(r)

		var req struct {
			RedirectURIs            []string `json:"redirect_uris,omitempty"`
			TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
			GrantTypes              []string `json:"grant_types,omitempty"`
			ResponseTypes           []string `json:"response_types,omitempty"`
			ClientName              string   `json:"client_name,omitempty"`
			ClientURI               string   `json:"client_uri,omitempty"`
			LogoURI                 string   `json:"logo_uri,omitempty"`
			Scope                   string   `json:"scope,omitempty"`
			ToSURI                  string   `json:"tos_uri,omitempty"`
			PolicyURI               string   `json:"policy_uri,omitempty"`
			JWKSURI                 string   `json:"jwks_uri,omitempty"`
			SoftwareID              string   `json:"software_id,omitempty"`
			SoftwareVersion         string   `json:"software_version,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			l.WithError(err).Error("failed to parse request body as JSON")
			http.Error(w, "Failed to parse request body as JSON", http.StatusBadRequest)
			return
		}

		for _, uri := range req.RedirectURIs {
			if !conf.Proxy.ValidateRedirectURL(uri) {
				http.Error(w, fmt.Sprintf("Invalid redirect URI '%s'", uri), http.StatusBadRequest)
				return
			}
		}

		resp := map[string]any{
			"client_id":                  constants.MCPOAuth2Proxy,
			"token_endpoint_auth_method": constants.AuthorizationServerTokenEndpointAuthMethod,
		}
		if len(req.RedirectURIs) > 0 {
			resp["redirect_uris"] = req.RedirectURIs
		}
		respondJSON(w, r, http.StatusCreated, resp)

		l.WithField("client", req).Info("client registered")
	})

	mux.HandleFunc(pathAuthorize, func(w http.ResponseWriter, r *http.Request) {
		l := logging.FromRequest(r)

		// Fetch supported scopes for the host.
		supportedScopeNames, supportedScopes, err := conf.Proxy.SupportedScopes(r.Context(), r.Host)
		if err != nil {
			l.WithError(err).Error("failed to get supported scopes")
			http.Error(w, "Failed to get supported scopes", http.StatusInternalServerError)
			return
		}

		// Render scope selection page if necessary.
		if !conf.Proxy.DisableConsentScreen && !r.URL.Query().Has("skip_scope_selection") && len(supportedScopes) > 0 {
			respondScopeSelectionPage(w, r, supportedScopes)
			return
		}

		// Prepare PKCE with configured IdP.
		codeVerifier, err := pkceVerifier()
		if err != nil {
			l.WithError(err).Error("failed to generate code verifier")
			http.Error(w, "Failed to generate code verifier", http.StatusInternalServerError)
			return
		}
		codeChallenge := pkceS256Challenge(codeVerifier)

		tx, err := store.NewTransaction(&conf.Proxy, r, codeVerifier, supportedScopeNames)
		if err != nil {
			l.WithError(err).Error("invalid transaction")
			http.Error(w, fmt.Sprintf("Invalid parameters: %v", err), http.StatusBadRequest)
			return
		}

		state, err := st.StoreTransaction(tx)
		if err != nil {
			l.WithError(err).Error("failed to generate state")
			http.Error(w, "Failed to generate state", http.StatusInternalServerError)
			return
		}

		// Build authorization code URL.
		oauth2Conf := oauth2Config(r, p, conf)
		authCodeURL := oauth2Conf.AuthCodeURL(state,
			oauth2.SetAuthURLParam(constants.QueryParamCodeChallenge, codeChallenge),
			oauth2.SetAuthURLParam(constants.QueryParamCodeChallengeMethod, constants.AuthorizationServerCodeChallengeMethod))

		setState(w, state)
		http.Redirect(w, r, authCodeURL, http.StatusSeeOther)
	})

	mux.HandleFunc(pathCallback, func(w http.ResponseWriter, r *http.Request) {
		l := logging.FromRequest(r)

		state, err := getAndDeleteStateAndCheckCSRF(w, r)
		if err != nil {
			l.WithError(err).Error("CSRF failed")
			http.Error(w, "CSRF failed", http.StatusBadRequest)
			return
		}

		tx, ok := st.RetrieveTransaction(state)
		if !ok {
			http.Error(w, "Session expired", http.StatusBadRequest)
			return
		}

		if tx.Host != r.Host {
			http.Error(w, "Host mismatch", http.StatusBadRequest)
			return
		}

		// Exchange authorization code for tokens.
		oauth2Conf := oauth2Config(r, p, conf)
		oauth2Conf.ClientSecret = conf.Provider.ClientSecret
		oauth2Token, err := oauth2Conf.Exchange(r.Context(), authorizationCode(r),
			oauth2.SetAuthURLParam(constants.QueryParamCodeVerifier, tx.CodeVerifier))
		if err != nil {
			l.WithError(err).Error("failed to exchange authorization code for tokens")
			http.Error(w, "Failed to exchange authorization code for tokens", http.StatusBadRequest)
			return
		}

		user, err := p.VerifyUser(r.Context(), oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			l.WithError(err).Error("failed to verify user")
			http.Error(w, "Failed to verify user", http.StatusBadRequest)
			return
		}

		// Issue an access token in the proxy realm.
		iss := baseURL(r)
		sub := user.Username
		aud := baseURL(r)
		now := nowFunc()
		groups := user.Groups
		scopes := tx.ClientParams.Scopes
		accessToken, exp, err := ti.Issue(iss, sub, aud, now, groups, scopes)
		if err != nil {
			l.WithError(err).Error("failed to issue access token")
			http.Error(w, "Failed to issue access token", http.StatusInternalServerError)
			return
		}

		// Store transaction outcome in the session.
		s := &store.Session{
			TX: tx,
			Outcome: &oauth2.Token{
				AccessToken: accessToken,
				TokenType:   "Bearer",
				Expiry:      exp,
				ExpiresIn:   int64(exp.Sub(now).Milliseconds() / 1000),
			},
		}
		authzCode, err := st.StoreSession(s)
		if err != nil {
			l.WithError(err).Error("failed to store tokens with authorization code")
			http.Error(w, "Failed to store tokens with authorization code", http.StatusInternalServerError)
			return
		}

		// Build redirect URL.
		redirectURI := tx.ClientParams.RedirectURL
		redirectParams := url.Values{}
		redirectParams.Set(constants.QueryParamAuthorizationCode, authzCode)
		redirectParams.Set(constants.QueryParamState, tx.ClientParams.State)
		redirectURL := fmt.Sprintf("%s?%s", redirectURI, redirectParams.Encode())

		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
	})

	mux.HandleFunc(pathToken, func(w http.ResponseWriter, r *http.Request) {
		l := logging.FromRequest(r)

		if err := r.ParseForm(); err != nil {
			l.WithError(err).Error("failed to parse form")
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		authzCode := r.FormValue(constants.QueryParamAuthorizationCode)

		s, ok := st.RetrieveSession(authzCode)
		if !ok {
			http.Error(w, "Authorization code expired", http.StatusBadRequest)
			return
		}

		if s.TX.Host != r.Host {
			http.Error(w, "Host mismatch", http.StatusBadRequest)
			return
		}

		// Validate client PKCE.
		if s.TX.ClientParams.CodeChallenge != pkceS256Challenge(r.FormValue(constants.QueryParamCodeVerifier)) {
			http.Error(w, "PKCE failed", http.StatusBadRequest)
			return
		}

		respondJSON(w, r, http.StatusOK, s.Outcome)
	})

	mux.HandleFunc(pathOpenIDConfiguration, func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, r, http.StatusOK, map[string]any{
			"issuer":                                baseURL(r),
			"jwks_uri":                              jwksURL(r),
			"id_token_signing_alg_values_supported": []string{issuer.Algorithm().String()},
		})
	})

	mux.HandleFunc(pathJWKS, func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, r, http.StatusOK, map[string]any{
			"keys": ti.PublicKeys(time.Now()),
		})
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !conf.Proxy.AcceptsHost(r.Host) {
			http.Error(w, "Host not allowed", http.StatusMisdirectedRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
