package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

const (
	// Ping endpoint. Will respond WWW-Authenticate header if a valid bearer token is not provided.
	pathAuthenticate = "/authenticate"

	// Returned in the /authenticate response.
	responseHeaderAccessToken = "X-Auth-Request-Access-Token"

	// OAuth 2.0 Dynamic Client Registration Protocol-compliant endpoints.
	pathOAuthProtectedResource   = "/.well-known/oauth-protected-resource"
	pathOAuthAuthorizationServer = "/.well-known/oauth-authorization-server"
	pathRegister                 = "/register"
	pathAuthorize                = "/authorize"
	pathCallback                 = "/callback"
	pathToken                    = "/token"
)

func newAPI(ti *tokenIssuer, p provider, conf *config, sessionStore sessionStore, nowFunc func() time.Time) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(pathAuthenticate, func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)

		iss := baseURL(r)
		aud := mcpOAuth2Proxy
		if !ti.verify(token, nowFunc(), iss, aud) {
			respondWWWAuthenticate(w, r)
			return
		}

		w.Header().Set(responseHeaderAccessToken, token)

		fromRequest(r).Debug("request authenticated")
	})

	mux.HandleFunc(pathOAuthProtectedResource, func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, map[string]any{
			"authorization_servers": []map[string]any{{
				"issuer":                 baseURL(r),
				"authorization_endpoint": fmt.Sprintf("%s%s", baseURL(r), pathAuthorize),
			}},
		})
	})

	mux.HandleFunc(pathOAuthAuthorizationServer, func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, map[string]any{
			"issuer":                                baseURL(r),
			"authorization_endpoint":                fmt.Sprintf("%s%s", baseURL(r), pathAuthorize),
			"token_endpoint":                        fmt.Sprintf("%s%s", baseURL(r), pathToken),
			"registration_endpoint":                 fmt.Sprintf("%s%s", baseURL(r), pathRegister),
			"code_challenge_methods_supported":      []string{authorizationServerCodeChallengeMethod},
			"grant_types_supported":                 []string{authorizationServerGrantType},
			"response_modes_supported":              []string{authorizationServerResponseMode},
			"response_types_supported":              []string{authorizationServerResponseType},
			"scopes_supported":                      []string{authorizationServerScope},
			"token_endpoint_auth_methods_supported": []string{authorizationServerTokenEndpointAuthMethod},
		})
	})

	mux.HandleFunc(pathRegister, func(w http.ResponseWriter, r *http.Request) {
		l := fromRequest(r)

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
			if !conf.Proxy.validateRedirectURL(uri) {
				http.Error(w, fmt.Sprintf("Invalid redirect URI '%s'", uri), http.StatusBadRequest)
				return
			}
		}

		resp := map[string]any{
			"client_id":                  mcpOAuth2Proxy,
			"token_endpoint_auth_method": authorizationServerTokenEndpointAuthMethod,
		}
		if len(req.RedirectURIs) > 0 {
			resp["redirect_uris"] = req.RedirectURIs
		}
		respondJSON(w, http.StatusCreated, resp)

		l.WithField("registration", req).Info("client registered")
	})

	mux.HandleFunc(pathAuthorize, func(w http.ResponseWriter, r *http.Request) {
		l := fromRequest(r)

		if r.URL.Query().Get(queryParamCodeChallengeMethod) != authorizationServerCodeChallengeMethod {
			http.Error(w, fmt.Sprintf("Unsupported %s", queryParamCodeChallengeMethod), http.StatusBadRequest)
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

		tx, err := newTransaction(&conf.Proxy, r, codeVerifier)
		if err != nil {
			l.WithError(err).Error("invalid transaction")
			http.Error(w, fmt.Sprintf("Invalid parameters: %v", err), http.StatusBadRequest)
			return
		}

		state, err := sessionStore.storeTransaction(tx)
		if err != nil {
			l.WithError(err).Error("failed to generate state")
			http.Error(w, "Failed to generate state", http.StatusInternalServerError)
			return
		}

		// Build authorization code URL.
		oauth2Conf := oauth2Config(r, p, conf)
		authCodeURL := oauth2Conf.AuthCodeURL(state,
			oauth2.SetAuthURLParam(queryParamCodeChallenge, codeChallenge),
			oauth2.SetAuthURLParam(queryParamCodeChallengeMethod, authorizationServerCodeChallengeMethod))

		setState(w, state)
		http.Redirect(w, r, authCodeURL, http.StatusSeeOther)
	})

	mux.HandleFunc(pathCallback, func(w http.ResponseWriter, r *http.Request) {
		l := fromRequest(r)

		state, err := getAndDeleteStateAndCheckCSRF(w, r)
		if err != nil {
			l.WithError(err).Error("CSRF failed")
			http.Error(w, "CSRF failed", http.StatusBadRequest)
			return
		}

		tx, ok := sessionStore.retrieveTransaction(state)
		if !ok {
			http.Error(w, "Session expired", http.StatusBadRequest)
			return
		}

		// Exchange authorization code for tokens.
		oauth2Conf := oauth2Config(r, p, conf)
		oauth2Conf.ClientSecret = conf.Provider.ClientSecret
		oauth2Token, err := oauth2Conf.Exchange(r.Context(), authorizationCode(r),
			oauth2.SetAuthURLParam(queryParamCodeVerifier, tx.codeVerifier))
		if err != nil {
			l.WithError(err).Error("failed to exchange authorization code for tokens")
			http.Error(w, "Failed to exchange authorization code for tokens", http.StatusBadRequest)
			return
		}

		user, err := p.verifyUser(r.Context(), oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			l.WithError(err).Error("failed to verify user")
			http.Error(w, "Failed to verify user", http.StatusBadRequest)
			return
		}

		// Issue an access token in the proxy realm.
		iss := baseURL(r)
		sub := user
		aud := mcpOAuth2Proxy
		now := nowFunc()
		accessToken, exp, err := ti.issue(iss, sub, aud, now)
		if err != nil {
			l.WithError(err).Error(fmt.Sprintf("failed to issue %s access token", mcpOAuth2Proxy))
			http.Error(w, fmt.Sprintf("Failed to issue %s access token", mcpOAuth2Proxy), http.StatusInternalServerError)
			return
		}

		// Store transaction outcome in the session.
		s := &session{
			tx: tx,
			outcome: &oauth2.Token{
				AccessToken: accessToken,
				TokenType:   "Bearer",
				Expiry:      exp,
				ExpiresIn:   int64(exp.Sub(now).Milliseconds() / 1000),
			},
		}
		authzCode, err := sessionStore.store(s)
		if err != nil {
			l.WithError(err).Error("failed to store tokens with authorization code")
			http.Error(w, "Failed to store tokens with authorization code", http.StatusInternalServerError)
			return
		}

		// Build redirect URL.
		redirectURI := tx.clientParams.redirectURL
		redirectParams := url.Values{}
		redirectParams.Set(queryParamAuthorizationCode, authzCode)
		redirectParams.Set(queryParamState, tx.clientParams.state)
		redirectURL := fmt.Sprintf("%s?%s", redirectURI, redirectParams.Encode())

		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
	})

	mux.HandleFunc(pathToken, func(w http.ResponseWriter, r *http.Request) {
		l := fromRequest(r)

		if err := r.ParseForm(); err != nil {
			l.WithError(err).Error("failed to parse form")
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		authzCode := r.FormValue(queryParamAuthorizationCode)

		s, ok := sessionStore.retrieve(authzCode)
		if !ok {
			http.Error(w, "Authorization code expired", http.StatusBadRequest)
			return
		}

		// Validate client PKCE.
		if s.tx.clientParams.codeChallenge != pkceS256Challenge(r.FormValue(queryParamCodeVerifier)) {
			http.Error(w, "PKCE failed", http.StatusBadRequest)
			return
		}

		respondJSON(w, http.StatusOK, s.outcome)
	})

	return mux
}
