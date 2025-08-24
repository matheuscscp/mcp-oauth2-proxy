package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
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
)

func newAPI(p provider, conf *config, sessionStore sessionStore) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(pathAuthenticate, func(w http.ResponseWriter, r *http.Request) {
		l := fromRequest(r)

		token := bearerToken(r)
		if token == "" {
			respondWWWAuthenticate(w, r)
			return
		}

		if err := p.verifyBearerToken(r.Context(), token); err != nil {
			l.WithError(err).Debug("failed to verify bearer token")
			respondWWWAuthenticate(w, r)
			return
		}

		l.Debug("request authenticated")
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
			"scopes_supported":                      p.supportedScopes(),
			"code_challenge_methods_supported":      []string{authorizationServerCodeChallengeMethod},
			"grant_types_supported":                 []string{authorizationServerGrantType},
			"response_modes_supported":              []string{authorizationServerResponseMode},
			"response_types_supported":              []string{authorizationServerResponseType},
			"token_endpoint_auth_methods_supported": []string{authorizationServerTokenEndpointAuthMethod},
		})
	})

	mux.HandleFunc(pathRegister, func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			fromRequest(r).WithError(err).Error("failed to parse request body as JSON")
			http.Error(w, "Failed to parse request body as JSON", http.StatusBadRequest)
			return
		}
		redirectURIs, ok := m["redirect_uris"]
		if !ok {
			http.Error(w, "Missing redirect_uris", http.StatusBadRequest)
			return
		}
		respondJSON(w, http.StatusCreated, map[string]any{
			"client_id":                  conf.Provider.ClientID,
			"token_endpoint_auth_method": authorizationServerTokenEndpointAuthMethod,
			"redirect_uris":              redirectURIs,
		})
	})

	mux.HandleFunc(pathAuthorize, func(w http.ResponseWriter, r *http.Request) {
		l := fromRequest(r)

		if r.URL.Query().Get(queryParamCodeChallengeMethod) != authorizationServerCodeChallengeMethod {
			http.Error(w, "Unsupported code_challenge_method", http.StatusBadRequest)
			return
		}

		codeVerifier, err := pkceVerifier()
		if err != nil {
			l.WithError(err).Error("failed to generate code verifier")
			http.Error(w, "Failed to generate code verifier", http.StatusInternalServerError)
			return
		}
		codeChallenge := pkceS256Challenge(codeVerifier)

		tx := r.URL.Query()
		tx.Set(queryParamCodeVerifier, codeVerifier)
		state, err := sessionStore.store(tx, nil)
		if err != nil {
			l.WithError(err).Error("failed to generate state")
			http.Error(w, "Failed to generate state", http.StatusInternalServerError)
			return
		}
		setState(w, state)

		url := p.oauth2Config(r).AuthCodeURL(state,
			oauth2.SetAuthURLParam(queryParamCodeChallenge, codeChallenge),
			oauth2.SetAuthURLParam(queryParamCodeChallengeMethod, authorizationServerCodeChallengeMethod))
		http.Redirect(w, r, url, http.StatusSeeOther)
	})

	mux.HandleFunc(pathCallback, func(w http.ResponseWriter, r *http.Request) {
		l := fromRequest(r)

		state, err := getAndDeleteStateAndCheckCSRF(w, r)
		if err != nil {
			l.WithError(err).Error("failed to check CSRF")
			http.Error(w, "Failed to check CSRF", http.StatusBadRequest)
			return
		}

		tx, _, ok := sessionStore.retrieve(state)
		if !ok {
			http.Error(w, "Session expired", http.StatusBadRequest)
			return
		}

		oauth2Token, err := p.oauth2Config(r).Exchange(r.Context(), authorizationCode(r),
			oauth2.SetAuthURLParam(queryParamCodeVerifier, tx.Get(queryParamCodeVerifier)))
		if err != nil {
			l.WithError(err).Error("failed to exchange authorization code for tokens")
			http.Error(w, "Failed to exchange authorization code for tokens", http.StatusBadRequest)
			return
		}

		tokens, err := p.verifyAndRepackExchangedTokens(r.Context(), oauth2Token)
		if err != nil {
			l.WithError(err).Error("failed to verify user")
			http.Error(w, "Failed to verify user", http.StatusBadRequest)
			return
		}

		authzCode, err := sessionStore.store(tx, tokens)
		if err != nil {
			l.WithError(err).Error("failed to store tokens with authorization code")
			http.Error(w, "Failed to store tokens with authorization code", http.StatusInternalServerError)
			return
		}

		redirectURI := tx.Get(queryParamRedirectURI)
		redirectParams := url.Values{}
		redirectParams.Set(queryParamAuthorizationCode, authzCode)
		redirectParams.Set(queryParamState, tx.Get(queryParamState))
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
		tx, tokens, ok := sessionStore.retrieve(authzCode)
		if !ok {
			http.Error(w, "Authorization code expired", http.StatusBadRequest)
			return
		}

		if tx.Get(queryParamCodeChallenge) != pkceS256Challenge(r.FormValue(queryParamCodeVerifier)) {
			http.Error(w, "PKCE failed", http.StatusBadRequest)
			return
		}

		respondJSON(w, http.StatusOK, tokens)
	})

	return mux
}
