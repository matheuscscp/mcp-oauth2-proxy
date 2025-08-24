package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

func getProviderAndConfig() (provider, *config) {
	conf, err := readConfig()
	if err != nil {
		logrus.WithError(err).Fatal("failed to read config")
	}
	p, err := newProvider(conf)
	if err != nil {
		logrus.WithError(err).Fatal("failed to create provider")
	}
	return p, conf
}

func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})

	signalReceived := make(chan os.Signal, 2)
	signal.Notify(signalReceived, os.Interrupt, syscall.SIGTERM)

	p, conf := getProviderAndConfig()

	sessionStore := newSessionStore()

	mux := http.NewServeMux()

	mux.HandleFunc(pathAuthenticate, func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			respondWWWAuthenticate(w, r)
			return
		}

		if err := p.verifyBearerToken(r.Context(), token); err != nil {
			logrus.WithError(err).Error("failed to verify bearer token")
			respondWWWAuthenticate(w, r)
			return
		}

		logrus.WithField("host", r.Host).Info("request authenticated")
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
		respondJSON(w, r, http.StatusOK, map[string]any{
			"issuer":                                baseURL(r),
			"authorization_endpoint":                fmt.Sprintf("%s%s", baseURL(r), pathAuthorize),
			"token_endpoint":                        fmt.Sprintf("%s%s", baseURL(r), pathToken),
			"registration_endpoint":                 fmt.Sprintf("%s%s", baseURL(r), pathRegister),
			"scopes_supported":                      p.supportedScopes(),
			"token_endpoint_auth_methods_supported": []string{authorizationServerAuthMethod},
			"response_types_supported":              []string{authorizationServerResponseType},
			"response_modes_supported":              []string{authorizationServerResponseMode},
			"grant_types_supported":                 []string{authorizationServerGrantType},
			"code_challenge_methods_supported":      []string{authorizationServerCodeChallengeMethod},
		})
	})

	mux.HandleFunc(pathRegister, func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "Failed to parse request body as JSON", http.StatusBadRequest)
			return
		}
		redirectURIs, ok := m["redirect_uris"]
		if !ok {
			http.Error(w, "Missing redirect_uris", http.StatusBadRequest)
			return
		}
		respondJSON(w, r, http.StatusCreated, map[string]any{
			"client_id":                  conf.Provider.ClientID,
			"token_endpoint_auth_method": authorizationServerAuthMethod,
			"redirect_uris":              redirectURIs,
		})
	})

	mux.HandleFunc(pathAuthorize, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get(queryParamCodeChallengeMethod) != authorizationServerCodeChallengeMethod {
			http.Error(w, "Unsupported code_challenge_method", http.StatusBadRequest)
			return
		}

		codeVerifier, err := pkceVerifier()
		if err != nil {
			logrus.WithError(err).Error("failed to generate code verifier")
			http.Error(w, "Failed to generate code verifier", http.StatusInternalServerError)
			return
		}
		codeChallenge := pkceS256Challenge(codeVerifier)

		tx := r.URL.Query()
		tx.Set(queryParamCodeVerifier, codeVerifier)
		state, err := sessionStore.store(tx, nil)
		if err != nil {
			logrus.WithError(err).Error("failed to generate state")
			http.Error(w, "Failed to generate state", http.StatusInternalServerError)
			return
		}
		setState(w, r, state)

		url := p.oauth2Config(r).AuthCodeURL(state,
			oauth2.SetAuthURLParam(queryParamCodeChallenge, codeChallenge),
			oauth2.SetAuthURLParam(queryParamCodeChallengeMethod, authorizationServerCodeChallengeMethod))
		http.Redirect(w, r, url, http.StatusSeeOther)
	})

	mux.HandleFunc(pathCallback, func(w http.ResponseWriter, r *http.Request) {
		state, err := getAndDeleteStateAndCheckCSRF(w, r)
		if err != nil {
			logrus.WithError(err).Error("failed to check CSRF")
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
			logrus.WithError(err).Error("failed to exchange authorization code for tokens")
			http.Error(w, "Failed to exchange authorization code for tokens", http.StatusBadRequest)
			return
		}

		tokens, err := p.verifyAndRepackExchangedTokens(r.Context(), oauth2Token)
		if err != nil {
			logrus.WithError(err).Error("failed to verify user")
			http.Error(w, "Failed to verify user", http.StatusBadRequest)
			return
		}

		authzCode, err := sessionStore.store(tx, tokens)
		if err != nil {
			logrus.WithError(err).Error("failed to store tokens with authorization code")
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
		if err := r.ParseForm(); err != nil {
			logrus.WithError(err).Error("failed to parse form")
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		authzCode := r.FormValue(queryParamAuthorizationCode)
		tx, tokens, ok := sessionStore.retrieve(authzCode)
		if !ok {
			http.Error(w, "Authorization code expired", http.StatusBadRequest)
			return
		}

		codeChallenge := tx.Get(queryParamCodeChallenge)
		codeVerifier := r.FormValue(queryParamCodeVerifier)
		if codeChallenge != pkceS256Challenge(codeVerifier) {
			http.Error(w, "PKCE failed", http.StatusBadRequest)
			return
		}

		respondJSON(w, r, http.StatusOK, tokens)
	})

	addr := conf.Server.Addr
	if addr == "" {
		addr = ":8080"
	}
	handler := http.Handler(mux)
	if conf.Server.CORS {
		handler = handleCORS(handler)
	}
	s := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/readyz", "/healthz":
			default:
				handler.ServeHTTP(w, r)
			}
		}),
	}

	go func() {
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.WithError(err).Fatal("failed to start server")
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			logrus.WithError(err).Error("failed to shut down server")
		} else {
			logrus.Info("server shut down successfully")
		}
	}()

	logrus.Info("server started, waiting for signal")
	<-signalReceived
	logrus.Info("signal received, shutting down server")
}
