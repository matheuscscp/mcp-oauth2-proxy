package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/oauth2"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/constants"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/logging"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/provider"
)

func baseURL(r *http.Request) string {
	return fmt.Sprintf("https://%s", r.Host)
}

func callbackURL(r *http.Request) string {
	return baseURL(r) + pathCallback
}

func jwksURL(r *http.Request) string {
	return baseURL(r) + pathJWKS
}

func authorizationCode(r *http.Request) string {
	return r.URL.Query().Get(constants.QueryParamAuthorizationCode)
}

func state(r *http.Request) string {
	return r.URL.Query().Get(constants.QueryParamState)
}

func bearerToken(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func oauth2Config(r *http.Request, p provider.Interface, conf *config.Config) *oauth2.Config {
	c := p.OAuth2Config()
	c.ClientID = conf.Provider.ClientID
	c.RedirectURL = callbackURL(r)
	return c
}

func respondWWWAuthenticate(w http.ResponseWriter, r *http.Request) {
	resourceMetadata := fmt.Sprintf("%s%s", baseURL(r), pathOAuthProtectedResource)
	wwwAuthenticate := fmt.Sprintf(`Bearer realm="%s", resource_metadata="%s"`, constants.MCPOAuth2Proxy, resourceMetadata)
	w.Header().Set("WWW-Authenticate", wwwAuthenticate)
	const status = http.StatusUnauthorized
	http.Error(w, http.StatusText(status), status)
}

func respondJSON(w http.ResponseWriter, r *http.Request, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logging.FromRequest(r).WithError(err).Error("failed to write response")
	}
}
