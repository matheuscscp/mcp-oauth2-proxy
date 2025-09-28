package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/constants"
)

// transaction represents an OAuth 2.0 authorization request.
// It contains the client parameters required for the authorization
// flows that must be supported by the proxy, the code verifier
// for PKCE with the configured IdP, and the host that initiated
// the transaction.
type transaction struct {
	clientParams transactionClientParams
	codeVerifier string
	host         string
}

type transactionClientParams struct {
	codeChallenge string
	redirectURL   string
	scopes        []string
	state         string
}

func newTransaction(conf *config.ProxyConfig, r *http.Request,
	codeVerifier string, hostScopes []string) (*transaction, error) {

	host := r.Host

	q := r.URL.Query()
	codeChallenge := q.Get(constants.QueryParamCodeChallenge)
	redirectURI := q.Get(constants.QueryParamRedirectURI)
	state := q.Get(constants.QueryParamState)

	supportedScopes := make(map[string]bool, len(hostScopes))
	for _, s := range hostScopes {
		supportedScopes[s] = true
	}

	scopes := []string{}
	for s := range strings.SplitSeq(q.Get(constants.QueryParamScopes), " ") {
		if s != "" && supportedScopes[s] {
			scopes = append(scopes, s)
		}
	}

	if !conf.ValidateRedirectURL(redirectURI) {
		return nil, fmt.Errorf("%s is not in the allow list: %s", constants.QueryParamRedirectURI, redirectURI)
	}

	if rp, allowedRP := q.Get(constants.QueryParamResponseType), constants.AuthorizationServerResponseType; rp != allowedRP {
		return nil, fmt.Errorf("'%s' is not supported for %s, only %s is allowed", rp, constants.QueryParamResponseType, allowedRP)
	}

	if ccm, allowedCCM := q.Get(constants.QueryParamCodeChallengeMethod), constants.AuthorizationServerCodeChallengeMethod; ccm != allowedCCM {
		return nil, fmt.Errorf("'%s' is not supported for %s, only %s is allowed", ccm, constants.QueryParamCodeChallengeMethod, allowedCCM)
	}

	return &transaction{
		clientParams: transactionClientParams{
			codeChallenge: codeChallenge,
			redirectURL:   redirectURI,
			scopes:        scopes,
			state:         state,
		},
		codeVerifier: codeVerifier,
		host:         host,
	}, nil
}
