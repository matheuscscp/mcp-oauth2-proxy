package store

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/constants"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/logging"
)

// Transaction represents an OAuth 2.0 authorization request.
// It contains the client parameters required for the authorization
// flows that must be supported by the proxy, the code verifier
// for PKCE with the configured IdP, and the host that initiated
// the Transaction.
type Transaction struct {
	ClientParams TransactionClientParams
	CodeVerifier string
	Host         string
}

type TransactionClientParams struct {
	CodeChallenge string
	RedirectURL   string
	Scopes        []string
	State         string
}

func NewTransaction(conf *config.ProxyConfig, r *http.Request,
	codeVerifier string, hostScopes []string) (*Transaction, error) {

	host := r.Host

	q := r.URL.Query()
	codeChallenge := q.Get(constants.QueryParamCodeChallenge)
	redirectURI := q.Get(constants.QueryParamRedirectURI)
	state := q.Get(constants.QueryParamState)

	supportedScopes := make(map[string]bool, len(hostScopes))
	for _, s := range hostScopes {
		supportedScopes[s] = true
	}

	var requestedScopes []string
	grantedScopes := []string{}
	for s := range strings.SplitSeq(q.Get(constants.QueryParamScopes), " ") {
		if s == "" {
			continue
		}
		requestedScopes = append(requestedScopes, s)
		if supportedScopes[s] {
			grantedScopes = append(grantedScopes, s)
		}
	}
	logging.FromRequest(r).WithField("requestScopes", requestedScopes).Debug("transaction requested scopes")

	if !conf.ValidateRedirectURL(redirectURI) {
		return nil, fmt.Errorf("%s is not in the allow list: %s", constants.QueryParamRedirectURI, redirectURI)
	}

	if rp, allowedRP := q.Get(constants.QueryParamResponseType), constants.AuthorizationServerResponseType; rp != allowedRP {
		return nil, fmt.Errorf("'%s' is not supported for %s, only %s is allowed", rp, constants.QueryParamResponseType, allowedRP)
	}

	if ccm, allowedCCM := q.Get(constants.QueryParamCodeChallengeMethod), constants.AuthorizationServerCodeChallengeMethod; ccm != allowedCCM {
		return nil, fmt.Errorf("'%s' is not supported for %s, only %s is allowed", ccm, constants.QueryParamCodeChallengeMethod, allowedCCM)
	}

	return &Transaction{
		ClientParams: TransactionClientParams{
			CodeChallenge: codeChallenge,
			RedirectURL:   redirectURI,
			Scopes:        grantedScopes,
			State:         state,
		},
		CodeVerifier: codeVerifier,
		Host:         host,
	}, nil
}
