package main

import (
	"fmt"
	"net/http"
	"strings"
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

func newTransaction(conf *proxyConfig, r *http.Request, codeVerifier string) (*transaction, error) {
	host := r.Host

	q := r.URL.Query()
	codeChallenge := q.Get(queryParamCodeChallenge)
	redirectURI := q.Get(queryParamRedirectURI)
	state := q.Get(queryParamState)

	scopes := []string{}
	for s := range strings.SplitSeq(q.Get(queryParamScopes), " ") {
		if s != "" {
			scopes = append(scopes, s)
		}
	}

	if !conf.validateRedirectURL(redirectURI) {
		return nil, fmt.Errorf("%s is not in the allow list: %s", queryParamRedirectURI, redirectURI)
	}

	if rp, allowedRP := q.Get(queryParamResponseType), authorizationServerResponseType; rp != allowedRP {
		return nil, fmt.Errorf("'%s' is not supported for %s, only %s is allowed", rp, queryParamResponseType, allowedRP)
	}

	if ccm, allowedCCM := q.Get(queryParamCodeChallengeMethod), authorizationServerCodeChallengeMethod; ccm != allowedCCM {
		return nil, fmt.Errorf("'%s' is not supported for %s, only %s is allowed", ccm, queryParamCodeChallengeMethod, allowedCCM)
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
