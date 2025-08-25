package main

import (
	"fmt"
	"net/http"
)

// transaction represents an OAuth 2.0 authorization request.
// It contains the client parameters required for the authorization
// flows that must be supported by the proxy and the code verifier
// for PKCE with the configured IdP.
type transaction struct {
	clientParams transactionClientParams
	codeVerifier string
}

type transactionClientParams struct {
	codeChallenge string
	redirectURL   string
	state         string
}

func newTransaction(conf *proxyConfig, r *http.Request, codeVerifier string) (*transaction, error) {
	q := r.URL.Query()
	codeChallenge := q.Get(queryParamCodeChallenge)
	redirectURI := q.Get(queryParamRedirectURI)
	state := q.Get(queryParamState)

	if !conf.validateRedirectURL(redirectURI) {
		return nil, fmt.Errorf("%s is not in the allow list: %s", queryParamRedirectURI, redirectURI)
	}

	return &transaction{
		clientParams: transactionClientParams{
			codeChallenge: codeChallenge,
			redirectURL:   redirectURI,
			state:         state,
		},
		codeVerifier: codeVerifier,
	}, nil
}
