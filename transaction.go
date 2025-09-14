package main

import (
	"fmt"
	"net/http"
)

// transaction represents an OAuth 2.0 authorization request.
// It contains the client parameters required for the authorization
// flows that must be supported by the proxy, the code verifier
// for PKCE with the configured IdP, and the host of the proxy
// that is handling the request.
type transaction struct {
	clientParams transactionClientParams
	codeVerifier string
	host         string
}

type transactionClientParams struct {
	codeChallenge string
	redirectURL   string
	state         string
}

func newTransaction(conf *proxyConfig, r *http.Request, codeVerifier string) (*transaction, error) {
	host := r.Host

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
		host:         host,
	}, nil
}
