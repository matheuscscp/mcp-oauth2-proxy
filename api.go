package main

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
