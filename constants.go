package main

const (
	mcpOAuth2Proxy = "mcp-oauth2-proxy"

	queryParamAuthorizationCode   = "code"
	queryParamCodeChallenge       = "code_challenge"
	queryParamCodeChallengeMethod = "code_challenge_method"
	queryParamCodeVerifier        = "code_verifier"
	queryParamRedirectURI         = "redirect_uri"
	queryParamResponseType        = "response_type"
	queryParamScopes              = "scope"
	queryParamState               = "state"

	authorizationServerCodeChallengeMethod     = "S256"
	authorizationServerGrantType               = "authorization_code"
	authorizationServerResponseMode            = "query"
	authorizationServerResponseType            = "code"
	authorizationServerDefaultScope            = mcpOAuth2Proxy
	authorizationServerTokenEndpointAuthMethod = "none"
)
