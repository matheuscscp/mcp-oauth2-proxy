package constants

const (
	MCPOAuth2Proxy = "mcp-oauth2-proxy"

	QueryParamAuthorizationCode   = "code"
	QueryParamCodeChallenge       = "code_challenge"
	QueryParamCodeChallengeMethod = "code_challenge_method"
	QueryParamCodeVerifier        = "code_verifier"
	QueryParamRedirectURI         = "redirect_uri"
	QueryParamResponseType        = "response_type"
	QueryParamScopes              = "scope"
	QueryParamState               = "state"

	AuthorizationServerCodeChallengeMethod     = "S256"
	AuthorizationServerGrantType               = "authorization_code"
	AuthorizationServerResponseMode            = "query"
	AuthorizationServerResponseType            = "code"
	AuthorizationServerDefaultScope            = MCPOAuth2Proxy
	AuthorizationServerTokenEndpointAuthMethod = "none"
)
