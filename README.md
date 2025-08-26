# mcp-oauth2-proxy

[![release](https://img.shields.io/github/v/release/matheuscscp/mcp-oauth2-proxy?sort=semver)](https://github.com/matheuscscp/mcp-oauth2-proxy/releases/latest)
[![test](https://github.com/matheuscscp/mcp-oauth2-proxy/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/matheuscscp/mcp-oauth2-proxy/actions/workflows/test.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![codecov](https://codecov.io/gh/matheuscscp/mcp-oauth2-proxy/branch/main/graph/badge.svg)](https://codecov.io/gh/matheuscscp/mcp-oauth2-proxy)

The search is over. Easy OAuth 2.0 proxy for MCP servers.

## Architecture

```mermaid
flowchart TB
    User[👤 User<br/>Browser]
    AI[🤖 AI Client<br/>Claude Desktop]
    RP[🔀 Reverse Proxy<br/>nginx]
    Proxy[🛡️ mcp-oauth2-proxy<br/>Authorization Server]
    IdP[🔑 Identity Provider<br/>Google/GitHub/Azure]
    MCP1[📦 MCP Server 1<br/>host: server1.example.com]
    MCP2[📦 MCP Server 2<br/>host: server2.example.com]
    
    %% User interactions
    User -.-> AI
    User -.-> IdP
    
    %% AI Client to services via Reverse Proxy
    AI --> RP
    RP --> Proxy
    RP --> MCP1
    RP --> MCP2
    
    %% Authentication flow
    Proxy -.-> IdP
    RP --> Proxy
    
    %% Styling
    classDef userStyle fill:#e1f5fe,stroke:#0277bd,stroke-width:2px
    classDef aiStyle fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef proxyStyle fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
    classDef idpStyle fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
    classDef mcpStyle fill:#fce4ec,stroke:#c2185b,stroke-width:2px
    classDef rpStyle fill:#f1f8e9,stroke:#558b2f,stroke-width:2px
    
    class User userStyle
    class AI aiStyle
    class Proxy proxyStyle
    class IdP idpStyle
    class MCP1,MCP2 mcpStyle
    class RP rpStyle
```

### How it Works

1. **User Authentication**: The user authenticates with the Identity Provider (IdP) through their browser using OAuth2 + PKCE
2. **AI Client Authorization**: The AI client initiates its own OAuth2 + PKCE flow, treating mcp-oauth2-proxy as the authorization server
3. **Proxy Mediation**: mcp-oauth2-proxy handles the OAuth flow by redirecting the user to complete authentication with the backing IdP
4. **Token Issuance**: After successful IdP authentication, mcp-oauth2-proxy issues its own JWT token to the AI client
5. **MCP Access**: AI client uses the JWT token to access MCP servers through the reverse proxy
6. **Request Routing**: Reverse proxy routes requests to appropriate MCP servers based on the Host header
7. **Token Validation**: For each MCP request, the reverse proxy calls `/authenticate` to validate the bearer token
8. **Secure Token Passing**: mcp-oauth2-proxy validates the token and returns it via `X-Auth-Request-Access-Token` header if valid
9. **MCP Server Access**: Reverse proxy forwards the request to the MCP server with the validated token

### API Endpoints

mcp-oauth2-proxy exposes the following HTTP endpoints:

#### Authentication Endpoint
- **`/authenticate`** - Token validation endpoint used by reverse proxy
  - **Input Headers**:
    - `Authorization: Bearer <jwt-token>` - JWT token issued by mcp-oauth2-proxy
  - **Output Headers** (on success - HTTP 200):
    - `X-Auth-Request-Access-Token: <jwt-token>` - Validated JWT token for forwarding
  - **Output Headers** (on failure - HTTP 401):
    - `WWW-Authenticate: Bearer realm="mcp-oauth2-proxy", resource_metadata="<base-url>/.well-known/oauth-protected-resource"`

#### OAuth 2.0 Discovery Endpoints
- **`/.well-known/oauth-protected-resource`** - OAuth 2.0 Protected Resource metadata
- **`/.well-known/oauth-authorization-server`** - OAuth 2.0 Authorization Server metadata

#### OAuth 2.0 Flow Endpoints
- **`/register`** - OAuth 2.0 Dynamic Client Registration
- **`/authorize`** - OAuth 2.0 Authorization endpoint (PKCE required)
- **`/callback`** - OAuth 2.0 Authorization callback
- **`/token`** - OAuth 2.0 Token exchange endpoint

### Key Features

- **Dual OAuth2 Flows**: Creates an authorization realm where the AI client never knows about the backing IdP
- **Cryptographic Isolation**: Keeps IdP cryptographic material secure, away from both AI clients and MCP servers
- **JWT Token Management**: Issues and manages its own JWT tokens for secure communication
- **Automatic Key Rotation**: Handles private key rotation for token signing and verification
- **Host-based Routing**: Supports multiple MCP servers through HTTP Host header routing

## Installation

### Container Images

Container images are distributed via GitHub Container Registry and signed with keyless Cosign:

```
ghcr.io/matheuscscp/mcp-oauth2-proxy
```

### Helm Chart

OCI Helm charts are available in GitHub Container Registry and signed with keyless Cosign:

```bash
helm install mcp-oauth2-proxy oci://ghcr.io/matheuscscp/mcp-oauth2-proxy/charts/mcp-oauth2-proxy \
  --set provider.name=google \
  --set provider.clientID=your-client-id \
  --set provider.clientSecret=your-client-secret
```

**Note**: The provider defaults to Google if not specified in the Helm values.

For all available configuration options, see the [values.yaml](charts/mcp-oauth2-proxy/values.yaml) file.

### ingress-nginx Integration

To integrate with ingress-nginx, configure the mcp-oauth2-proxy Helm chart to enable ingress, then create Ingress resources for each MCP server that requires authentication.

#### Configure mcp-oauth2-proxy Ingress via Helm

```bash
helm install mcp-oauth2-proxy oci://ghcr.io/matheuscscp/mcp-oauth2-proxy/charts/mcp-oauth2-proxy \
  --set provider.clientID=your-client-id \
  --set provider.clientSecret=your-client-secret \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set 'ingress.hosts[0]=my-mcp.example.com'
```

#### MCP Server Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-mcp-server
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    # Only the auth-url annotation is needed for mcp-oauth2-proxy integration
    nginx.ingress.kubernetes.io/auth-url: https://$host/authenticate
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - my-mcp.example.com
      secretName: my-mcp-server-tls
  rules:
    - host: my-mcp.example.com
      http:
        paths:
          - path: /mcp
            pathType: ImplementationSpecific
            backend:
              service:
                name: my-mcp-server
                port:
                  name: http
```

The key difference from traditional oauth2-proxy integration is that mcp-oauth2-proxy only requires the `auth-url` annotation. The `/authenticate` endpoint handles token validation and returns the validated token via the `X-Auth-Request-Access-Token` header when authentication succeeds, or returns 401 with `WWW-Authenticate` header when authentication fails.

### Key Configuration Options

- `provider.name`: OAuth2 provider (`google`)
- `provider.clientID`: OAuth2 client ID from your IdP
- `provider.clientSecret`: OAuth2 client secret from your IdP  
- `provider.allowedEmailDomains`: List of Go regular expressions for allowed email domains
- `proxy.allowedRedirectURLs`: List of Go regular expressions for allowed redirect URLs
- `server.cors`: Enable CORS support
- `ingress.enabled`: Enable ingress for external access
- `podMonitor.enabled`: Enable Prometheus monitoring

## Roadmap

- [x] Google Authentication
- [ ] GitHub Authentication
- [ ] Microsoft Entra ID Authentication
- [ ] Google Authorization (via Google Groups)
- [ ] GitHub Authorization (via GitHub Teams)
- [ ] Azure Authorization (via Microsoft Entra ID Groups)
