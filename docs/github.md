# GitHub Provider

The GitHub provider can be configured to authenticate users with a
GitHub OAuth App or a GitHub App, and can optionally be configured to
also fetch the user's teams in a GitHub Organization by configuring
a GitHub App private key.

This provider does not support any form of configuring the use of
short-lived credentials automatically fetched from the execution
environment. This is a limitation from GitHub. If you need this
feature, consider using another provider.

To configure this provider, set the following Helm values:

```yaml
provider:
  name: github
```

## Authentication

The username returned by the GitHub provider is the user's GitHub username.

To create and configure a *GitHub OAuth App*, follow the instructions
[here](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app).

To create and configure a *GitHub App*, follow the instructions
[here](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app).

In both cases, you must add an Authorization callback URL for the
proxy callback URL, e.g. `https://mcp.example.com/callback`.

Example of Helm values for the GitHub provider:

```yaml
provider:
  name: github
  clientID: I1c6Oj1r3liQMvHv2ZSj
  clientSecret: 68bf05c8d7a9d30d1b2285576875ba00b2b41ff3
```

## Authorization

If configured with a GitHub App private key, the proxy will also verify
the state of the user membership in a GitHub Organization. If the user is
suspended or not active in the GitHub Organization, the proxy will not let
them in. In addition, the proxy will also list the GitHub Teams the user
is a member of in the GitHub Organization and add them to the `groups`
claim of JWTs issued for AI clients.

When configured to use a GitHub App for authorization, authentication must
also be done with the same GitHub App, you cannot use separate GitHub Apps
for authentication and authorization. If you only need authentication, a
GitHub OAuth App is sufficient.

The configuration steps are:

1. Create a GitHub App inside the GitHub Organization and grant it
Read-only access to Members in the Organization permissions.
2. Configure the GitHub App for [authentication](#authentication)
and configure the proxy to use the GitHub App for authentication.
3. [Create](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps#generating-private-keys)
a private key for the GitHub App and download the PEM file.

Example of Kubernetes Secret with a GitHub App private key:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: github-app
  namespace: mcp-oauth2-proxy
type: Opaque
stringData:
  private-key.pem: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIEp.....xKUjqKA==
    -----END RSA PRIVATE KEY-----
```

Example of Helm values to mount the key in the proxy:

```yaml
provider:
  name: github
  clientID: I1c6Oj1r3liQMvHv2ZSj
  clientSecret: 68bf05c8d7a9d30d1b2285576875ba00b2b41ff3
  organization: my-github-org # must be set only when a GitHub App private key is configured
volumes:
  - name: github-app
    secret:
      secretName: github-app
volumeMounts:
  - name: github-app
    mountPath: /etc/mcp-oauth2-proxy/github
    readOnly: true
env:
  - name: GITHUB_APP_PRIVATE_KEY
    value: /etc/mcp-oauth2-proxy/github/private-key.pem
```
