# Google Provider

The Google provider can be configured to authenticate users with a
Google OAuth2 Client, and to optionally fetch their Google Groups in
a Google Workspace by configuring a GCP Service Account.

To configure this provider, set the following Helm values:

```yaml
provider:
  name: google
```

## Authentication

The username returned by the Google provider is the user's email address.
The Google provider will take the list of Go regular expressions for the
allowed email domains into account when authenticating users. If the list
is empty or not set, all email domains are allowed.

To create and configure a Google OAuth2 Client, follow the instructions
[here](https://support.google.com/cloud/answer/15549257). You must add
an Authorized JavaScript Origin for the MCP URL without any paths, e.g.
`https://mcp.example.com`, and an Authorized Redirect URI for the
proxy callback URL, e.g. `https://mcp.example.com/callback`.

Example of Helm values for the Google provider:

```yaml
provider:
  name: google
  clientID: your-client-id.apps.googleusercontent.com
  clientSecret: your-client-secret
  allowedEmailDomains:
    - ^my-org\.com$
```

## Authorization

If configured with a GCP Service Account, the proxy will also verify the state of
the user in a Google Workspace identified by the domain of the user's email address.
If the user is archived, suspended or deleted, the proxy will not let them in.
In addition, the proxy will also list the Google Groups the user is a member of
in the Google Workspace and add them to the `groups` claim of JWTs issued for
AI clients.

The configuration steps are:

1. Create a GCP Project and enable the following APIs on it:
    - `iamcredentials.googleapis.com` (for minting JWTs)
    - `admin.googleapis.com` (for accessing Google Workspace user and group info)
2. Create a GCP Service Account and grant it the IAM Role Service Account Token Creator
(`roles/iam.serviceAccountTokenCreator`) *on itself*. This self-impersonation permission
is required for the proxy to use this Service Account to call the IAM SignJWT API for
minting JWTs for Google Workspace Domain-wide Delegation.
3. [Configure the proxy](#configuring-the-proxy-to-use-a-gcp-service-account)
to use the Service Account via one of the following methods:
    - [Workload Identity Federation for GKE](#via-workload-identity-federation-for-gke)
    - [Workload Identity Federation for Kubernetes](#via-workload-identity-federation-for-kubernetes)
    - [JSON Private Key](#via-json-private-key)
4. In the Google Workspace Admin Console, go to Security > Access and data control >
API controls > MANAGE DOMAIN WIDE DELEGATION > Add new (API client). In the Client ID
field, enter the Client ID of the Service Account created in step 1 (can be found in
the Service Account page in the Google Cloud Console). In the OAuth scopes field,
enter the following scopes separated by comma and click AUTHORIZE:
    - `https://www.googleapis.com/auth/admin.directory.user.readonly`
    - `https://www.googleapis.com/auth/admin.directory.group.readonly`

### Configuring the proxy to use a GCP Service Account

#### Via Workload Identity Federation for GKE

If you are running the proxy in a GKE Kubernetes cluster, you can use
[Workload Identity Federation for GKE](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity).

**Note:** This link describes two methods: one where a GCP Service Account is not
used, and one where a GCP Service Account is used. The latter is required for the
proxy to be able to call the IAM SignJWT API for minting JWTs for Google Workspace
Domain-wide Delegation. Google Workspace Domain-wide Delegation requires a GCP
Service Account.

Set the following Helm values:

```yaml
serviceAccount:
  create: true
  name: mcp-oauth2-proxy # Must match the KSA name configured in GCP.
  annotations:
    iam.gke.io/gcp-service-account: my-sa-name@my-project-id.iam.gserviceaccount.com
```

#### Via Workload Identity Federation for Kubernetes

If you are running the proxy in a Kubernetes cluster that is not GKE, you can use
[Workload Identity Federation for Kubernetes](https://cloud.google.com/iam/docs/workload-identity-federation-with-kubernetes).

**Note:** This link describes two methods: one where a GCP Service Account is not
used, and one where a GCP Service Account is used. The latter is required for the
proxy to be able to call the IAM SignJWT API for minting JWTs for Google Workspace
Domain-wide Delegation. Google Workspace Domain-wide Delegation requires a GCP
Service Account.

Create a Kubernetes ConfigMap with the JSON configuration:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: google-credentials
  namespace: mcp-oauth2-proxy
data:
  credentials.json: |
    {
      "universe_domain": "googleapis.com",
      "type": "external_account",
      "audience": "//iam.googleapis.com/projects/MY_PROJECT_NUMBER/locations/global/workloadIdentityPools/MY_POOL_ID/providers/MY_PROVIDER_ID",
      "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
      "token_url": "https://sts.googleapis.com/v1/token",
      "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/my-sa-name@my-project-id.iam.gserviceaccount.com:generateAccessToken",
      "credential_source": {
        "file": "/var/run/service-account/gcp-token",
        "format": {
          "type": "text"
        }
      }
    }
```

Then set the following Helm values:

```yaml
serviceAccount:
  create: true
  name: mcp-oauth2-proxy # Must match the KSA name configured in GCP.
volumes:
  - name: google-credentials
    configMap:
      name: google-credentials
  - name: gcp-token
    projected:
      sources:
      - serviceAccountToken:
          audience: https://iam.googleapis.com/projects/MY_PROJECT_NUMBER/locations/global/workloadIdentityPools/MY_POOL_ID/providers/MY_PROVIDER_ID
          expirationSeconds: 3600
          path: gcp-token
volumeMounts:
  - name: google-credentials
    mountPath: /etc/mcp-oauth2-proxy/google
    readOnly: true
  - name: gcp-token
    mountPath: /var/run/service-account
    readOnly: true
env:
  - name: GOOGLE_APPLICATION_CREDENTIALS
    value: /etc/mcp-oauth2-proxy/google/credentials.json
```

#### Via JSON Private Key

This is the most unrecommended method as it involves using a long-lived
JSON Private Key, which means the rotation and security hygiene is on you.
Furthermore, if an attacker steals this key, they can impersonate the
Service Account from anywhere with Internet access.

Google is actively trying to move users away from this method, so if your GCP
Organization was created after May 2024, you will need to enable the creation of
[Service Account Keys](https://cloud.google.com/iam/docs/keys-create-delete#allow-creation).

After enabling the creation of Service Account Keys, you can create a new key following
[this](https://cloud.google.com/iam/docs/keys-create-delete#iam-service-account-keys-create-console)
guide.

Create a Kubernetes Secret with the JSON Private Key:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: google-credentials
  namespace: mcp-oauth2-proxy
type: Opaque
stringData:
  credentials.json: |
    {
      "type": "service_account",
      "project_id": "my-project-id",
      "private_key_id": "43b7ed5d5a204028cee1b628ed9bee81c707ca07",
      "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQ...yIsIN2JY=\n-----END PRIVATE KEY-----\n",
      "client_email": "my-sa-name@my-project-id.iam.gserviceaccount.com",
      "client_id": "114521628649475320846",
      "auth_uri": "https://accounts.google.com/o/oauth2/auth",
      "token_uri": "https://oauth2.googleapis.com/token",
      "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
      "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/my-sa-name%40my-project-id.iam.gserviceaccount.com",
      "universe_domain": "googleapis.com"
    }
```

Then set the following Helm values:

```yaml
volumes:
  - name: google-credentials
    secret:
      secretName: google-credentials
volumeMounts:
  - name: google-credentials
    mountPath: /etc/mcp-oauth2-proxy/google
    readOnly: true
env:
  - name: GOOGLE_APPLICATION_CREDENTIALS
    value: /etc/mcp-oauth2-proxy/google/credentials.json
```
