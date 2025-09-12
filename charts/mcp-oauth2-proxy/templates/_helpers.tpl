{{/*
Expand the name of the chart.
*/}}
{{- define "mcp-oauth2-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "mcp-oauth2-proxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "mcp-oauth2-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "mcp-oauth2-proxy.labels" -}}
helm.sh/chart: {{ include "mcp-oauth2-proxy.chart" . }}
{{ include "mcp-oauth2-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "mcp-oauth2-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcp-oauth2-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "mcp-oauth2-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "mcp-oauth2-proxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the list of HTTP paths that ingress must listen on.
*/}}
{{- define "mcp-oauth2-proxy.ingressPaths" -}}
paths:
  # Authentication endpoint.
  - /authenticate

  # OAuth2 DCRP endpoints.
  - /.well-known/oauth-protected-resource
  - /.well-known/oauth-authorization-server
  - /register
  - /authorize
  - /callback
  - /token

  # OIDC endpoints.
  - /.well-known/openid-configuration
  - /openid/v1/jwks
{{- end }}
