{{- define "obridge.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "obridge.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "obridge.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "obridge.labels" -}}
app.kubernetes.io/name: {{ include "obridge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "obridge.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "obridge.controller.fullname" -}}
{{- printf "%s-controller" (include "obridge.fullname" .) -}}
{{- end -}}

{{- define "obridge.webhook.fullname" -}}
{{- printf "%s-webhook" (include "obridge.fullname" .) -}}
{{- end -}}

{{/* webhook TLS Certificate / Secret name (shared with cert-manager inject-ca-from). */}}
{{- define "obridge.webhook.certName" -}}
{{- printf "%s-tls" (include "obridge.webhook.fullname" .) -}}
{{- end -}}
