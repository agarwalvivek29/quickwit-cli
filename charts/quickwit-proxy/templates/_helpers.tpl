{{/* Chart name (overridable). */}}
{{- define "quickwit-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified app name. */}}
{{- define "quickwit-proxy.fullname" -}}
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

{{- define "quickwit-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "quickwit-proxy.labels" -}}
helm.sh/chart: {{ include "quickwit-proxy.chart" . }}
{{ include "quickwit-proxy.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "quickwit-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "quickwit-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "quickwit-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "quickwit-proxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Name of the Secret holding the audit DSN (defaults to the release fullname). */}}
{{- define "quickwit-proxy.dsnSecretName" -}}
{{- default (include "quickwit-proxy.fullname" .) .Values.proxy.audit.dsnSecretName }}
{{- end }}
