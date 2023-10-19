{{/*
Expand the name of the chart.
*/}}
{{- define "vul-operator.name" -}}
  {{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec). If release name contains chart name it will be used
as a full name.
*/}}
{{- define "vul-operator.fullname" -}}
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
{{- define "vul-operator.chart" -}}
  {{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "vul-operator.labels" -}}
{{- if eq .Values.managedBy "Helm" -}}
helm.sh/chart: {{ include "vul-operator.chart" . }}
{{ end -}}
{{ include "vul-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Values.managedBy }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "vul-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vul-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "vul-operator.serviceAccountName" -}}
  {{- if .Values.serviceAccount.create }}
    {{- default (include "vul-operator.fullname" .) .Values.serviceAccount.name }}
  {{- else }}
    {{- default "default" .Values.serviceAccount.name }}
  {{- end }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "vul-operator.namespace" -}}
  {{- default .Release.Namespace .Values.operator.namespace }}
{{- end }}

{{/*
Define the image registry to use if global values are set.
*/}}
{{- define "global.imageRegistry" -}}
{{- if ((.Values.global).image).registry -}}
  {{- .Values.global.image.registry }}
{{- end }}
{{- end }}
