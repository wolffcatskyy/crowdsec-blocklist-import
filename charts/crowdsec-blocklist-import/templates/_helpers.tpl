{{/*
Expand the name of the chart.
*/}}
{{- define "crowdsec-blocklist-import.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "crowdsec-blocklist-import.fullname" -}}
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
{{- define "crowdsec-blocklist-import.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "crowdsec-blocklist-import.labels" -}}
helm.sh/chart: {{ include "crowdsec-blocklist-import.chart" . }}
{{ include "crowdsec-blocklist-import.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "crowdsec-blocklist-import.selectorLabels" -}}
app.kubernetes.io/name: {{ include "crowdsec-blocklist-import.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "crowdsec-blocklist-import.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "crowdsec-blocklist-import.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret holding CROWDSEC_LAPI_KEY and friends.
*/}}
{{- define "crowdsec-blocklist-import.secretName" -}}
{{- if .Values.existingSecret }}
{{- .Values.existingSecret }}
{{- else }}
{{- include "crowdsec-blocklist-import.fullname" . }}
{{- end }}
{{- end }}

{{/*
Validate the requested run mode.
*/}}
{{- define "crowdsec-blocklist-import.validateMode" -}}
{{- if not (or (eq .Values.mode "cronjob") (eq .Values.mode "deployment")) }}
{{- fail "mode must be \"cronjob\" or \"deployment\"" }}
{{- end }}
{{- end }}

{{/*
Container spec shared by the CronJob and Deployment workloads.
Expects a dict: {"root": ., "interval": "0"} - interval is forced to "0"
for one-shot CronJob runs and comes from config.interval for the daemon.
*/}}
{{- define "crowdsec-blocklist-import.container" -}}
{{- $root := .root -}}
name: {{ include "crowdsec-blocklist-import.name" $root }}
image: "{{ $root.Values.image.repository }}:{{ $root.Values.image.tag | default $root.Chart.AppVersion }}"
imagePullPolicy: {{ $root.Values.image.pullPolicy }}
envFrom:
  - configMapRef:
      name: {{ include "crowdsec-blocklist-import.fullname" $root }}
env:
  - name: INTERVAL
    value: {{ .interval | quote }}
  - name: CROWDSEC_LAPI_KEY
    valueFrom:
      secretKeyRef:
        name: {{ include "crowdsec-blocklist-import.secretName" $root }}
        key: CROWDSEC_LAPI_KEY
  - name: ABUSEIPDB_API_KEY
    valueFrom:
      secretKeyRef:
        name: {{ include "crowdsec-blocklist-import.secretName" $root }}
        key: ABUSEIPDB_API_KEY
        optional: true
  - name: WEBHOOK_URL
    valueFrom:
      secretKeyRef:
        name: {{ include "crowdsec-blocklist-import.secretName" $root }}
        key: WEBHOOK_URL
        optional: true
  {{- with $root.Values.extraEnv }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
{{- with $root.Values.securityContext }}
securityContext:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $root.Values.resources }}
resources:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
