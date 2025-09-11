{{/*
------ Define default app labels and annotations (not for Istio) ------
*/}}

{{- define "application.annotations" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- if .Values.kafkaTopic }}
alfabank/log_kafka_topic: {{ .Values.kafkaTopic }}
{{- end }}
{{- if .Values.podAnnotations }}
{{ tpl (.Values.podAnnotations | toYaml | default) $ }}
{{- end }}
{{- end }}

{{- define "application.image.tag" -}}
{{- if .Values.image.tag }}
{{- printf "%s" .Values.image.tag -}}
{{- else }}
{{- printf "%s" .Values.containers.tag -}}
{{- end }}
{{- end }}

{{/*
------ Deployment Secrets and Volumes ------
*/}}

{{- define "application.volumes" -}}
{{- range $secret := .Values.containers.secrets }}
- name: {{ tpl $secret.name $ }}
  secret:
    defaultMode: {{ tpl (default "0420" $secret.permissions) $ }}
    secretName: {{ tpl $secret.name $ }}
{{- if $secret.items }}
    items: {{ tpl ($secret.items | toYaml | default) $ | nindent 6 }}
{{- end }}
{{- end }}
{{- range $configMap := .Values.containers.configMaps }}
- name: {{ tpl $configMap.name $ }}
  configMap:
    name: {{ tpl $configMap.name $ }}
{{- end }}
{{- range $claim := .Values.containers.persistentVolumeClaims }}
{{- if $claim.mounts }}
- name: {{ tpl $claim.name $ }}
  persistentVolumeClaim:
    claimName: {{ tpl ($claim.claimName | default $claim.name) $ }}
{{- end }}
{{- end }}
{{- end }}

{{- define "application.volumeMounts" -}}
{{- range $secret := .Values.containers.secrets }}
- mountPath: {{ tpl $secret.mountPath $ }}
  name: {{ tpl $secret.name $ }}
  readOnly: true
{{- if $secret.subPath }}
  subPath: {{ tpl $secret.subPath $ }}
{{- end }}
{{- end }}
{{- range $configMap := .Values.containers.configMaps }}
- mountPath: {{ tpl $configMap.mountPath $ }}
  name: {{ tpl $configMap.name $ }}
{{- end }}
{{- range $claim := .Values.containers.persistentVolumeClaims }}
{{- if empty $claim.mounts }}
{{- fail (print "PersistentVolumeClaim mount declaration is invalid!") -}}
{{- end }}
{{- range $mount := $claim.mounts }}
- mountPath: {{ tpl $mount.mountPath $ }}
  name: {{ tpl $claim.name $ }}
{{- if $mount.subPath }}
  subPath: {{ tpl $mount.subPath $ }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
------ VirtualServices additional parameters ------
*/}}

{{- define "virtualService.headers" -}}
{{- if .headers -}}
headers:
{{ .headers | toYaml | indent 2 -}}
{{- end -}}
{{- end -}}

{{- define "virtualService.subset" -}}
{{- if .subset -}}
subset: {{ .subset -}}
{{- end -}}
{{- end -}}

{{/*
------ Gateway and VirtualService host names ------
Create a list of fully qualified host names.
We truncate each at 253 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}

{{- define "network.fqdn_ingress" -}}
{{- $truncateError := "The following value cannot be longer than 253 characters\n" }}

{{- if .Values.global.hosts -}}

{{ tpl (.Values.global.hosts | toYaml | default) $ -}}

{{- else if .Values.overrideIngressHostname -}}
{{- if (gt (len .Values.overrideIngressHostname) 253) -}}
{{- fail (print $truncateError ".Values.overrideIngressHostname: " .Values.overrideIngressHostname) -}}
{{- end -}}

- {{ print .Values.overrideIngressHostname -}}

{{- else -}}
{{- if (gt (len (print .Values.project.name "." .Values.cluster)) 253) -}}
{{- fail (print $truncateError ".Values.project.name + . + .Values.cluster: " .Values.project.name "." .Values.cluster) -}}
{{- end -}}

- {{ print .Values.project.name "." .Values.cluster -}}

{{- end -}}

{{- end -}}

{{/*
------ Service name ------
Create a default fully qualified app name.
We truncate at 253 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}

{{- define "network.service_name" -}}
{{- $truncateError := "The following values cannot be longer than 253 characters\n" }}


{{- if (le (len .Values.project.service) 253) -}}
{{ .Values.project.service }}

{{- else -}}
{{- fail (print $truncateError ".Values.project.service: " .Values.project.service) -}}
{{- end -}}

{{- end }}


{{/*
------ Global helpers ------
*/}}

{{- define "_helper.global.chart" -}}
{{- printf "%s-%s" $.Chart.Name $.Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "_helper.global.labels" -}}
app.kubernetes.io/name: {{ .Values.project.service }}
app.kubernetes.io/component: ufr-application
app.kubernetes.io/part-of: {{ .Values.project.name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app: {{ .Values.project.service }}
helm.sh/chart: {{ include "_helper.global.chart" $ }}
{{- end }}

{{- define "_helper.global.selectorLabels" -}}
app.kubernetes.io/name: {{ .Values.project.service }}
app.kubernetes.io/component: {{ .Values.project.service }}
app.kubernetes.io/part-of: {{ .Values.project.name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app: {{ .Values.project.service }}
{{- end }}

{{/*
------ Pod helpers ------
*/}}

{{- define "_helper.pod.labels" -}}
{{ include "_helper.global.selectorLabels" $ }}
{{- if $.Values.podAdditionalLabels }}
{{ tpl ($.Values.podAdditionalLabels | toYaml | default) $ }}
{{- end }}
{{- end }}

{{- define "_helper.pod.javaOpts" -}}
{{- $maxHeap := $.Values.containers.resources.requests.memory | replace "i" "" }}
{{- $iniHeap := $maxHeap }}
{{- $maxStackSize := "1024K" }}
{{- $maxMetaSpace := "128M" }}
{{- $sslOpts := "" }}
{{- if contains "/data/ssl/CAs" ($.Values.containers.configMaps | toYaml) }}
{{-   $sslOpts = "-Djavax.net.ssl.trustStore=/data/ssl/CAs/ufr-combined-ca.p12 -Djavax.net.ssl.trustStorePassword=changeit -Djavax.net.ssl.trustStoreType=PKCS12" }}
{{- else if contains "/data/ssl/CAs" ($.Values.containers.secrets | toYaml) }}
{{-   $sslOpts = "-Djavax.net.ssl.trustStore=/data/ssl/CAs/ufrTrustStore.jks -Djavax.net.ssl.trustStorePassword= -Djavax.net.ssl.trustStoreType=JKS" }}
{{- end }}
{{- $memOpts := printf "-Xms%s -Xmx%s -Xss%s -XX:MaxMetaspaceSize=%s" $iniHeap $maxHeap $maxStackSize $maxMetaSpace }}
{{- $timezoneOpts := "-Duser.timezone=Europe/Moscow" }}
{{- $extraOpts := $.Values.containers.envs.extraJavaOpts | trim }}
{{- printf "-server %s %s %s %s" $memOpts $sslOpts $timezoneOpts $extraOpts -}}
{{- end }}

{{- define "_helper.pod.envDict" -}}
{{- if $.Values.containers.env }}
{{-   $.Values.containers.env | toYaml -}}
{{- else }}
{{-   $envDict := $.Values.containers.envs.env }}
{{-   if $.Values.containers.envs.enabledDefaults }}
{{-     $defaultEnvDict := dict
  "TZ" "Europe/Moscow" }}
{{-     if eq $.Values.containers.envs.type "java" }}
{{-       $defaultEnvDict = merge $defaultEnvDict (dict
  "JAVA_OPTS" (include "_helper.pod.javaOpts" $) ) }}
{{-     end }}
{{-     $envDict = merge $envDict $defaultEnvDict }}
{{-   end }}
{{-   $envDict | toYaml -}}
{{- end }}
{{- end }}

{{- define "_helper.pod.env" -}}
{{- range $key, $val := fromYaml (include "_helper.pod.envDict" $) }}
- name: {{ tpl $key $ | quote }}
  value: {{ tpl $val $ | quote }}
{{- end }}

{{- range $key, $val := $.Values.containers.envs.envKeyRef }}
{{- if $val }}
- name: {{ $key }}
  valueFrom:
{{- if hasKey $val "secretKeyRef" }}
    secretKeyRef:
      name: {{ $val.secretKeyRef.name | quote }}
      key: {{ $val.secretKeyRef.key | quote }}
{{- else if hasKey $val "configMapKeyRef" }}
    configMapKeyRef:
      name: {{ $val.configMapKeyRef.name | quote }}
      key: {{ $val.configMapKeyRef.key | quote }}
{{- end }}
{{- end }}
{{- end}}
{{- end }}

{{- define "_helper.pod.affinity" -}}
podAntiAffinity:
  preferredDuringSchedulingIgnoredDuringExecution:
  - weight: 100
    podAffinityTerm:
      labelSelector:
        matchExpressions:
        - key: app
          operator: In
          values:
            - {{ .Values.project.service }}
      topologyKey: kubernetes.io/hostname
{{- if $.Values.affinity }}
{{ tpl (.Values.affinity | toYaml) $ }}
{{- end }}
{{- end }}

{{- define "_helper.pod.topologySpreadConstraints" -}}
- maxSkew: 1
  topologyKey: kubernetes.io/hostname
  whenUnsatisfiable: DoNotSchedule
  labelSelector:
    matchLabels:
      app: {{ .Values.project.service }}
  minDomains: 1
  nodeAffinityPolicy: Honor
  nodeTaintsPolicy: Ignore
{{- if $.Values.topologySpreadConstraints }}
{{ tpl (.Values.topologySpreadConstraints | toYaml) $ }}
{{- end }}
{{- end }}

{{/*
------ Service helpers ------
*/}}

{{- define "_helper.service.annotations" -}}
{{- if $.Values.containers.prometheus.enabled -}}
prometheus.io/path: {{ tpl $.Values.containers.prometheus.path $ | quote }}
prometheus.io/port: "{{ $.Values.containers.prometheus.port }}"
prometheus.io/scrape: "true"
{{- end }}
{{- end }}

{{/*
------ Auth helpers ------
*/}}

{{- define "_helper.auth.authPolicy" -}}
{{- if .Values.keycloakAuth.rules }}
{{- range .Values.keycloakAuth.rules}}
  - {{- if not .notSecured }} from:
        - source:
            requestPrincipals: ["*"]
    {{- end }}
  {{- if or .paths .methods }}
    to:
    - operation:
  {{- end }}
        {{- if .paths }}
        paths: [ {{ .paths }} ]
        {{- end }}
        {{- if .methods }}
        methods: [ {{ .methods }} ]
        {{- end }}
    {{- if .roles}}
    when:
    {{- end }}
    {{- range .roles}}
    - key: request.auth.claims[realm_access][roles]
      values: [ {{ . }} ]
    {{- end }}
{{- end }}
{{ else }}
  - from:
      - source:
          requestPrincipals: [ "*" ]
{{- end }}
{{- end }}

{{- define "_helper.auth.selectorLabels" -}}
{{- if eq "custom" $.Values.keycloakAuth.workloadSelector.type -}}
{{ $.Values.keycloakAuth.workloadSelector.customLabels | toYaml }}
{{- else if eq "app" $.Values.keycloakAuth.workloadSelector.type -}}
{{ include "_helper.global.selectorLabels" $ }}
{{- else -}}
app.kubernetes.io/part-of: {{ $.Values.project.name }}
{{- end }}
{{- end }}

{{- define "_helper.auth.labels" -}}
app.kubernetes.io/component: ufr-application
app.kubernetes.io/part-of: {{ .Values.project.name }}
app.kubernetes.io/instance: {{ .Release.Name }}
helm.sh/chart: {{ include "_helper.global.chart" $ }}
{{- end }}


{{- define "ufr-chart.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}