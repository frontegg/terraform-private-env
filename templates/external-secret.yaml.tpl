installCRDs: ${installCRDs}
replicaCount: ${replicaCount}

serviceAccount:
  create: true
  name: "external-secrets"
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::${accountid}:role/external-secrets-${environment}-role"

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 250m
    memory: 256Mi

env:
  - name: "AWS_REGION"
    value: "${region}"
  - name: "LOG_LEVEL"
    value: "info"
  - name: "ENVIRONMENT"
    value: "${environment}"

concurrent: ${concurrent}

webhook:
  create: true
  replicaCount: ${replicaCount}
  resources:
    limits:
      cpu: 100m
      memory: 256Mi
    requests:
      cpu: 50m
      memory: 128Mi

prometheus:
  enabled: true
  servicemonitor:
    enabled: true

# The affinity section specifies rules for scheduling pods in the Kubernetes cluster.
# In this case, it ensures that pods with the label 'app.kubernetes.io/name' equal to 'external-secrets'
# are not scheduled on the same node.
affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchExpressions:
        - key: app.kubernetes.io/name
          operator: In
          values:
          - external-secrets
      topologyKey: kubernetes.io/hostname