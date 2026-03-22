# Agentity Helm Chart Deployment Guide

This guide covers production-ready deployments of Agentity using Kubernetes and Helm.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Pre-Deployment Checklist](#pre-deployment-checklist)
3. [Secret Management](#secret-management)
4. [Deployment Scenarios](#deployment-scenarios)
5. [Post-Deployment Verification](#post-deployment-verification)
6. [Monitoring and Observability](#monitoring-and-observability)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

- Kubernetes cluster 1.24+
- Helm 3.0+
- kubectl configured to access your cluster
- (Optional) cert-manager for TLS/HTTPS
- (Optional) Prometheus for metrics
- (Optional) External PostgreSQL database
- (Optional) Redis instance or cluster

## Pre-Deployment Checklist

### 1. Generate Cryptographic Keys

Generate a 32-byte hex key for cryptographic operations:
```bash
CRYPTO_KEY=$(openssl rand -hex 32)
echo "AGENTITY_CRYPTO_ROOT_KEY=$CRYPTO_KEY"
```

Generate a secure admin API key:
```bash
ADMIN_KEY=$(openssl rand -hex 32)
echo "AGENTITY_AUTH_ADMIN_API_KEY=$ADMIN_KEY"
```

### 2. Plan Your Infrastructure

Decide on:
- **Store Backend**: memory (dev-only) or PostgreSQL (production)
- **Cache Layer**: Redis (optional, for distributed deployments)
- **Authentication**: OIDC issuer URL (if using OIDC)
- **Observability**: OpenTelemetry endpoint (if enabling distributed tracing)
- **Ingress**: Domain name and TLS certificate issuer

### 3. Prepare Kubernetes Namespace

```bash
kubectl create namespace agentity
kubectl label namespace agentity workload=agentity
```

### 4. Configure RBAC (if needed)

The chart creates a ServiceAccount by default. For fine-grained RBAC:
```bash
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: agentity
  namespace: agentity
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
EOF
```

## Secret Management

### Option 1: Sealed Secrets (Recommended)

Install sealed-secrets controller:
```bash
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.18.0/controller.yaml
```

Create a secret file:
```bash
cat > secrets.yaml <<EOF
adminApiKey: "your-secret-admin-key"
cryptoRootKey: "0123456789abcdef0123456789abcdef"
postgresql:
  password: "postgres-password"
redis:
  password: "redis-password"
EOF
```

Seal it:
```bash
kubectl create secret generic agentity-secrets \
  --from-literal=adminApiKey="your-admin-key" \
  -n agentity \
  --dry-run=client -o yaml | kubeseal -f - > sealed-secrets.yaml
```

Deploy sealed secret:
```bash
kubectl apply -f sealed-secrets.yaml
```

### Option 2: External Secrets Operator

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  -n external-secrets-system --create-namespace
```

Create an external secret:
```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-store
spec:
  provider:
    vault:
      server: "https://vault.example.com"
      path: "secret"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "agentity"
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: agentity
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-store
    kind: SecretStore
  target:
    name: agentity
    creationPolicy: Owner
  data:
    - secretKey: adminApiKey
      remoteRef:
        key: agentity
        property: admin_api_key
    - secretKey: cryptoRootKey
      remoteRef:
        key: agentity
        property: crypto_root_key
```

### Option 3: Helm Values with Secrets File

Create `secrets.yaml`:
```yaml
adminApiKey: "your-secret-key-here"
cryptoRootKey: "0123456789abcdef0123456789abcdef"
postgresql:
  password: "postgres-password"
redis:
  password: "redis-password"
```

Add to `.gitignore`:
```
secrets.yaml
*-secrets.yaml
```

Deploy with both files:
```bash
helm install agentity ./charts/agentity \
  -f values-production.yaml \
  -f secrets.yaml
```

## Deployment Scenarios

### Scenario 1: Minimal Development Deployment

```bash
helm install agentity ./charts/agentity \
  -f charts/agentity/values-development.yaml \
  -n agentity
```

Verify:
```bash
kubectl port-forward -n agentity svc/agentity 8080:8080
curl http://localhost:8080/health
```

### Scenario 2: Production with PostgreSQL and Redis

Create `prod-values.yaml`:
```yaml
replicaCount: 3

config:
  store:
    type: postgres

postgresql:
  enabled: true
  host: postgres.prod.svc.cluster.local
  password: "secure-password"

redis:
  enabled: true
  address: redis-cluster.prod.svc.cluster.local:6379
  password: "secure-password"

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: agentity.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: agentity-tls
      hosts:
        - agentity.example.com
```

Deploy:
```bash
helm install agentity ./charts/agentity \
  -f prod-values.yaml \
  -f secrets.yaml \
  -n agentity \
  --create-namespace
```

### Scenario 3: Multi-Region with OIDC

Create `multi-region-values.yaml`:
```yaml
replicaCount: 3

config:
  logLevel: info

oidc:
  issuerUrl: "https://keycloak.example.com/auth/realms/agentity"

postgresql:
  enabled: true
  host: postgres-global.prod.svc.cluster.local
  maxConns: 50

redis:
  enabled: true
  address: redis-cluster-global.prod.svc.cluster.local:6379

otel:
  enabled: true
  exporterType: otlp
  endpoint: "http://otel-collector.monitoring.svc.cluster.local:4317"

affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchExpressions:
            - key: app.kubernetes.io/name
              operator: In
              values:
                - agentity
        topologyKey: kubernetes.io/hostname
```

Deploy to multiple clusters:
```bash
for cluster in us-east-1 eu-west-1 ap-southeast-1; do
  kubectl config use-context $cluster
  helm install agentity ./charts/agentity \
    -f multi-region-values.yaml \
    -f secrets-$cluster.yaml \
    -n agentity \
    --create-namespace
done
```

## Post-Deployment Verification

### 1. Check Deployment Status

```bash
kubectl rollout status deployment/agentity -n agentity
kubectl get pods -n agentity -l app.kubernetes.io/name=agentity
```

### 2. Verify Service is Running

```bash
kubectl get svc -n agentity agentity
kubectl get endpoints -n agentity agentity
```

### 3. Test Health Endpoint

```bash
kubectl run -it --rm debug --image=alpine --restart=Never -- \
  wget http://agentity.agentity.svc.cluster.local:8080/health
```

### 4. Retrieve Admin API Key

```bash
kubectl get secret -n agentity agentity \
  -o jsonpath="{.data.AGENTITY_AUTH_ADMIN_API_KEY}" | base64 --decode
```

### 5. Check Logs

```bash
kubectl logs -n agentity -l app.kubernetes.io/name=agentity --tail=100
```

## Monitoring and Observability

### Prometheus Metrics

The Agentity chart includes Prometheus scrape annotations. Add this ServiceMonitor:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: agentity
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: agentity
  endpoints:
    - port: http
      path: /metrics
      interval: 30s
```

### Distributed Tracing with OpenTelemetry

Enable OTEL in values:
```yaml
otel:
  enabled: true
  serviceName: agentity
  exporterType: otlp
  endpoint: "http://otel-collector.monitoring.svc.cluster.local:4317"
```

### Structured Logging

Configure JSON logging:
```yaml
config:
  logFormat: json
  logLevel: info
```

Parse logs with a tool like Loki:
```bash
kubectl logs -n agentity -l app.kubernetes.io/name=agentity -f | jq '.'
```

## Troubleshooting

### Pod won't start

```bash
kubectl describe pod -n agentity -l app.kubernetes.io/name=agentity
kubectl logs -n agentity -l app.kubernetes.io/name=agentity
```

### CrashLoopBackOff

Check readiness/liveness probe failures:
```bash
kubectl get events -n agentity --sort-by='.lastTimestamp'
```

### Service not accessible

```bash
kubectl get svc -n agentity
kubectl get endpoints -n agentity agentity
kubectl port-forward -n agentity svc/agentity 8080:8080
```

### Database connection errors

```bash
# Test PostgreSQL connectivity
kubectl run -it --rm psql --image=postgres:16-alpine --restart=Never -- \
  psql -h postgres.agentity.svc.cluster.local -U agentity -d agentity -c "SELECT 1"
```

### High memory usage

Check resource limits and actual consumption:
```bash
kubectl top pods -n agentity -l app.kubernetes.io/name=agentity
kubectl describe nodes | grep -A 10 agentity
```

### Helm chart validation

```bash
helm lint ./charts/agentity
helm template agentity ./charts/agentity --values values-production.yaml
```

## Upgrading

### Minor version upgrade (same chart major version)

```bash
helm upgrade agentity ./charts/agentity \
  -f values-production.yaml \
  -f secrets.yaml \
  -n agentity
```

### Major version upgrade (breaking changes)

1. Read CHANGELOG.md for breaking changes
2. Test in staging environment
3. Back up database
4. Perform rolling upgrade with health checks enabled

```bash
helm upgrade agentity ./charts/agentity \
  -f values-production.yaml \
  -f secrets.yaml \
  -n agentity \
  --wait \
  --timeout 5m
```

## Rollback

```bash
helm rollback agentity -n agentity
```

Or to a specific revision:
```bash
helm history agentity -n agentity
helm rollback agentity <REVISION> -n agentity
```

## Security Best Practices

1. **Never commit secrets** - Use external secret management
2. **Enable Pod Security Standards** - Use restricted PSS
3. **Use Network Policies** - Restrict egress/ingress
4. **Enable RBAC** - Limit API access
5. **Scan container images** - Use image scanning tools
6. **Enable audit logging** - Monitor API calls
7. **Rotate secrets regularly** - Update keys periodically
8. **Use TLS everywhere** - Enable HTTPS and mTLS
9. **Monitor pod logs** - Aggregate and alert on errors
10. **Set resource limits** - Prevent resource exhaustion

## Support

For issues or questions:
- Check the [Agentity GitHub](https://github.com/aswiniverse/agentity)
- Review logs: `kubectl logs -n agentity -l app.kubernetes.io/name=agentity`
- Run diagnostics: `helm get values agentity -n agentity`
