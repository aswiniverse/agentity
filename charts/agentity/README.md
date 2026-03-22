# Agentity Helm Chart

A production-grade Kubernetes Helm chart for deploying [Agentity](https://github.com/aswiniverse/agentity) — Agent IAM with cryptographic capability tokens for AI agent authorization.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.0+

## Installation

### Add the Helm repository (when published)
```bash
helm repo add agentity https://charts.agentity.io
helm repo update
```

### Install the chart from local directory
```bash
helm install agentity ./charts/agentity
```

### Install with custom values
```bash
helm install agentity ./charts/agentity \
  --set adminApiKey="your-api-key" \
  --set cryptoRootKey="your-32-byte-hex-key"
```

### Install into a specific namespace
```bash
helm install agentity ./charts/agentity \
  --namespace agentity \
  --create-namespace
```

## Quick Start

### 1. Create a values file
```bash
cat > my-values.yaml <<EOF
replicaCount: 2

config:
  logLevel: info
  store:
    type: memory  # or "postgres"

adminApiKey: "your-secret-admin-key"
cryptoRootKey: "0123456789abcdef0123456789abcdef"  # 32-byte hex key
EOF
```

### 2. Deploy
```bash
helm install agentity ./charts/agentity -f my-values.yaml
```

### 3. Access the service
```bash
kubectl port-forward svc/agentity 8080:8080
curl http://localhost:8080/health
```

## Configuration

All configuration is driven through `values.yaml`. Key settings:

### Container Image
```yaml
image:
  repository: ghcr.io/aswiniverse/agentity
  pullPolicy: IfNotPresent
  tag: ""  # defaults to Chart.appVersion
```

### Application Configuration
```yaml
config:
  logLevel: info           # debug, info, warn, error
  logFormat: json          # json or console
  store:
    type: memory           # memory or postgres
  port: 8080
  readTimeout: 30s
  writeTimeout: 30s
  shutdownTimeout: 15s
```

### Secrets (Required for Production)
```yaml
# Admin API key for authentication
adminApiKey: "your-secret-key"

# 32-byte hex key for cryptographic operations
cryptoRootKey: "0123456789abcdef0123456789abcdef"
```

### Database Configuration
```yaml
postgresql:
  enabled: false
  host: postgres.default.svc.cluster.local
  port: 5432
  database: agentity
  user: agentity
  password: ""  # Change in production!
  maxConns: 20
```

### Redis Cache
```yaml
redis:
  enabled: false
  address: redis:6379
  password: ""
  db: 0
```

### OpenID Connect (OIDC)
```yaml
oidc:
  issuerUrl: "https://your-oidc-provider.example.com"
```

### OpenTelemetry
```yaml
otel:
  enabled: false
  serviceName: agentity
  exporterType: stdout  # or otlp
  endpoint: ""
```

### Kubernetes Service
```yaml
service:
  type: ClusterIP
  port: 8080
```

### Ingress
```yaml
ingress:
  enabled: false
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

### Pod Security
```yaml
podSecurityContext: {}
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
```

### Resources
```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

### Horizontal Pod Autoscaling
```yaml
autoscaling:
  enabled: false
  minReplicas: 1
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80
```

## Common Use Cases

### Deploy with PostgreSQL backend
```yaml
config:
  store:
    type: postgres

postgresql:
  enabled: true
  host: postgres.default.svc.cluster.local
  password: "secure-postgres-password"
```

### Deploy with Redis caching
```yaml
redis:
  enabled: true
  address: redis.default.svc.cluster.local:6379
  password: "secure-redis-password"
```

### Enable Ingress with TLS
```yaml
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: api.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: api-tls
      hosts:
        - api.example.com
```

### Enable autoscaling
```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 75
```

### Enable OIDC authentication
```yaml
oidc:
  issuerUrl: "https://auth.example.com"
```

## Upgrading

```bash
helm upgrade agentity ./charts/agentity -f my-values.yaml
```

## Uninstalling

```bash
helm uninstall agentity
```

## Environment Variables

The chart maps the following environment variables to the Agentity application:

| Environment Variable | Source | Notes |
|----------------------|--------|-------|
| `AGENTITY_AUTH_ADMIN_API_KEY` | Secret | Admin API key for authentication |
| `AGENTITY_CRYPTO_ROOT_KEY` | Secret | 32-byte hex key for crypto operations |
| `AGENTITY_STORE_DSN` | Secret | PostgreSQL connection string (if enabled) |
| `AGENTITY_REDIS_PASSWORD` | Secret | Redis password (if enabled) |
| `AGENTITY_SERVER_PORT` | ConfigMap | Server port (default: 8080) |
| `AGENTITY_LOG_LEVEL` | ConfigMap | Log level: debug, info, warn, error |
| `AGENTITY_LOG_FORMAT` | ConfigMap | Log format: json or console |
| `AGENTITY_STORE_TYPE` | ConfigMap | Store type: memory or postgres |
| `AGENTITY_REDIS_ENABLED` | ConfigMap | Enable Redis: true or false |
| `AGENTITY_OTEL_ENABLED` | ConfigMap | Enable OpenTelemetry: true or false |

## Troubleshooting

### Check deployment status
```bash
kubectl get deployment agentity
kubectl describe deployment agentity
```

### View logs
```bash
kubectl logs -l app.kubernetes.io/name=agentity
kubectl logs -f deployment/agentity
```

### Port-forward to service
```bash
kubectl port-forward svc/agentity 8080:8080
curl http://localhost:8080/health
```

### Check secrets
```bash
kubectl get secret agentity
kubectl describe secret agentity
```

### Get admin API key
```bash
kubectl get secret agentity -o jsonpath="{.data.AGENTITY_AUTH_ADMIN_API_KEY}" | base64 --decode
```

## Security Considerations

1. **Never commit secrets to version control** - Use sealed-secrets, external-secrets, or SOPS
2. **Use read-only root filesystem** - Enabled by default (requires emptyDir for /tmp)
3. **Run as non-root** - Configured to run as UID 1000
4. **Restrict network access** - Use NetworkPolicies in production
5. **Use TLS for Ingress** - Enable TLS termination and use cert-manager
6. **Rotate API keys regularly** - Update `adminApiKey` and `cryptoRootKey` periodically
7. **Use external PostgreSQL** - Don't run database in-cluster without persistent storage

## Advanced Configuration

### Custom image
```yaml
image:
  repository: my-registry.example.com/agentity
  tag: custom-v1.0.0
```

### Node affinity
```yaml
affinity:
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      nodeSelectorTerms:
        - matchExpressions:
            - key: workload
              operator: In
              values:
                - agentity
```

### Pod disruption budget
```bash
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: agentity
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: agentity
```

### Network policy
```bash
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agentity
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: agentity
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
```

## License

See the main [Agentity repository](https://github.com/aswiniverse/agentity) for license information.

## Support

For issues, questions, or contributions, please visit the [Agentity GitHub repository](https://github.com/aswiniverse/agentity).
