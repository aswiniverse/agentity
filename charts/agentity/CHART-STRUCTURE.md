# Agentity Helm Chart Structure

Complete documentation of the production-grade Kubernetes Helm chart for Agentity.

## Directory Layout

```
charts/agentity/
├── Chart.yaml                 # Chart metadata and version info
├── README.md                  # Comprehensive usage guide
├── DEPLOYMENT.md              # Production deployment guide
├── CHART-STRUCTURE.md         # This file - chart architecture
├── NOTES.txt                  # Post-installation notes template
├── values.yaml                # Default configuration values
├── values-development.yaml    # Development environment values
├── values-production.yaml     # Production environment values
└── templates/
    ├── _helpers.tpl           # Helm template helpers and macros
    ├── configmap.yaml         # ConfigMap with non-secret env vars
    ├── secret.yaml            # Secret with sensitive values
    ├── deployment.yaml        # Deployment specification
    ├── service.yaml           # ClusterIP Service
    ├── serviceaccount.yaml    # ServiceAccount
    ├── ingress.yaml           # Ingress (conditional)
    └── hpa.yaml               # HorizontalPodAutoscaler (conditional)
```

## File Descriptions

### Root Configuration Files

#### `Chart.yaml`
Helm chart metadata following the v2 API specification.

**Key attributes:**
- `apiVersion: v2` - Helm 3.x format
- `name: agentity` - Chart name
- `version: 0.1.0` - Chart version (increment on changes)
- `appVersion: 0.1.0` - Application version
- Includes keywords, home URL, source links, and maintainer info

#### `values.yaml`
Default configuration values for the chart. All values are overridable at deployment time.

**Structure:**
- `replicaCount` - Number of pod replicas (default: 1)
- `image` - Container image configuration
- `imagePullSecrets` - Private registry credentials (optional)
- `serviceAccount` - Kubernetes ServiceAccount configuration
- `podAnnotations` - Pod metadata annotations
- `podSecurityContext` - Pod-level security context
- `securityContext` - Container-level security context
- `service` - Kubernetes Service configuration
- `ingress` - Ingress configuration (disabled by default)
- `resources` - CPU and memory limits/requests
- `autoscaling` - HPA configuration (disabled by default)
- `nodeSelector` - Node selection constraints
- `tolerations` - Kubernetes tolerations
- `affinity` - Pod affinity rules
- `config` - Application-specific settings (logLevel, store type, ports, timeouts)
- `adminApiKey` - Admin authentication key (SECRET - set at deployment)
- `cryptoRootKey` - Cryptographic root key (SECRET - set at deployment)
- `oidc` - OpenID Connect configuration
- `redis` - Redis cache configuration
- `otel` - OpenTelemetry settings
- `postgresql` - PostgreSQL database configuration

#### `values-development.yaml`
Pre-configured values for development deployments.

**Features:**
- Single replica for resource efficiency
- Memory-backed data store (no persistence)
- Console logging for readability
- Disabled autoscaling
- No ingress (use port-forward)
- Lower resource limits
- Dev-friendly logging levels (debug)

#### `values-production.yaml`
Pre-configured values for production deployments.

**Features:**
- 3+ replicas for high availability
- PostgreSQL backend for persistence
- Redis caching enabled
- JSON structured logging
- Autoscaling enabled (3-10 replicas)
- Ingress with TLS/HTTPS
- Higher resource limits (1000m CPU, 512Mi memory)
- Pod anti-affinity for distribution across nodes
- OTEL observability enabled
- Security annotations and configurations

### Documentation Files

#### `README.md`
Comprehensive user guide covering:
- Installation methods
- Quick start examples
- Configuration options for all features
- Common use cases
- Troubleshooting steps
- Environment variable reference
- Security considerations
- Advanced configurations

#### `DEPLOYMENT.md`
Production deployment playbook including:
- Pre-deployment checklist
- Secret management strategies (sealed-secrets, external-secrets, helm values)
- Multiple deployment scenarios (dev, production, multi-region)
- Post-deployment verification steps
- Monitoring and observability setup
- Troubleshooting guide
- Upgrade and rollback procedures
- Security best practices

#### `NOTES.txt`
Post-installation message shown to users after deployment.

**Content:**
- Access instructions based on service type (Ingress/LoadBalancer/ClusterIP)
- Commands to retrieve admin API key
- Deployment status verification

### Template Files

Templates use Go text templating with Helm extensions. All templates include:
- Standard Kubernetes API versions
- Label consistency using helper functions
- Conditional sections for optional features
- Proper indentation with `nindent`
- Whitespace control with `{{-` and `-}}`

#### `_helpers.tpl`
Reusable template helpers:

**Defines:**
- `agentity.name` - Chart name with override support
- `agentity.fullname` - Fully qualified name (release-name-chart or fullnameOverride)
- `agentity.chart` - Chart name and version string
- `agentity.labels` - Standard Kubernetes labels (helm.sh/chart, app.kubernetes.io/*, managed-by)
- `agentity.selectorLabels` - Labels for pod selectors (name, instance)
- `agentity.serviceAccountName` - ServiceAccount name resolution

**Usage pattern:**
```yaml
labels:
  {{- include "agentity.labels" . | nindent 4 }}
selector:
  matchLabels:
    {{- include "agentity.selectorLabels" . | nindent 6 }}
```

#### `configmap.yaml`
ConfigMap containing non-sensitive environment variables:

**Variables:**
- `AGENTITY_SERVER_PORT` - Server port (default: 8080)
- `AGENTITY_LOG_LEVEL` - Logging level
- `AGENTITY_LOG_FORMAT` - Log format (json/console)
- `AGENTITY_STORE_TYPE` - Store backend (memory/postgres)
- `AGENTITY_SERVER_READ_TIMEOUT` - HTTP read timeout
- `AGENTITY_SERVER_WRITE_TIMEOUT` - HTTP write timeout
- `AGENTITY_SERVER_SHUTDOWN_TIMEOUT` - Graceful shutdown timeout
- `AGENTITY_OIDC_ISSUER_URL` - OIDC provider URL (if configured)
- `AGENTITY_REDIS_*` - Redis configuration (if enabled)
- `AGENTITY_OTEL_*` - OpenTelemetry settings (if enabled)

**Features:**
- Conditional inclusion based on values
- Proper quoting for string values
- Boolean values as "true"/"false" strings

#### `secret.yaml`
Secret containing sensitive environment variables:

**Variables:**
- `AGENTITY_AUTH_ADMIN_API_KEY` - Admin API key (base64 encoded)
- `AGENTITY_CRYPTO_ROOT_KEY` - Crypto root key (base64 encoded)
- `AGENTITY_REDIS_PASSWORD` - Redis password (if enabled, base64 encoded)
- `AGENTITY_STORE_DSN` - PostgreSQL connection string (if enabled, base64 encoded)

**Features:**
- Base64 encoding via `b64enc` filter
- Default values for missing secrets
- Conditional inclusion based on store type

#### `deployment.yaml`
Kubernetes Deployment specification:

**Key components:**
- Metadata with standard labels
- Replica count (conditional on autoscaling)
- Pod selector labels
- Pod template with annotations
- Checksum annotations for config/secret changes (triggers rolling restart on changes)
- Image pull secrets support
- ServiceAccount assignment
- Security context (pod and container level)
- Container specification:
  - Image with tag defaulting to Chart.appVersion
  - HTTP port mapping (8080)
  - envFrom for ConfigMap and Secret injection
  - Liveness probe: `/health` endpoint (10s initial delay, 30s period)
  - Readiness probe: `/health` endpoint (5s initial delay, 10s period)
  - Resource limits and requests
- EmptyDir volume for /tmp (when read-only filesystem enabled)
- Node selector, affinity, and tolerations support

#### `service.yaml`
Kubernetes Service specification:

**Configuration:**
- Service type from values (default: ClusterIP)
- Port mapping (external → container port 8080)
- Named port "http" for consistency
- Pod selector using helper labels

#### `serviceaccount.yaml`
Kubernetes ServiceAccount:

**Features:**
- Conditional creation (enabled by default)
- Annotations support (for IRSA, Workload Identity, etc.)
- Custom name override

#### `ingress.yaml`
Kubernetes Ingress resource:

**Features:**
- Conditional (disabled by default)
- Ingress class support (nginx, traefik, etc.)
- Custom annotations (cert-manager, rate limiting, etc.)
- TLS configuration with secret references
- Multiple host/path combinations
- Backend service routing

#### `hpa.yaml`
HorizontalPodAutoscaler for load-based scaling:

**Configuration:**
- Conditional (disabled by default)
- Min/max replica range
- CPU utilization target (default: 80%)
- API version v2 (stable)
- Target reference to Deployment

## Configuration Flow

```
values.yaml (defaults)
    ↓
values-development.yaml or values-production.yaml (overrides)
    ↓
helm install --set key=value (CLI overrides)
    ↓
ConfigMap + Secret
    ↓
Deployment (reads from ConfigMap + Secret)
    ↓
Container environment variables
    ↓
Agentity application
```

## Template Variables Reference

Common template variables available in all templates:

| Variable | Description |
|----------|-------------|
| `.Chart` | Chart metadata (name, version, appVersion) |
| `.Values` | User-provided values |
| `.Release` | Release metadata (name, namespace, service) |
| `.Template` | Current template information |

## Helm Hooks and Functions

**Hooks used:**
- None (standard deployment)

**Key functions:**
- `include` - Include template helpers
- `nindent` - Indent YAML with newline prefix
- `quote` - Quote string values
- `b64enc` - Base64 encode
- `printf` - String formatting
- `default` - Provide default values
- `toYaml` - Convert Go values to YAML

## Environment Variable Mapping

The chart maps all Agentity configuration options to environment variables following the `AGENTITY_*` prefix pattern:

**Naming convention:**
- YAML path: `config.store.type`
- Env var: `AGENTITY_STORE_TYPE` (convert dots to underscores, uppercase)

**Sources:**
- ConfigMap: Non-sensitive values
- Secret: Sensitive values (API keys, passwords)

## Security Model

### Pod Security
- Runs as non-root user (UID 1000)
- Read-only root filesystem (with /tmp emptyDir)
- No privileged escalation
- Dropped ALL capabilities

### Resource Isolation
- CPU limits: 500m (dev) to 1000m (prod)
- Memory limits: 256Mi (dev) to 512Mi (prod)
- Request-based autoscaling for overcommit prevention

### Network Security
- ClusterIP service (no direct external access)
- Ingress for external traffic with optional TLS
- Pod anti-affinity for availability zone distribution

### Secret Management
- Secrets stored as base64 (use sealed-secrets or external-secrets in production)
- API keys and crypto keys stored in Secret, not ConfigMap
- Database passwords encrypted in transit

## Scaling and Performance

### Horizontal Scaling
- HPA targets 80% CPU utilization (configurable)
- Min/max replica configuration
- Pod anti-affinity spreads replicas across nodes

### Resource Efficiency
- Memory-efficient container (Alpine-based image)
- Graceful shutdown with timeout
- Connection pooling for databases

## Health and Observability

### Health Checks
- Liveness probe: Detects hung processes
- Readiness probe: Prevents traffic to initializing pods
- HTTP `/health` endpoint

### Metrics
- Prometheus-compatible metrics at `/metrics`
- Pod annotations for scrape configuration
- OpenTelemetry optional for distributed tracing

### Logging
- JSON structured logging (production)
- Console logging (development)
- Log level configuration

## Upgrade Path

Chart versioning follows semantic versioning:
- **Patch (0.1.1)**: No breaking changes, safe auto-upgrade
- **Minor (0.2.0)**: New features, backward compatible
- **Major (1.0.0)**: Breaking changes, manual review required

## Compliance and Standards

- Follows Kubernetes resource conventions
- Helm best practices and patterns
- YAML validation
- Security context hardening
- RBAC-friendly design

## File Integrity

All files use proper:
- YAML indentation (2 spaces)
- Template syntax validation
- No circular references
- Consistent naming conventions
- Documentation and comments

## Testing the Chart

```bash
# Validate YAML syntax
helm lint ./charts/agentity

# Render templates
helm template agentity ./charts/agentity

# Dry-run deployment
helm install agentity ./charts/agentity --dry-run --debug

# Test with different values
helm template agentity ./charts/agentity -f values-production.yaml

# Validate against Kubernetes schema
helm template agentity ./charts/agentity | kubeval
```
