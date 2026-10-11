# SentinelWP — Ubuntu Server LTS Deployment Guide
## Enterprise Docker Compose Production Topology

This guide details the step-by-step procedure to deploy SentinelWP on Ubuntu Server 22.04 LTS or 24.04 LTS using Docker Compose.

---

## 1. System Requirements

### Minimum Hardware (Small / Controlled Pilot)
- **CPU:** 4 vCPUs (x86_64 or ARM64)
- **RAM:** 8 GiB
- **Disk:** 50 GiB SSD (ext4/xfs)
- **Network:** 1 Gbps, static public or internal IP

### Recommended Production Specifications
- **CPU:** 8 vCPUs
- **RAM:** 16 GiB
- **Disk:** 100+ GiB NVMe SSD
- **Swap:** 4 GiB enabled

### Operating System & Host Packages
- **OS:** Ubuntu Server 22.04 LTS / 24.04 LTS
- **Docker Engine:** 24.0.0 or higher
- **Docker Compose:** v2.20.0 or higher
- **Host Firewall (UFW):** Ingress restricted to ports `80/tcp` (HTTP) and `443/tcp` (HTTPS). Internal datastore ports (`5432`, `6379`) are isolated to Docker bridge networks and must NEVER be opened on the host.

---

## 2. Host Provisioning & Docker Installation

```bash
# Update Ubuntu package indices
sudo apt-get update && sudo apt-get upgrade -y

# Install prerequisites
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# Add Docker official GPG key and APT repository
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine and Compose plugin
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Verify installation
docker --version
docker compose version
```

---

## 3. Directory Layout & Repository Setup

Create the application directory under `/opt/sentinelwp`:

```bash
sudo mkdir -p /opt/sentinelwp
sudo chown -R $USER:$USER /opt/sentinelwp
cd /opt/sentinelwp

# Clone or unpack release distribution
git clone -b feat/sentinelwp-sprint11-enterprise-packaging https://github.com/example/sentinelwp.git .
```

---

## 4. Production Configuration & Secrets Setup

Create the production environment file from the provided example template:

```bash
cp .env.production.example .env.production
chmod 0600 .env.production
```

Generate cryptographically strong secrets for `WSA_SECRET_KEY`, `POSTGRES_PASSWORD`, and `REDIS_PASSWORD`:

```bash
# Generate high-entropy keys
SECRET_KEY=$(openssl rand -hex 32)
PG_PASS=$(openssl rand -hex 24)
REDIS_PASS=$(openssl rand -hex 24)

# Edit .env.production and set these values
nano .env.production
```

Validate the environment file using the preflight validator:

```bash
bash scripts/validate_prod_env.sh .env.production
```

The script will verify entropy, file permissions (0600), URL consistency, and fail closed if placeholders are detected.

---

## 5. TLS Certificate Provisioning

Place your organization's valid TLS certificates in `nginx/certs/`:
- `nginx/certs/sentinelwp.crt` (Certificate + Intermediate CA bundle)
- `nginx/certs/sentinelwp.key` (Private key, permissions `0600`)

For testing in staging or pilot environments, generate a self-signed certificate:

```bash
bash scripts/generate_self_signed_cert.sh
```

---

## 6. Container Stack Build & Deployment

### Step A: Build Multi-Stage Production Image
```bash
docker compose -f docker-compose.prod.yml build
```

### Step B: Start Datastores (PostgreSQL & Redis)
```bash
docker compose -f docker-compose.prod.yml up -d db redis
```

Wait until datastores report healthy:
```bash
docker compose -f docker-compose.prod.yml ps db redis
```

### Step C: Execute Schema Migrations (Init Container)
The ephemeral `migrate` service executes versioned Alembic migrations (revisions `001` through `009`) under distributed advisory locking (`85504753`):

```bash
docker compose -f docker-compose.prod.yml run --rm migrate
```

Verify that the migration container completed cleanly with exit code 0.

### Step D: Launch Full Application Stack
```bash
docker compose -f docker-compose.prod.yml up -d
```

---

## 7. Operational Verification

Run the deployment verification script against the local stack:

```bash
bash scripts/verify_deployment.sh --host 127.0.0.1
```

Or perform manual verification:
1. **HTTP Redirect:** `curl -I http://127.0.0.1/` (Must return `HTTP/1.1 301 Moved Permanently` to `https://...`).
2. **Health Probe:** `curl -k -s https://127.0.0.1/health` (Must return `status: ok`).
3. **Readiness Probe:** `curl -k -s https://127.0.0.1/ready` (Must return `database: connected`, `redis: connected`, `status: ready`).
4. **Network Exposure:** `netstat -tlpn` (Must only show ports 80 and 443 bound; ports 5432 and 6379 must NOT be listening on host interfaces).

---

## 8. Service Lifecycle Management

```bash
# View service status
docker compose -f docker-compose.prod.yml ps

# View unified logs
docker compose -f docker-compose.prod.yml logs -f --tail=100

# Graceful restart of web service
docker compose -f docker-compose.prod.yml restart web

# Graceful restart of scan workers
docker compose -f docker-compose.prod.yml restart worker-scan

# Graceful full shutdown
docker compose -f docker-compose.prod.yml down
```
