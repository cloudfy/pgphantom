# pgphantom

A PostgreSQL 16+ **edge reverse proxy** written in Rust. pgphantom sits in front of your PostgreSQL cluster, provides TLS termination, authenticates clients, and routes connections to the right backend — all without requiring a local Rust installation.

```
client ──TLS──► pgphantom ──► pg-primary
                         └──► pg-replica
                         └──► ...
```

---
## Features

- **TLS termination** — accept TLS from clients; connect to backends over plain TCP or TLS
- **Auth relay mode** — forward SCRAM-SHA-256, MD5, or cleartext challenges transparently; passwords never touch pgphantom
- **JWT / OAUTHBEARER mode** — validate Bearer JWTs from any OIDC provider against a JWKS endpoint; connect to backends with a service account or RFC 8693 STS-minted token
- **Flexible routing** — exact mappings and regex rules with capture-group substitution (`$1`, `$2`) in database name and backend host
- **Multi-node config via etcd** — nodes publish and watch config; routing rules propagate across the cluster
- **Pure-Rust TLS** — powered by `rustls`; no OpenSSL dependency in the binary or the Docker image
- **Built for PostgreSQL 16+** — implements the PostgreSQL wire protocol natively, including SASL OAUTHBEARER (RFC 7628)

---

## Quick start

**No local Rust required.** Everything builds inside Docker.

```bash
# Clone and configure
git clone https://github.com/cloudfy/pgphantom
cd pgphantom
cp config.example.yaml config.yaml

# Start pgphantom + two PostgreSQL 16 backends + etcd
docker compose up --build
```

Connect with any PostgreSQL client:

```bash
psql -h localhost -p 5432 -U myuser -d appdb
```

---

## Building

```bash
# Image only
docker build -t pgphantom .

# Run a single container
docker run --rm \
  -p 5432:5432 \
  -v $(pwd)/config.yaml:/etc/pgphantom/config.yaml:ro \
  pgphantom
```

The multi-stage Dockerfile uses `rust:1.88-slim-bookworm` as the builder and produces a `debian:bookworm-slim` runtime image (~50 MB).

---

## Configuration

pgphantom is configured via a single YAML or JSON file (defaults to `/etc/pgphantom/config.yaml`). All string values support `${ENV_VAR}` substitution.

```yaml
listen:
  host: "0.0.0.0"
  port: 5432
  tls:
    enabled: true
    cert_file: "/certs/server.crt"
    key_file:  "/certs/server.key"

auth:
  mode: "relay"           # relay | jwt
  methods:
    scram_sha_256: true
    md5: true
    cleartext: false
    oauthbearer: false    # set true when mode = jwt

routing:
  mappings:
    - database: "appdb"
      backend: "primary"
    - database: "analyticsdb"
      backend: "replica"
  backends:
    primary:
      host: "pg-primary"
      port: 5432
    replica:
      host: "pg-replica"
      port: 5432

logging:
  level: "info"
  format: "text"   # text | json
```

See **[docs/readme.md](docs/readme.md)** for the full configuration reference including JWT, STS, regex routing rules, TLS options, and cluster/etcd settings.

---

## Authentication modes

### Relay mode

pgphantom forwards the backend's SCRAM-SHA-256, MD5, or cleartext challenge verbatim. Credentials are never inspected or stored.

### JWT mode

Clients authenticate with a JWT Bearer token using PostgreSQL 16's native SASL OAUTHBEARER mechanism. pgphantom validates the token against your IdP's JWKS endpoint, then connects to the backend with either a static service account or an STS-minted token.

```yaml
auth:
  mode: "jwt"
  methods:
    oauthbearer: true
  jwt:
    jwks_uri: "https://auth.example.com/.well-known/jwks.json"
    issuer:   "https://auth.example.com"
    audience: "pgphantom"
    username_claim: "sub"
```

---

## Routing

Rules are evaluated in order: **exact mappings → regex rules → default backend → reject**.

```yaml
routing:
  # Exact match
  mappings:
    - database: "appdb"
      backend: "primary"

  # Regex with capture groups
  regex_rules:
    - match_database: "^prod_(.*)"
      rewrite_database: "$1"
      backend_host: "$1-pg.internal.example.com"
      backend_port: 5432

  default_backend: "primary"
```

---

## CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config <PATH>` | `/etc/pgphantom/config.yaml` | Config file path (YAML or JSON) |
| `--bind <HOST:PORT>` | *(from config)* | Override listen address |
| `--log-level <LEVEL>` | *(from config)* | `trace` / `debug` / `info` / `warn` / `error` |
| `--log-format <FORMAT>` | *(from config)* | `text` / `json` |

`RUST_LOG` is also honoured and takes precedence over `--log-level`.

---

## Project layout

```
Cargo.toml
Dockerfile
docker-compose.yml
config.example.yaml
config.example.json
docs/
  readme.md          ← full configuration reference
src/
  main.rs            ← CLI + startup
  server.rs          ← TCP accept loop, TLS acceptor
  proxy.rs           ← per-connection handler, TLS negotiation
  backend.rs         ← backend connect, SCRAM-SHA-256 + MD5 client auth
  routing/           ← route resolver (mappings + regex)
  auth/
    jwt.rs           ← JWKS cache + JWT validation
    relay.rs         ← auth challenge relay
    oauthbearer.rs   ← RFC 7628 SASL OAUTHBEARER parser
    sts.rs           ← RFC 8693 token exchange
  protocol/          ← PostgreSQL wire protocol framing
  config/            ← config deserialization + env-var substitution
  cluster/           ← etcd watcher + config distribution
  errors.rs
```

---

## License

[MIT](LICENSE)
