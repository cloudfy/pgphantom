# pgphantom

A PostgreSQL 16+ edge reverse proxy written in Rust. pgphantom terminates inbound PostgreSQL connections and forwards them to one or more internal PostgreSQL backends. It supports TLS termination, multiple authentication modes (relay and JWT/OAUTHBEARER), regex-based routing, and multi-node config distribution via etcd.

No local Rust installation is required — the Docker image is a fully self-contained build.

---

## Table of Contents

- [pgphantom](#pgphantom)
  - [Table of Contents](#table-of-contents)
  - [Quick start](#quick-start)
  - [Building](#building)
  - [CLI flags](#cli-flags)
  - [Configuration file](#configuration-file)
    - [`listen`](#listen)
    - [`auth`](#auth)
      - [`auth.methods`](#authmethods)
      - [`auth.mode` — relay](#authmode--relay)
      - [`auth.mode` — jwt](#authmode--jwt)
      - [`auth.jwt`](#authjwt)
      - [`auth.sts`](#authsts)
    - [`routing`](#routing)
      - [`routing.mappings`](#routingmappings)
      - [`routing.regex_rules`](#routingregex_rules)
      - [`routing.backends`](#routingbackends)
      - [`routing.default_backend`](#routingdefault_backend)
    - [`cluster`](#cluster)
      - [`cluster.etcd`](#clusteretcd)
    - [`logging`](#logging)
  - [Environment variable substitution](#environment-variable-substitution)
  - [TLS certificates](#tls-certificates)
  - [Docker \& docker-compose](#docker--docker-compose)
    - [Environment variables recognised by the container](#environment-variables-recognised-by-the-container)
    - [Volume mounts](#volume-mounts)
    - [Exposed port](#exposed-port)
  - [Authentication modes in depth](#authentication-modes-in-depth)
    - [Relay mode](#relay-mode)
    - [JWT mode](#jwt-mode)
  - [Routing resolution order](#routing-resolution-order)
  - [Cluster / etcd](#cluster--etcd)

---

## Quick start

```bash
# 1. Copy and edit the example config
cp config.example.yaml config.yaml
$EDITOR config.yaml

# 2. Build and start with Docker Compose (PostgreSQL backends + etcd included)
docker compose up --build
```

Clients connect to `localhost:5432` exactly as they would to a native PostgreSQL server.

---

## Building

Rust is **not** required on the host. The multi-stage Dockerfile handles the full build inside a `rust:1.85-slim-bookworm` container and produces a minimal `debian:bookworm-slim` runtime image (~50 MB).

```bash
# Build the Docker image
docker build -t pgphantom .

# Run a single container
docker run --rm \
  -p 5432:5432 \
  -v $(pwd)/config.yaml:/etc/pgphantom/config.yaml:ro \
  pgphantom
```

---

## CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config <PATH>` | `/etc/pgphantom/config.yaml` | Path to the YAML or JSON configuration file. |
| `--bind <HOST:PORT>` | *(from config)* | Override `listen.host` and `listen.port`. |
| `--log-level <LEVEL>` | *(from config)* | Override `logging.level` (`trace`/`debug`/`info`/`warn`/`error`). |
| `--log-format <FORMAT>` | *(from config)* | Override `logging.format` (`text`/`json`). |

The `RUST_LOG` environment variable is also honoured and takes precedence over `--log-level`.

---

## Configuration file

The configuration file is YAML (`.yaml`/`.yml`) or JSON (`.json`), detected by file extension. All string values support `${ENV_VAR}` substitution (see [Environment variable substitution](#environment-variable-substitution)).

---

### `listen`

Controls the TCP/TLS listener.

```yaml
listen:
  host: "0.0.0.0"   # IP address to bind (default: 0.0.0.0)
  port: 5432         # TCP port (default: 5432)
  tls:
    enabled: false
    cert_file: "/certs/server.crt"   # PEM certificate chain
    key_file:  "/certs/server.key"   # PEM private key
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `host` | string | `0.0.0.0` | Bind address. |
| `port` | integer | `5432` | Bind port. |
| `tls.enabled` | bool | `false` | Enable TLS for inbound connections. |
| `tls.cert_file` | string | — | Path to the PEM certificate (required when `tls.enabled = true`). |
| `tls.key_file` | string | — | Path to the PEM private key (required when `tls.enabled = true`). |

When `tls.enabled = false`, clients still receive an `N` response to SSLRequest and connect over plain TCP. pgphantom never rejects a client that sends SSLRequest when TLS is disabled.

---

### `auth`

Top-level authentication configuration.

```yaml
auth:
  methods:
    scram_sha_256: true
    md5: true
    cleartext: false
    oauthbearer: false
  mode: "relay"
  jwt: ...        # required when mode = "jwt"
  sts: ...        # optional, used with jwt mode
```

---

#### `auth.methods`

Enables or disables individual SASL/password mechanisms globally. These act as an allow-list; any mechanism not in this list is filtered out before being offered to clients or accepted from backends.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `scram_sha_256` | bool | `true` | Allow SCRAM-SHA-256 (recommended). |
| `md5` | bool | `true` | Allow MD5 password (legacy; disable in new deployments). |
| `cleartext` | bool | `false` | Allow cleartext password. **Only enable over TLS.** |
| `oauthbearer` | bool | `false` | Allow SASL OAUTHBEARER. **Required when `mode = "jwt"`.** |

---

#### `auth.mode` — relay

```yaml
auth:
  mode: "relay"
```

pgphantom forwards the backend's authentication challenge verbatim to the client. Passwords are never seen or stored by pgphantom. Supported mechanisms: SCRAM-SHA-256, MD5, cleartext.

When pgphantom has TLS terminated the connection, it automatically strips `SCRAM-SHA-256-PLUS` from the offered mechanism list (channel binding cannot be re-established to the backend).

---

#### `auth.mode` — jwt

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

pgphantom authenticates the client using SASL OAUTHBEARER (RFC 7628 / PostgreSQL 16+). The client provides a JWT Bearer token; pgphantom validates it against the JWKS endpoint, then connects to the backend using either a static service account or an STS-minted token.

---

#### `auth.jwt`

Required when `auth.mode = "jwt"`.

```yaml
auth:
  jwt:
    jwks_uri: "https://auth.example.com/.well-known/jwks.json"
    issuer: "https://auth.example.com"
    audience: "pgphantom"
    refresh_interval_secs: 300
    username_claim: "sub"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `jwks_uri` | string | — | HTTPS URL of the JWKS endpoint used to fetch public keys for JWT signature verification. |
| `issuer` | string | — | Expected `iss` claim. Tokens with a different issuer are rejected. |
| `audience` | string | — | Expected `aud` claim. |
| `refresh_interval_secs` | integer | `300` | How often (in seconds) the JWKS cache is refreshed. |
| `username_claim` | string | `sub` | JWT claim whose value is used as the PostgreSQL username when `service_user` is not set on the backend. |

Supported signing algorithms: RS256, ES256 (via the JWK `alg` field).

---

#### `auth.sts`

Optional. When set and no `service_user` is configured on the matched backend, pgphantom exchanges the client's JWT for a backend-specific token via RFC 8693 Token Exchange.

```yaml
auth:
  sts:
    token_endpoint: "https://sts.example.com/token"
    client_id: "pgphantom"
    client_secret_env: "STS_CLIENT_SECRET"
    audience: "internal-postgres"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `token_endpoint` | string | — | RFC 8693 token exchange endpoint URL. |
| `client_id` | string | — | OAuth 2.0 client ID for pgphantom. |
| `client_secret_env` | string | — | Environment variable name containing the client secret. |
| `audience` | string | — | `audience` parameter sent in the token exchange request. |

---

### `routing`

Determines which backend receives each connection based on the `database` and `user` parameters from the client's StartupMessage.

---

#### `routing.mappings`

Exact-match rules, evaluated first. Both `database` and `user` are optional; omitting one means "match any".

```yaml
routing:
  mappings:
    - database: "appdb"
      backend: "primary"

    - database: "analyticsdb"
      user: "analyst"
      backend: "replica"

    - database: "appdb"
      rewrite_database: "app_production"
      backend: "primary"
```

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `database` | string | no | Client database name to match (exact). |
| `user` | string | no | Client username to match (exact). |
| `backend` | string | yes | Name of the backend (must exist in `routing.backends`). |
| `rewrite_database` | string | no | Database name sent to the backend instead of the original. |

---

#### `routing.regex_rules`

Regex rules, evaluated after mappings. Supports capture groups (`$1`, `$2`, …) in `rewrite_database` and `backend_host`.

```yaml
routing:
  regex_rules:
    - match_database: "^prod_(.*)"
      rewrite_database: "$1"
      backend_host: "$1-pg.internal.example.com"
      backend_port: 5432
      backend_tls:
        enabled: true
        ca_file: "/certs/internal-ca.crt"
```

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `match_database` | string | no | Go-style regex matched against the database name. |
| `match_user` | string | no | Regex matched against the username. |
| `rewrite_database` | string | no | Database name to send to the backend; supports `$1` capture groups. |
| `backend_host` | string | yes | Hostname of the backend; supports `$1` capture groups. |
| `backend_port` | integer | no | Port (default: `5432`). |
| `backend_tls` | object | no | TLS settings for the backend connection (same schema as `routing.backends[*].tls`). |
| `service_user` | string | no | Static backend username (JWT mode). |
| `service_password_env` | string | no | Env var for backend password (JWT mode). |

---

#### `routing.backends`

Named backend definitions referenced by mappings. Multiple mappings can share the same backend.

```yaml
routing:
  backends:
    primary:
      host: "pg-primary"
      port: 5432
      tls:
        enabled: false

    secure-backend:
      host: "secure-pg.internal"
      port: 5432
      tls:
        enabled: true
        ca_file: "/certs/internal-ca.crt"
      service_user: "pgphantom_svc"
      service_password_env: "BACKEND_PASSWORD"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `host` | string | — | Backend hostname or IP. |
| `port` | integer | `5432` | Backend port. |
| `tls.enabled` | bool | `false` | Connect to the backend over TLS. |
| `tls.ca_file` | string | — | CA certificate to verify the backend's certificate. If omitted, the system trust store is used. |
| `service_user` | string | — | *(JWT mode)* Backend username. If absent, the `username_claim` value from the JWT is used. |
| `service_password_env` | string | — | *(JWT mode)* Name of an environment variable containing the backend password when using `service_user`. If neither this nor `auth.sts` is set, connections in JWT mode will be rejected. |

---

#### `routing.default_backend`

Optional. The named backend used when no mapping or regex rule matches. If unset, pgphantom rejects the connection with PostgreSQL error code `3D000` (database does not exist).

```yaml
routing:
  default_backend: "primary"
```

---

### `cluster`

Multi-node config distribution via etcd. When enabled, each pgphantom node publishes its running config to etcd and watches for updates from peers.

```yaml
cluster:
  enabled: false
  node_id: "node-1"     # optional — defaults to $HOSTNAME
  etcd:
    endpoints:
      - "http://etcd:2379"
    prefix: "/pgphantom/config/"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable cluster mode. |
| `node_id` | string | `$HOSTNAME` | Unique identifier for this node, used as the etcd key suffix. |

---

#### `cluster.etcd`

Required when `cluster.enabled = true`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `endpoints` | list of strings | `["http://localhost:2379"]` | etcd endpoint URLs. |
| `prefix` | string | `/pgphantom/config/` | Key prefix under which node configs are stored and watched. |
| `tls.enabled` | bool | `false` | Connect to etcd over TLS. |
| `tls.ca_file` | string | — | CA certificate for verifying the etcd server certificate. |

---

### `logging`

```yaml
logging:
  level: "info"
  format: "text"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `level` | string | `info` | Minimum log level: `trace`, `debug`, `info`, `warn`, `error`. |
| `format` | string | `text` | Log output format: `text` (human-readable) or `json` (structured, for log aggregation). |

The `RUST_LOG` environment variable overrides `level` and also accepts per-module directives, e.g. `RUST_LOG=pgphantom=debug,hyper=warn`.

---

## Environment variable substitution

Any string value in the config file can reference an environment variable using `${VAR_NAME}` syntax. This is resolved at startup.

```yaml
auth:
  sts:
    client_secret_env: "STS_CLIENT_SECRET"   # the env var NAME

# Or inline substitution in any string value:
routing:
  backends:
    primary:
      host: "${PRIMARY_PG_HOST}"
```

Note: `service_password_env` takes the **name** of the env var as a string (the lookup happens at runtime per-connection), while `${...}` substitution happens once at config load time.

---

## TLS certificates

For local development, generate a self-signed certificate:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout certs/server.key \
  -out certs/server.crt \
  -days 365 \
  -subj "/CN=localhost"
```

Mount the `certs/` directory into the container at `/certs` (this is already configured in `docker-compose.yml`).

---

## Docker & docker-compose

### Environment variables recognised by the container

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | Overrides `logging.level`; accepts `tracing` filter syntax. |
| `HOSTNAME` | Used as the cluster `node_id` when not set in the config. Set automatically by Docker. |
| Any variable referenced by `${VAR}` in the config or by `service_password_env` / `client_secret_env` | Passed through to config substitution or credential lookup. |

### Volume mounts

| Container path | Purpose |
|----------------|---------|
| `/etc/pgphantom/config.yaml` | Main configuration file (replace with your own). |
| `/certs/` | TLS certificates for the listener and/or backend connections. |

### Exposed port

`5432/tcp` — standard PostgreSQL port. Change the host-side mapping in `docker-compose.yml` if `5432` is already in use.

---

## Authentication modes in depth

### Relay mode

```
Client ──SCRAM/MD5──► pgphantom ──SCRAM/MD5──► PostgreSQL backend
```

pgphantom acts as a transparent pass-through for the authentication exchange. The user's credentials are relayed to the backend and never inspected or stored. This is the lowest-friction deployment mode — no JWT infrastructure is required.

**When to use:** You want TLS termination and/or routing but do not need centralised identity.

### JWT mode

```
Client ──OAUTHBEARER (JWT)──► pgphantom ──service account or STS token──► PostgreSQL backend
```

The client presents a JWT as the SASL OAUTHBEARER token (PostgreSQL 16+ native). pgphantom:

1. Validates the JWT signature using the JWKS endpoint.
2. Checks `iss`, `aud`, and `exp` claims.
3. Connects to the backend using one of:
   - A **static service account** (`service_user` + `service_password_env` on the backend).
   - An **STS-minted token** (RFC 8693 exchange using the client's JWT as the subject token, if `auth.sts` is configured).

**When to use:** You have an IdP (Keycloak, Entra ID, Okta, …) that issues JWTs and want to avoid distributing PostgreSQL passwords to every application.

---

## Routing resolution order

Connection routing is resolved as follows:

1. **Mappings** — evaluated top-to-bottom. First exact match on `database` and/or `user` wins.
2. **Regex rules** — evaluated top-to-bottom. First rule whose regexes match the database and user wins. Capture groups from the match are available as `$1`, `$2`, … in `rewrite_database` and `backend_host`.
3. **default_backend** — used if no mapping or regex rule matched.
4. **Reject** — if no default backend is configured, the connection is closed with error `3D000`.

---

## Cluster / etcd

When `cluster.enabled = true`, each pgphantom node:

1. **Publishes** its current config as JSON under `{prefix}/{node_id}` at startup.
2. **Watches** the `{prefix}` key space for updates from other nodes.
3. **Reloads** routing rules when a peer publishes an updated config.

The etcd prefix defaults to `/pgphantom/config/`. All nodes in a cluster must share the same etcd cluster and prefix.

> **Note:** In the current release, config updates received from peers are logged but do not yet trigger a live reload of the active proxy context. Full hot-reload support is planned for a future release.
