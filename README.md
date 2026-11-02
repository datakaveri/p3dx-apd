# p3dx-apd

Access Policy Database (APD) for the P3DX platform, written in Go.

Stores dataset access policies set by data providers, manages the access-request lifecycle between consumers and providers, handles consent flows, and serves as the policy oracle that TOP (Trusted Orchestrator Protocol) queries before accepting any workload contract.

---

## What this repo does

- Stores dataset access policies submitted by data providers (via p3dx-aaa backend proxy)
- Answers policy queries from TOP by dataset ID — no policy means TOP rejects the contract
- Manages the full access-request lifecycle: consumer creates request → TEE provisioned → provider submits key bundle → consumer retrieves result
- Handles consent approval/denial via one-time token links sent to providers by email
- Receives TEE attestation reports and computation results as callbacks

---

## Repository Structure

```
p3dx-apd/
├── cmd/server/main.go          # Entry point — wires dependencies and starts HTTP server
├── internal/
│   ├── config/                 # Env var loading
│   ├── domain/                 # Core types (AccessRequest, Policy, ConsentToken, etc.)
│   ├── handler/                # HTTP handlers
│   ├── middleware/             # JWT verification, role enforcement
│   ├── repository/             # PostgreSQL queries (pgx)
│   ├── router/                 # chi router — all route definitions
│   └── service/                # Business logic (access requests, consent, TEE, attestation)
├── keys/                       # EC key material (P-256) for JWT signing
├── policies/                   # Optional policy dump directory (POC)
├── schema.sql                  # PostgreSQL schema
└── go.mod
```

---

## Getting Started

### Prerequisites

- Go 1.22+
- PostgreSQL (schema applied via `schema.sql`)
- EC key pair (P-256) for JWT signing

### Apply database schema

```bash
psql -h localhost -U <db_user> -d <db_name> -f schema.sql
```

### Configure environment

```env
PORT=8082

DB_HOST=localhost
DB_PORT=5432
DB_USER=apd
DB_PASSWORD=<password>
DB_NAME=apd
DB_SSLMODE=disable

JWT_PRIVATE_KEY_PATH=./keys/jwt_private.pem
JWT_PUBLIC_KEY_PATH=./keys/jwt_public.pem
JWT_ISSUER=http://localhost:8082

APD_BASE_URL=http://localhost:8082
APD_SIGNING_KEY_PATH=./keys/jwt_private.pem

TEE_ORCHESTRATOR_URL=http://localhost:9999

# Optional: dump every received policy to a JSON file (POC persistence/reload)
APD_POLICY_DUMP_DIR=./policies

# Optional: JWT token lifetime (default: 60 minutes)
JWT_EXPIRY_MINUTES=60

# Consent email — required if EMAIL_ENABLED=true (default: true)
EMAIL_ENABLED=true
CONSENT_BASE_URL=http://localhost:8082/api/v1/consent
SMTP_HOST=localhost
SMTP_PORT=587
SMTP_USER=<smtp-user>
SMTP_PASSWORD=<smtp-password>
EMAIL_FROM=apd@example.com

# AMD SEV-SNP attestation — required for production TEE verification
AMD_ARK_CERT_PATH=./keys/ark.pem   # ARK certificate for AMD chain-of-trust verification
AMD_SKIP_CHAIN_VERIFY=false         # Set true in dev/test to skip AMD cert chain
AMD_ALLOWED_POLICY=0                # Acceptable AMD guest policy bitmask

# Optional: shared secret service callers (gov_layer) send as
# X-Forms-Push-Token on /api/v1/forms/*. Browser callers send a user JWT
# instead. Left unset, requests without a JWT are not checked — fine for
# local dev, not for production.
FORMS_PUSH_TOKEN=

# Accept Keycloak-issued (RS256) user tokens — what the P3DX UI holds after
# signing in — verified against this realm's JWKS. ES256 tokens signed by
# JWT_PUBLIC_KEY_PATH's key keep working either way.
KEYCLOAK_JWKS_URL=http://localhost:8080/realms/master/protocol/openid-connect/certs

# Comma-separated browser origins allowed to call APD (the P3DX UI).
CORS_ORIGINS=http://localhost:5174
```

### Run

```bash
go run ./cmd/server/main.go
```

Expected output:
```
connected to postgres
APD server listening on :8082
```

---

## API Endpoints

### Public (no auth required)

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/api/v1/policy` | Receive a dataset access policy (from p3dx-aaa proxy) |
| `GET` | `/api/v1/policy/{policyId}` | Fetch a policy by policy ID (used by TOP) |
| `GET` | `/api/v1/policy/by-item/{itemId}` | Fetch a policy by dataset ID (used by TOP) |
| `GET` | `/api/v1/consent/{token}/approve` | Provider approves consent via one-time link |
| `GET` | `/api/v1/consent/{token}/deny` | Provider denies consent via one-time link |
| `POST` | `/api/v1/tee/attestation` | TEE submits attestation report (phase 3) |
| `POST` | `/api/v1/tee/result` | TEE submits computation result (phase 5) |

### Authenticated (Bearer JWT required)

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/api/v1/access-requests` | `consumer` | Create a new access request (phase 1) |
| `GET` | `/api/v1/access-requests` | `consumer` | List own access requests |
| `GET` | `/api/v1/access-requests/{requestId}` | any | Get a specific access request |
| `POST` | `/api/v1/access-requests/{requestId}/compute` | `consumer` | Trigger TEE provisioning (phase 2) |
| `GET` | `/api/v1/access-requests/{requestId}/result` | `consumer` | Poll for encrypted result (phase 5) |
| `POST` | `/api/v1/access-requests/{requestId}/key-bundle` | `provider` | Submit encrypted key bundle (phase 4) |
| `GET` | `/api/v1/provider/access-requests` | `provider` | List access requests assigned to provider |
| `POST` | `/api/v1/me/policies` | `provider` (dataset) / `infra_provider` (`rules.policy_type: "infra-provider"`) | Register or edit (same `itemId`) a policy; `provider_id` comes from the token |
| `GET` | `/api/v1/me/policies/datasets` | `provider` | List the caller's dataset policies |
| `GET` | `/api/v1/me/policies/datasets/{itemId}` | `provider` | One of the caller's dataset policies (403 if someone else's) |
| `DELETE` | `/api/v1/me/policies/datasets/{itemId}` | `provider` | Soft-delete one of the caller's datasets |
| `GET` | `/api/v1/me/policies/infrastructure` | `infra_provider` | List the caller's infrastructure |
| `DELETE` | `/api/v1/me/policies/infrastructure/{itemId}` | `infra_provider` | Soft-delete one of the caller's infrastructure entries |
| `GET` | `/api/v1/catalogue/datasets` | any | Dataset catalogue `[{id, name}]` (policies + FL provider forms) |
| `GET` | `/api/v1/catalogue/infrastructure` | any | Infrastructure catalogue (InfraCat) |
| `GET` | `/api/v1/catalogue/infrastructure/{itemId}` | any | One infra's `rules.infrastructure` detail |

### FL forms (user JWT or `X-Forms-Push-Token`)

`/api/v1/forms/*` (submissions, provider-forms, dataset-names) accepts either a user's Bearer JWT (the UI) or the `FORMS_PUSH_TOKEN` shared secret (services). `POST /api/v1/forms/provider-forms` additionally needs the `provider` role when called with a user JWT.

### Policy note (POC)

The `/api/v1/policy/*` endpoints are unauthenticated and trust the `provider_id` they are given — they are for internal service callers only (gov_layer posts consumer grants and reads `/mine`, `/mine-datasets`; TOP reads policies). Do not expose them publicly; browsers use the JWT-guarded `/api/v1/me/policies` and `/api/v1/catalogue` routes instead. If `APD_POLICY_DUMP_DIR` is set, every received policy is also written to a JSON file. APD reloads from this directory on-demand if the policy is not found in the database, providing resilience across restarts.

---

## Access Request Lifecycle

```
Phase 1  Consumer creates access request
         POST /api/v1/access-requests

Phase 2  Consumer triggers TEE provisioning
         POST /api/v1/access-requests/{requestId}/compute
         → APD provisions TEE, sends consent email to provider

Phase 3  TEE submits attestation report
         POST /api/v1/tee/attestation

Phase 4  Provider submits encrypted key bundle
         POST /api/v1/access-requests/{requestId}/key-bundle
         (or via email consent link: GET /api/v1/consent/{token}/approve)

Phase 5  TEE runs computation, submits result
         POST /api/v1/tee/result
         Consumer polls: GET /api/v1/access-requests/{requestId}/result
```

---

## More Information

See the p3dx-aaa `Setup.md` for how APD fits into the full P3DX platform architecture, including how TOP queries APD during workload contract ingestion.
