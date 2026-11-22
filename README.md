# Certhia

<img src="web/static/certhia.png" alt="Certhia logo" width="64">

Certhia is a self-hosted workspace for scanning container images, comparing versions, and tracking vulnerability remediation. Axum serves the API and the static SvelteKit dashboard from one Rust process, with PostgreSQL for scan history, findings, and jobs.

## Run with Docker

```sh
docker compose up -d --build --wait
```

Open <http://localhost:3001>. The dashboard binds to loopback by default. On first run, get the setup code with `docker compose logs app` and create the first administrator in the browser, or set `CERTHIA_ADMIN_EMAIL` and `CERTHIA_ADMIN_PASSWORD_FILE` before starting. See [Sign-in and workspace access](docs/auth.md) for bootstrap, roles, OIDC, and recovery. Set `CERTHIA_PORT` to change the host port. Compose starts a separate PostgreSQL 17 service on its internal network. The app checks database reachability and migration state at `/api/ready`. The liveness endpoint is `/api/health`.

The standard image includes Trivy for scanning and Skopeo for image operations. Trivy downloads its vulnerability database on the first scan. For an existing deployment, keep its Compose project, database credentials, and volume mappings. Set `POSTGRES_USER` and `POSTGRES_DB` to the initialized database values, keep its existing password, and map existing named volumes in a local Compose override before starting the renamed services. Include `compose.scanners.yaml` to install additional local scanners.

When upgrading, set S3 configuration using only the `CERTHIA_S3_` variables listed below. Earlier unprefixed and provider aliases are no longer read. Restart all app replicas together when applying the migration that changes database notification channels. For an existing Compose project, set its name with `-p` and map the existing data volumes in a local override:

```yaml
volumes:
  postgres-data:
    external: true
    name: existing-postgres-volume
  certhia-data:
    external: true
    name: existing-app-volume
```

## PostgreSQL deployment and backup

Use PostgreSQL 16 or later. Set `DATABASE_URL` to the primary and optionally `DATABASE_READ_URL` to a read replica. The application role needs permission to create tables, functions and indexes in its own schema. The migration enables trigram indexes when the optional pg_trgm extension is available. The default Compose password is for local development. Set `POSTGRES_PASSWORD` before initializing the volume, and supply a URL-encoded `DATABASE_URL` if the password contains URI delimiters.

Back up the Compose database with:

```sh
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' > certhia.dump
```

Several app replicas can share a primary. Configure a shared 32-byte AES-GCM key with `CERTHIA_REGISTRY_KEY_FILE`. Put a load balancer in front of the replicas. Each worker renews its active lease. When a worker dies, a replacement may repeat scanner execution and only the current lease can commit a result. Scheduled runs and their jobs commit together. Size database connection limits for up to eight primary connections, an optional eight replica connections and a notification listener per process.

Back up the registry key, raw report bucket or shared volume, and uploaded archives alongside the database. To restore an empty database use `pg_restore --no-owner --dbname="$DATABASE_URL" certhia.dump`. Raw reports can also be re-imported with `digestdesk reimport REFERENCE PLATFORM FILE`. Existing SQLite installations should retain a backup of their data directory. A PostgreSQL installation starts with an empty schema.

The Kubernetes manifest in `deploy/kubernetes.yaml` uses an external database. Set its image to your build, configure the allowed hostname, provide `DATABASE_URL` and optionally `DATABASE_READ_URL` in the `certhia-database` Secret, and mount the existing key as `registry.key` in the `certhia-key` Secret. For CloudNativePG, use its primary read/write service for migrations and writes and its read-only service for the optional replica connection. For managed PostgreSQL, configure TLS verification and mount the provider CA as required. Provide first-admin bootstrap credentials in the deployment Secret or configure a shared setup code across replicas. The sample uses a ReadWriteMany volume for archive inputs, patch outputs and filesystem report storage. Configure a storage class with RWX support. Application containers may be replaced independently.

## Scan a private image

1. Open **Registry connections → Add registry** and enter the exact registry host, username, and token or password with pull access.
2. Paste a tag or digest into **Image to test**, then choose **Test image access**. This checks manifest access separately from catalog permissions.
3. Save the connection and choose **Scan image** on its row, or select it under **Registry connection** in **Start scan**. Pick a repository and tag or enter a reference manually. The connection can pull an exact image even when the registry restricts catalog access.

Some registries issue tokens from a different host than the one that serves images. When the registry's `WWW-Authenticate` challenge names another token service, enter that hostname under **Connection options → Separate token host** for catalog browsing. A scoped pull token can work when the registry disables catalog listing.

Provider catalog settings accept an organization, user, or group for Docker Hub, GHCR, and GitLab, an owner for Gitea, a repository for Nexus, or `project/repository` for Google Artifact Registry. GitLab tokens need API access for provider catalog browsing and registry access to pull. With Artifact Registry, use `oauth2accesstoken`, `_json_key`, or `_json_key_base64` as appropriate for your credentials. Other registries can be browsed using their OCI catalog when enabled. The registry editor supports HTTP and self-signed endpoints when explicitly configured.

## Workflows

- Scan registry images by tag or digest, discover Docker and Swarm images or Kubernetes pods, upload a Docker image archive, or import Trivy JSON.
- Queue batches, prioritize jobs, cancel pending or running scans, and view live progress. Set `CERTHIA_MAX_CONCURRENT_SCANS` to raise local concurrency.
- Compare completed scans or resolve two registry references to immutable digests. Review package updates and advisories added or removed by a change.
- Browse image histories and vulnerability details, classify findings, inspect layers, export image archives, and publish to a registry.
- Review vulnerability findings grouped by ecosystem, and filter reports or the advisory index by ecosystem.
- Triage vulnerabilities by image version. Tracking follows the same reference, digest, and platform across repeat scans. Use **Linked issues only** to find tracked work.
- Download PDF, Excel, Markdown, JSON, CycloneDX SBOM, OpenVEX, and ZIP reports. View the available per-scanner artifacts in each scan.
- Schedule specific images, all tracked images, or regex-based image and tag selection. See execution history and use **Run now** for an immediate run.
- Configure scan and audit retention, test notifications, analyze patch candidates, save a dry run, and build a patched OCI image with BuildKit.
- Choose default scanner providers in **Workspace preferences**.
- Queue an image scan from CI after a push or subscribe to Harbor push events from **Registry connections**.
- Open **API reference** at `/api-reference` for routes and request parameters. The service exposes `/api/health`, `/api/ready`, `/api/version`, and `/api/openapi.json`.

## Link vulnerabilities to issues

In **Workspace preferences → Issue trackers**, add a named tracker. Copy an issue URL from the project and replace its ID with `{id}`. For example, use `https://tracker.example.com/browse/{id}` for an issue URL ending in `/browse/SEC-123`. Set up a tracker for each project that uses a different URL template. HTTP and HTTPS links to self-hosted trackers are supported.

Open a finding's status for the affected image version, select the saved tracker, and enter the issue ID. Each version can link to its own issue. Changes to a tracker's template apply to future links. Existing links keep their saved URLs, including when a tracker is removed.

## Watch for newly detected vulnerabilities

On a completed scan, choose **Watch new vulnerabilities**. Certhia uses the latest completed report as the baseline. It creates an alert the first time a later report for the same reference and platform includes a new advisory ID. Use **Schedule rescans**, or run another scan of that reference manually or from CI.

See alerts and delivery status under **Workspace preferences → Image watches**. External delivery uses the destination in **Notifications**. Turn off ordinary scan completion notifications if you only want vulnerability alerts.

## Export supply chain reports

Open **SBOM and VEX** on a completed report to download CycloneDX 1.6 or OpenVEX 0.2.0. Available documents are also included in the ZIP bundle. OpenVEX describes the scanned image. Record a false positive with an explanatory note on that scan to document a `not_affected` decision. Findings without a qualifying review are exported as `under_investigation`.

## Optional deployment features

| Feature | Configuration |
| --- | --- |
| Docker and Swarm | Add `-f compose.docker.yaml`. Set `CERTHIA_DOCKER_GID` to the host socket group, for example `stat -c %g /var/run/docker.sock`. |
| Kubernetes | Add `-f compose.integrations.yaml -f compose.kube.yaml`. Set `CERTHIA_KUBECONFIG` to a readable kubeconfig with pod-list permission. Mounted config and referenced certificates must be readable by UID 10001. |
| Additional local scanners | Add `-f compose.scanners.yaml` to include Grype, Syft, Dockle, OSV-Scanner, and Dive. Select engines in **Workspace preferences** or when starting a scan. |
| S3 artifacts | Set `CERTHIA_S3_BUCKET`, `CERTHIA_S3_ACCESS_KEY`, and `CERTHIA_S3_SECRET_KEY`. Set `CERTHIA_S3_REGION` as needed, and `CERTHIA_S3_ENDPOINT` for a compatible service such as MinIO. |
| Image patch builds | Add `-f compose.integrations.yaml` and set `CERTHIA_BUILDKIT_ADDR` to a reachable BuildKit worker. For mutual TLS, mount the files and set `CERTHIA_BUILDKIT_CA`, `CERTHIA_BUILDKIT_CERT`, and `CERTHIA_BUILDKIT_KEY` inside the container. |

Include `-f compose.yaml` before all override files. For example:

```sh
docker compose -f compose.yaml -f compose.docker.yaml up -d --build --wait
```

The optional Docker socket gives the container Docker engine access. For shared access, put Certhia behind a TLS proxy, preserve the browser-facing `Host`, and set `CERTHIA_AUTH_SECURE_COOKIE=1`, `CERTHIA_AUTH_ORIGIN`, and `CERTHIA_ALLOWED_HOSTS`. Certhia provides native user sign-in and can connect to your identity provider over OpenID Connect. See [Authentication setup](docs/auth.md).

## Scan after an image push

Open **Registry connections**, choose **Webhook** on a saved connection, and generate a token. Save the token in your CI secret store or Harbor project during setup. Each connection uses its own token and saved pull credentials. New tokens use the `certhia_wh_` prefix. Existing tokens with the legacy prefix remain valid until rotated or revoked.

For CI, run this after the image is published. Set `CERTHIA_WEBHOOK_URL` to the CI endpoint, `CERTHIA_WEBHOOK_TOKEN` to the token, and `IMAGE_REFERENCE` to the published reference. Prefer the digest when a job must scan the exact artifact it built.

```sh
jq -n --arg reference "$IMAGE_REFERENCE" '{reference: $reference}' |
  curl --fail-with-body --silent --show-error \
    --header "Authorization: Bearer $CERTHIA_WEBHOOK_TOKEN" \
    --header 'Content-Type: application/json' \
    --data-binary @- "$CERTHIA_WEBHOOK_URL"
```

For Harbor, create an HTTP webhook for **Artifact pushed** in the project. Paste the Harbor endpoint and put the token in **Auth Header**. Both Default and CloudEvents payloads work. The registry host in the event must match the saved connection, and a digest is used when available. See the [Harbor webhook configuration guide](https://goharbor.io/docs/main/working-with-projects/project-configuration/configure-webhooks/).

Both endpoints return scan IDs with HTTP `202`. Matching scans already queued or running return their existing IDs. The default platform is `linux/amd64`. CI can send `platform` for another supported platform. Scans use the workspace scanner defaults when they start, and explicit engine choices on manual scans take precedence. If none of the workspace choices are available for a source, it uses Trivy.

If CI or Harbor needs to reach a remote dashboard, expose the webhook delivery paths under `/api/webhooks/registries/` through your TLS proxy and forward the `Authorization` header. Registry management requires a signed-in administrator. Webhook delivery keeps its registry token authentication.

## Develop and verify

Install Trivy and Skopeo on the host for live scans in development. Report imports work with the Rust API alone.

```sh
cd backend
CERTHIA_AUTH_SECURE_COOKIE=0 cargo run
```

```sh
cd web
npm ci
npm run dev
```

Vite proxies `/api` to port 8080. Set `CERTHIA_API_URL` to override it. The Rust server accepts `CERTHIA_DATA_DIR`, `CERTHIA_WEB_DIR`, and `CERTHIA_BIND` to change its storage, static build, and listener.

```sh
cargo test --manifest-path backend/Cargo.toml --locked
npm --prefix web run check
npm --prefix web run build
```

Run the end-to-end smoke suite against an empty instance with Trivy installed, `CERTHIA_DOCKER_SOCKET` configured, and a local administrator. Pass the administrator credentials as `CERTHIA_TEST_ADMIN_EMAIL` and `CERTHIA_TEST_ADMIN_PASSWORD` in the test environment.

```sh
CERTHIA_TEST_URL=http://127.0.0.1:3081 node tests/parity-smoke.mjs
```

Set `CERTHIA_LOG_FORMAT=json` for structured request logs and `RUST_LOG` to adjust tracing levels. Requests receive an `x-request-id`. To export traces, build the backend with `cargo build --release --features otel` (in Compose set `CERTHIA_CARGO_FEATURES=otel` when building) and set `OTEL_EXPORTER_OTLP_ENDPOINT` to the collector's OTLP/HTTP base URL.

## License

Licensed under the GNU Affero General Public License v3.
