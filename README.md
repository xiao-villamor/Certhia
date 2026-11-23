# Certhia

<img src="web/static/certhia.png" alt="Certhia logo" width="64">

Certhia is a self-hosted tool for scanning container images and keeping the reports. Compare two tags to see which packages changed and which findings the scanners still report. You can link a ticket to a CVE and see which images it affects.

[Quick start](#quick-start) · [Private registries](docs/private-registries.md) · [Kubernetes discovery](docs/kubernetes-discovery-scheduling.md) · [Company sign-in](docs/auth.md)

https://github.com/user-attachments/assets/cf2bfabc-2101-46cd-9c1a-1f5b67018a42

[Download the full-resolution MP4](https://raw.githubusercontent.com/xiao-villamor/Certhia/main/docs/media/certhia-overview.mp4)

## Quick start

You need Docker and the Compose plugin.

```sh
git clone https://github.com/xiao-villamor/Certhia.git
cd Certhia
```

**Trivy only**

```sh
docker compose up -d --build --wait
```

**All scanner providers**

```sh
docker compose -f compose.yaml -f compose.scanners.yaml up -d --build --wait
```

`compose.scanners.yaml` adds Grype, Syft, Dockle, OSV-Scanner, and Dive alongside Trivy. Use it for a fresh install or to add providers to an existing Compose installation. Keep the same project name and any existing override files. List `compose.scanners.yaml` after any override that changes the app’s build target.

1. Open <http://localhost:3001> and create the first administrator.
2. Choose default providers during setup or later in **Workspace preferences → Scanner providers**. For one scan, select providers under **Scan options**.
3. Select **Start scan**, choose **Registry image**, and enter `alpine:3.22`. Open the completed report to review findings or download an SBOM.

Compose starts Certhia and PostgreSQL 17 on loopback. Set `CERTHIA_PORT` to change the host port. The first build compiles the Rust backend, builds the web app, and downloads the tools for the selected image. Later builds reuse Docker’s build cache. Trivy and Grype can also download their vulnerability databases on first use.

For a shared instance, configure [HTTPS, roles, and OIDC](docs/auth.md). See [deployment options](#optional-deployment-features) for Docker, Kubernetes, and S3.

## What you can do

Scan an image by tag or digest, discover it in Docker, Swarm, or Kubernetes, or upload a Docker archive. You can also import a Trivy JSON report you already have.

If scanners disagree, open the report to see each provider's severity and reported fix. Search by CVE or GHSA. You can link one ticket across the affected images, track a single version, or record an exception with a reason and expiry.

Download CycloneDX, SPDX, or OpenVEX from a completed report. Certhia can retain a CycloneDX SBOM with scheduled scans. Rescans can run on a schedule, after a push from CI or Harbor, or when Kubernetes reports a new image digest.

The dashboard uses SvelteKit and the API is written in Rust. PostgreSQL stores reports and scan jobs. Open `/api-reference` for the API docs.

## Compare image versions

In **Report comparison**, choose two completed reports for the same platform with comparable vulnerability evidence. You can see what each report detected and which package versions changed. Use **Download security changelog** to attach the comparison to a ticket or release notes. See [Image vulnerability tracking](docs/image-vulnerability-tracking.md) for issue links and published-image comparisons.

## Explain scanner differences

A scan with completed reports from at least two vulnerability engines (Trivy, Grype, or OSV-Scanner) includes **Scanner differences** on the report page and `discrepancies.json` in its ZIP export. Each finding names the scanners that reported it and lists any known aliases. Search a report by either its CVE or its GHSA. Syft appears in the scan summary when it supplies the package inventory.

Run `explain` from the checkout to compare two or three scanner JSON reports offline.

```sh
cargo build --release --locked --manifest-path backend/Cargo.toml
backend/target/release/digestdesk explain --trivy trivy.json --grype grype.json --osv osv.json --same-input
```

Use `--json` for machine-readable output. The comparison checks available image identifiers and platforms. When the reports came from the same image or SBOM and lack a common image ID, add `--same-input` to record that fact. Add `--sbom inventory.cdx.json` with `--same-input` to supply the associated CycloneDX source-package metadata. Conflicting image IDs are rejected.

The comparator reconciles explicit advisory aliases and one-to-one Alpine binary/source relationships for the same package version. A difference in severity or fixed versions, an ambiguous source, or a finding reported by a single scanner remains available for review. The explanation includes any CPE matching evidence recorded by Grype. Tracking decisions are independent of reconciliation.

## Scan a private image

1. Open **Registry connections → Add registry** and enter the exact registry host, username, and token or password with pull access.
2. Paste a tag or digest into **Image to test**, select the scan platform, then choose **Test image access**. This reads the manifest and image configuration. The scan downloads the layers.
3. Save the connection and choose **Scan image** on its row, or select it under **Registry connection** in **Start scan**. Pick a repository and tag or enter a reference manually. The connection can pull an exact image even when the registry restricts catalog access.

Some registries issue tokens from a different host than the one that serves images. When the registry's `WWW-Authenticate` challenge names another token service, enter that hostname under **Connection options → Separate token host** for catalog browsing. A scoped pull token can work when the registry disables catalog listing.

Provider catalog settings accept an organization, user, or group for Docker Hub, GHCR, and GitLab, an owner for Gitea and Forgejo, a repository for Nexus, or `project/repository` for Google Artifact Registry. GitLab tokens need API access for provider catalog browsing and registry access to pull. With Artifact Registry, use `oauth2accesstoken`, `_json_key`, or `_json_key_base64` as appropriate for your credentials. Other registries can be browsed using their OCI catalog when enabled. The registry editor supports HTTP and self-signed endpoints when explicitly configured. See [Private registry connections](docs/private-registries.md).

## Link vulnerabilities to issues

In **Workspace preferences → Issue trackers**, add a named tracker. Copy an issue URL from the project and replace its ID with `{id}`. For example, use `https://tracker.example.com/browse/{id}` for an issue URL ending in `/browse/SEC-123`. Set up a tracker for each project that uses a different URL template. HTTP and HTTPS links to self-hosted trackers are supported.

Open a finding's tracking details for the affected image version. If you need to create an issue, use **Copy issue draft** to take the scan evidence to your tracker. Select the saved tracker, enter the issue ID, and choose a scope. Use **All images for this CVE** for a shared ticket, or attach an image-specific issue. Use **Exception** to record a reason and expiry across versions of a reference or repository on the selected platform. See [Image vulnerability tracking](docs/image-vulnerability-tracking.md).

## Watch for newly detected vulnerabilities

On a completed scan, choose **Watch new vulnerabilities**. Certhia uses the latest completed report as the baseline. It creates an alert the first time a later report for the same reference and platform includes a new advisory ID. Use **Schedule rescans**, or run another scan of that reference manually or from CI.

See alerts and delivery status under **Workspace preferences → Image watches**. External delivery uses the destination in **Notifications**. Turn off ordinary scan completion notifications if you only want vulnerability alerts.

## Scan a Kubernetes pod image or a Swarm service image

In **Start scan**, choose **Kubernetes**, enter the namespace, and select **Find pod images**. Choose an image from the results, verify its reference and platform, and select **Start scan**. For private images, choose a registry connection that can pull the image.

Discovery shows the pods, workloads, and containers using each image. Certhia uses the running manifest digest when Kubernetes reports a pullable digest. To queue scans when deployments change, select **Kubernetes digest changes** when creating a schedule. See [Kubernetes discovery and scheduling](docs/kubernetes-discovery-scheduling.md).

For Swarm, connect Certhia to a manager’s Docker socket. Choose **Docker Swarm → Find service images** to scan an individual service or scan all unique service image digests. Local Docker discovery labels images used by running containers.

## Export supply chain reports

On a completed scan, open **Report contents** to download CycloneDX 1.6 or SPDX 2.3 JSON. Both formats include package URLs when the scanner supplies them. To obtain an inventory, choose Trivy or Syft for the scan, or import a Trivy JSON report with packages. For scheduled scans, enable **Retain a CycloneDX SBOM** to store an SBOM with each report that has package inventory.

Use **OpenVEX** in the same section to download OpenVEX 0.2.0 for the scanned image. Available documents are also included in the ZIP bundle. Record a false positive with an explanatory note on that scan to document a `not_affected` decision. Findings without a qualifying review are exported as `under_investigation`.

## Scan after an image push

Open **Registry connections**, choose **Webhook** on a saved connection, and generate a token. Save the token in your CI secret store or Harbor project during setup. Each connection uses its own token and saved pull credentials. New tokens use the `certhia_wh_` prefix. Existing tokens with the legacy prefix remain valid until rotated or revoked.

For CI, run this after the image is published. Set `CERTHIA_WEBHOOK_URL` to the CI endpoint, `CERTHIA_WEBHOOK_TOKEN` to the token, and `IMAGE_REFERENCE` to the published reference. Prefer the digest when a job must scan the exact artifact it built.

The repository includes a [GitHub Action](integrations/github-action/action.yml) that waits for the scan, links the report from the job summary, and can block on fixable high or critical advisories. Reference a commit that contains the action. The publishing step must provide the complete image reference and digest to the following step.

```yaml
- name: Scan the published digest
  uses: xiao-villamor/Certhia/integrations/github-action@<commit-sha>
  with:
    webhook-url: ${{ vars.CERTHIA_WEBHOOK_URL }}
    webhook-token: ${{ secrets.CERTHIA_WEBHOOK_TOKEN }}
    image: ${{ steps.publish.outputs.image }}@${{ steps.publish.outputs.digest }}
    fail-on-fixable: critical
```

The action requires a complete vulnerability scan. Omit `fail-on-fixable` to report the counts without a severity gate. The gate counts each advisory once at its highest fixable severity from this scan. Tracking decisions and exceptions apply to the workspace triage views. Protect the registry token as a GitHub Actions secret and use the step in a trusted workflow after publishing.

To queue a scan from another CI system, call the webhook directly.

```sh
jq -n --arg reference "$IMAGE_REFERENCE" '{reference: $reference}' |
  curl --fail-with-body --silent --show-error \
    --header "Authorization: Bearer $CERTHIA_WEBHOOK_TOKEN" \
    --header 'Content-Type: application/json' \
    --data-binary @- "$CERTHIA_WEBHOOK_URL"
```

For Harbor, create an HTTP webhook for **Artifact pushed** in the project. Paste the Harbor endpoint and put the token in **Auth Header**. Both Default and CloudEvents payloads work. The registry host in the event must match the saved connection, and a digest is used when available. See the [Harbor webhook configuration guide](https://goharbor.io/docs/main/working-with-projects/project-configuration/configure-webhooks/).

Both endpoints return scan IDs with HTTP `202`. Matching scans already queued or running return their existing IDs. CI can append `/{scanId}` to the CI endpoint and send a GET with the same bearer token to read the status and summary for up to 24 hours. The dashboard report requires a workspace session. The default platform is `linux/amd64`. CI can send `platform` for another supported platform. Scans use the workspace scanner defaults when they start, and explicit engine choices on manual scans take precedence. If none of the workspace choices are available for a source, it uses Trivy.

If CI or Harbor needs to reach a remote dashboard, expose the webhook delivery paths under `/api/webhooks/registries/` through your TLS proxy and forward the `Authorization` header. Registry management requires a signed-in administrator. Webhook delivery keeps its registry token authentication.

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

## PostgreSQL deployment and backup

Use PostgreSQL 16 or later. Set `DATABASE_URL` to the primary and optionally `DATABASE_READ_URL` to a read replica. The application role needs permission to create tables, functions and indexes in its own schema. The migration enables trigram indexes when the optional pg_trgm extension is available. The default Compose password is for local development. Set `POSTGRES_PASSWORD` before initializing the volume, and supply a URL-encoded `DATABASE_URL` if the password contains URI delimiters.

Back up the Compose database with:

```sh
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' > certhia.dump
```

Several app replicas can share a primary. Configure a shared 32-byte AES-GCM key with `CERTHIA_REGISTRY_KEY_FILE`. Put a load balancer in front of the replicas. Each worker renews its active lease. When a worker dies, a replacement may repeat scanner execution and only the current lease can commit a result. Scheduled runs and their jobs commit together. Size database connection limits for up to eight primary connections, an optional eight replica connections and a notification listener per process.

Back up the registry key, raw report bucket or shared volume, and uploaded archives alongside the database. To restore an empty database use `pg_restore --no-owner --dbname="$DATABASE_URL" certhia.dump`. Raw reports can also be re-imported with `digestdesk reimport REFERENCE PLATFORM FILE`. If you are moving from SQLite, back up its data directory first. A new PostgreSQL installation starts with an empty schema.

The Kubernetes manifest in `deploy/kubernetes.yaml` uses an external database. Set its image to your build, configure the allowed hostname, provide `DATABASE_URL` and optionally `DATABASE_READ_URL` in the `certhia-database` Secret, and mount the existing key as `registry.key` in the `certhia-key` Secret. For CloudNativePG, use its primary read/write service for migrations and writes and its read-only service for the optional replica connection. For managed PostgreSQL, configure TLS verification and mount the provider CA as required. Provide first-admin bootstrap credentials in the deployment Secret or configure a shared setup code across replicas. The sample uses a ReadWriteMany volume for archive inputs, patch outputs and filesystem report storage. Configure a storage class with RWX support. Application containers may be replaced independently.

### Upgrade an existing deployment

Keep the existing Compose project, initialized database credentials, and volume mappings. Set `POSTGRES_USER` and `POSTGRES_DB` to the initialized values and keep the existing password.

When upgrading, set S3 configuration using the `CERTHIA_S3_` variables in the deployment table above. Earlier unprefixed and provider aliases are no longer read. Restart all app replicas together when applying the migration that changes database notification channels. For an existing Compose project, set its name with `-p` and map the existing data volumes in a local override:

```yaml
volumes:
  postgres-data:
    external: true
    name: existing-postgres-volume
  certhia-data:
    external: true
    name: existing-app-volume
```

## Benchmark report processing

```sh
backend/target/release/digestdesk bench explain --synthetic 8000 --warmup 5 --iterations 40 > before.json
backend/target/release/digestdesk bench explain --trivy trivy.json --grype grype.json --iterations 40 > local-reports.json
backend/target/release/digestdesk bench compare before.json after.json
```

The synthetic size counts candidate advisories. Each run records input hashes, output counts and hash, all timed samples, median and p95 in milliseconds. The total covers JSON decoding, matching and serialization. File reads and fixture generation happen before timing. Use the same workload and build profile for both runs. A negative median change means the candidate took less time.

For an existing completed scan on a test instance, set `CERTHIA_BENCH_COOKIE` to that instance’s session cookie and run the following. This measures sequential, authenticated HTTP reads through the last response byte, including the scan detail, JSON report, inventory and discrepancy report when available. Both API variants must serve the same database scan at the same URL for `bench compare`. Warm-up and measured requests share a connection pool.

```sh
backend/target/release/digestdesk bench report --base-url http://127.0.0.1:3001 --scan-id "$SCAN_ID" --warmup 5 --iterations 40 > api.json
```

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

GNU Affero General Public License v3.
