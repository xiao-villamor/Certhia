# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Certhia is for people who need to know which vulnerabilities have been reported in the Docker images they build or run. Platform engineers can follow findings across services, application maintainers can follow their own images across releases, and security teams can look up which scanned versions reported an advisory.

## Product Purpose

Keep a history of what each image scan reported. For a given advisory, a team should be able to see which image versions reported it, whether it appeared in the latest completed scan, and which issue tracks it.

## Positioning

Certhia is a self-hosted vulnerability tracker for Docker images. Each report records scanner observations for a particular image version and platform. A later scan supplies the next observation, even when the image itself has stayed the same and the scanner’s advisory data has changed.

## Product direction

Build on today’s issue links and Markdown comparison export. The proposed workflow would register a finding in the team’s issue tracker and attach later scan observations to the same issue. A release security changelog would summarize what the scans reported as newly detected, still detected, or no longer detected. The team manages ticket status in its tracker.

## Operating Context

- Engineers work from registry tags or digests, images discovered in Docker, Swarm, or Kubernetes, uploaded Docker image archives, or imported Trivy reports.
- Scans can be started manually, queued in batches, scheduled, or triggered by CI and Harbor push events. Watch alerts use a completed scan as the baseline and report newly detected advisories on subsequent scans of the same reference and platform.
- Engineers review scan reports, record notes and status, and link findings to their existing issue tracker. They can compare completed reports to see how the findings changed.
- The browser dashboard is self-hosted. The standard Compose deployment binds to loopback. Shared deployments use a TLS proxy and require users to sign in with a local account or an OpenID Connect provider.

## Capabilities and Constraints

- Registry connections can use pull credentials for an exact image even when catalog listing is unavailable. Tags can move. Comparisons can resolve registry references to immutable digests.
- A scan is specific to a platform. Finding status and issue links can differ across image versions.
- The standard deployment uses PostgreSQL for scan history, findings, and jobs. Trivy is included by default. Additional scanner engines can be configured.
- Reports can be exported as PDF, Excel, Markdown, JSON, CycloneDX SBOM, OpenVEX, or ZIP. OpenVEX describes the scanned image. A false-positive decision with an explanatory note can support a `not_affected` status.
- BuildKit is required to build a patched OCI image through the patch workflow.

## Brand Commitments

The user-facing product name is Certhia, as used in the dashboard and README.

## Evidence on Hand

- [README](README.md) documents deployment, scan inputs, image comparison, issue tracking, image watches, and exports.
- The [scan report](web/src/routes/scans/%5Bid%5D/+page.svelte), [report comparison](web/src/routes/compare/+page.svelte), and [finding tracker](web/src/lib/FindingTracker.svelte) show the workflow the product supports today.
- The [image finding tracking migration](backend/migrations/0012_image_finding_tracking.sql) records how tracking keys are scoped to an image version and advisory.

## Product Principles

1. Keep image-version evidence and remediation together. Show which reference, digest, and platform a finding or decision applies to.
2. Describe changes in terms of scanner evidence. “No longer detected” means the later completed scan did not report the finding. A failed or missing scan supplies no new observation.
3. Preserve remediation decisions across repeat scans of the same image version, and keep linked issues and notes traceable to the relevant finding.
