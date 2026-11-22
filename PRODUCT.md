# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Platform and DevOps engineers use Certhia to triage vulnerabilities in the container images they operate and check whether an image update resolves them. They need to identify the affected version, review the scan evidence, and carry a remediation decision through to a follow-up scan or linked issue.

## Product Purpose

Certhia is a self-hosted workspace for scanning container images, comparing versions, and tracking remediation. An engineer should be able to explain which image version was scanned, which findings changed between versions, and what action was taken on each tracked finding.

## Positioning

Certhia connects scan evidence and remediation to the container image version it applies to. Tracking follows the image reference, digest, platform, and advisory across repeat scans. Engineers can compare completed reports to see which advisories were added or removed and which packages changed.

## Operating Context

- Engineers work from registry tags or digests, images discovered in Docker, Swarm, or Kubernetes, uploaded Docker image archives, or imported Trivy reports.
- Scans can be started manually, queued in batches, scheduled, or triggered by CI and Harbor push events. Watch alerts use a completed scan as the baseline and report newly detected advisories on subsequent scans of the same reference and platform.
- Engineers review the scan report, record finding status and notes, and link findings to their existing issue tracker. They can compare with a later report to verify the outcome of an update.
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
2. Make the outcome of an update verifiable. Show package changes and advisory changes between versions so engineers can see what the update resolved and what still needs attention.
3. Preserve remediation decisions across repeat scans of the same image version, and keep linked issues and notes traceable to the relevant finding.
