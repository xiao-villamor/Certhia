# PostgreSQL storage design

This document describes the target layout for PostgreSQL 16 and later. PostgreSQL 17 is the reference deployment. A primary handles writes, migrations and read-after-write requests. An optional replica serves searches, comparisons and dashboards where replay lag is acceptable. Each replica of the application needs the same AES-GCM registry key and access to the same artifact store.

## Identity and history

A repository has a registry and a canonical name. Registry identity is the host. Saved connection profiles reference the host so separate credentials and catalog settings can coexist for the same registry. Deleting a profile preserves repository and digest history. A tag points to its current platform manifest digest. Keep a separate repository-to-digest association so moving or deleting a tag does not discard scan history. Match platform manifests by content digest. An import without a verified digest needs an explicitly synthetic identity derived from the sanitized report bytes to prevent unrelated uploads to a mutable tag from merging.

Normalize ecosystem and severity names into small dictionaries. Packages have one global identity per ecosystem, name, version and package URL, including absent URLs. Keep the layer association on the digest inventory. A missing inventory is distinct from an empty inventory. An immutable digest can acquire its first complete inventory on a later scan.

Advisories are unique by source and external identifier. Trivy provides the advisory identifier. The merge refreshes severity and summary from the observation. Extended metadata uses the modification date when supplied. Store references as JSONB. Store open and resolved findings in the same table with a composite primary key of digest, package and advisory. A rescan reopens a previously resolved match. To reconstruct historical comparisons even across multiple reopenings, record membership transitions keyed by scan and finding separately. Resolve findings only after an authoritative, complete scan for the same scanner coverage.

Use UUIDv7 scan IDs in the API. An unpartitioned scan directory maps UUIDs to queued timestamps and compact bigint scan numbers. This allows global uniqueness and narrow finding references without depending on a PostgreSQL extension. Keep scan numbers after monthly scan detail retention. Triage status, notes, and issue links are keyed by repository, digest, reference, platform, and advisory. The upgrade copies existing repository tracking to versions with saved evidence for the advisory. VEX reviews retain scan scope.

## Physical layout and queries

Distribute findings and digest_packages across 16 hash partitions on digest ID. Index open findings by advisory then digest and by package then digest, with a partial predicate on the nullable resolution scan number. Digest-first primary keys support comparison and SBOM retrieval. Maintain reverse repository membership and tag indexes. Optional pg_trgm GIN indexes support infix searches on advisory IDs and package names.

Range-partition scan details by queued time and audit events by creation time using UTC calendar months. Create next month's partitions ahead of time and serialize DDL across replicas. Retention drops complete expired partitions after checking active jobs. Keep artifact garbage collection separate from database retention. Paged lists order by stable keys and return continuation cursors. Keep the same filter parameters when following a cursor.

## Merge and counters

Compress sanitized raw evidence with zstd into content-addressed local or object storage before opening the merge transaction. Replica deployments use a shared volume or object bucket. A failed commit may leave an unreferenced object for later collection. Never fetch an object to answer an index query.

Serialize merges on the digest row. A leased write validates its token and deletes the job inside the transaction. Assign a monotonic observation order under the digest lock so first and last observation order is independent of queue order. Stream binary COPY into transaction-local staging tables and deduplicate before joining to the dictionaries. Insert missing dimensions in deterministic key order. Insert inventory on the first complete observation. Use set differences to close missing findings and upsert the observed findings. Record transitions, update the tag subject to observation order, publish the evidence reference and complete the job in the same transaction.

Apply grouped counter deltas for digest severity totals, repository severity totals, package prevalence and distinct affected digests per advisory. Multiple tags for a digest must count once within a repository. Severity changes in shared advisory metadata must also adjust counts on other affected digests. Retry deadlock or serialization failures at the transaction boundary using the same observation ID.

## Workers and operational data

Claim ready jobs in priority and queue-time order with FOR UPDATE SKIP LOCKED. Each claim issues a new lease token. Heartbeats and final updates require the current token. A crashed worker can cause repeated scanner work after expiry. Fencing guarantees a single accepted merge and prevents a stale worker overwriting its successor. Commit schedule advancement, a unique (schedule, nominal fire time) run and its jobs together.

LISTEN before checking for work and recheck after reconnect. NOTIFY signals committed changes, while persisted activity sequence numbers allow reconnecting UI clients to replay missed progress. A timer for the earliest lease expiry wakes workers even if no notification arrives.

Use separate relational tables for registry configuration, catalog entries, webhooks, schedules, runs, settings, encrypted notification configuration, watches, observations, alerts, issue trackers, batches, batch membership, patches, VEX reviews, audit events and artifact metadata. Back up registry.key and artifact storage alongside the database.

## Capacity and acceptance measurements

At 5,000 repositories and 50 distinct manifests each, 400 packages per manifest gives 100 million inventory associations. With bigint digest and scan numbers, integer package and advisory keys, and a dictionary for repeated fix strings, an open finding's fixed-width values occupy about 36 bytes before alignment, tuple header, page overhead and indexes. Budget roughly 7–9 GB for 100 million heap tuples alone. Indexes, inventory, WAL, historical transitions, free space and backups need separate capacity. These are estimates.

Benchmark on four vCPUs and 8 GB RAM with PostgreSQL 17. Record disk type, database size, dataset cardinalities, concurrency, cache state, and p50/p95 for advisory impact, repository findings, dashboard, package ranking, digest comparison and advisory search. Measure end-to-end merge time for 2,000 findings including commit. The scale run was stopped at the operator’s request before the timing pass.

## Re-importing raw evidence

The backend accepts `reimport REFERENCE PLATFORM FILE` before starting the HTTP listener. The file may be a Trivy container report in JSON or a zstd-compressed copy. Set DATABASE_URL and CERTHIA_DATA_DIR as for the server. The importer sanitizes scanner evidence before archiving it. It prints the committed UUID. Repeated imports create separate scan observations and reuse finding identities.

The merge operates at serializable isolation and retries serialization failures and deadlocks. Stage rows carry either an inventory package or a package/advisory observation. The merge records membership changes separately so reopenings survive. Package counts measure open finding occurrences. Advisory counts measure distinct digests with any open match. Repository severity counts include distinct historical manifests associated with the repository, including untagged manifests.

The scanners and importer use the same merge. A partial observation can add findings while preserving earlier open findings. Imports without a manifest digest use a synthetic report hash. Per-scanner coverage and historical advisory metadata revisions are not modeled separately. Historical scan comparisons preserve finding membership and use current advisory text and fix metadata.

## Pagination and scaling

Most list responses preserve their original JSON shape and carry the continuation in the `x-next-cursor` response header. Registry catalog, watch and analytics responses have their own continuation fields. Search and sort precede the page limit. The advisory library pages finding occurrences, so an advisory can continue on the next page. The scan desk reads global totals from `/api/dashboard`. The lookup endpoints include `/api/library/advisories`, `/api/library/advisories/{id}/digests`, `/api/repositories/{id}/findings`, `/api/library/top-packages` and `/api/digests/{a}/compare/{b}`. The analytics routes use internal numeric dimensions. A scheduled run returns up to 200 scan IDs, its total and its run ID. Follow `/api/scheduled-scans/history?run=UUID` for subsequent pages.

Raw scanner files are content-addressed zstd objects. Local evidence, archive inputs, and patch outputs require shared filesystem storage across replicas when those features use disk. Persist the registry encryption key externally. The server honors `DATABASE_READ_URL` for library and analytics requests. Immediate scan detail and job reads use the primary.

## Benchmark fixture and run status

The SQL generator defaults to 5,000 repositories, 250,000 immutable digests, 100 million inventory associations and 100.25 million open findings. Each digest shares 200 base packages and has 200 rotating application packages. One advisory is common to every digest. Run on an empty, migrated, disposable database.

```sh
psql "$DATABASE_URL" -X -f tests/storage/seed.sql
PGDATABASE="$DATABASE_URL" tests/storage/benchmark.sh
digestdesk benchmark-ingest
```

The pgbench runner warms each query ten times and measures 100 single-client transactions. The release binary times 50 scans with 2,000 findings after five warm-ups and includes parsing, compression, evidence storage and commit. For HTTP benchmarks, set `CERTHIA_BENCH_URL` to the disposable instance and run `cargo bench --bench storage` in `backend/`.

The trial used PostgreSQL 17 Alpine on an Intel N100 with four CPU cores, a 512 GB TWSC SATA SSD and 15 GiB host RAM. Docker limited PostgreSQL to four CPUs and 8 GiB with 512 MiB shared buffers. Builds shared the host during loading. The isolated generator ran with foreign key triggers disabled. At cancellation, 192,500 digests had committed, equivalent to 77,000,000 package associations and 77,192,500 findings from completed generator batches. PostgreSQL reported 19 GB before final rollups. The 100M-row read p50/p95, throughput and 200 ms ingest target remain unverified.
