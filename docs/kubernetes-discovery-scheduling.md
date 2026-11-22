# Kubernetes digest change scheduling

The Kubernetes schedule mode reuses `kubernetes_observation` in
`backend/src/discovery.rs`. It polls the configured cluster and optional
namespace through the existing scheduler. A schedule can select a registry
connection to filter by registry host and supply credentials.

The first successful poll queues the confirmed digests it discovers.
Subsequent polls queue newly observed references per workload and container.
The comparison tracks the digest set during rolling updates and keeps known
digests for containers whose runtime status cannot establish a manifest
digest. When controller metadata is available, Deployment and CronJob
identities carry across changes to their ReplicaSets and Jobs.

The schedule stores its baseline and enqueues scans in the same database
transaction. This integration depends on
`backend/migrations/0018_kubernetes_schedule_observations.sql`.
