<script lang="ts">
  import { Clock3, ListChecks } from '@lucide/svelte';
  import { active, time, type Scan, type ScanProgress } from './api.js';

  let { scan, progress, reconnecting }: { scan: Scan; progress?: ScanProgress; reconnecting: boolean } = $props();
  let now = $state(Date.now());
  const scanning = $derived(active(scan));
  const queued = $derived(scan.status === 'queued');
  const entries = $derived(progress?.activity ?? []);
  const latest = $derived(entries.at(-1));
  const startedAt = $derived(progress?.startedAt || scan.createdAt);
  const endedAt = $derived(scan.finishedAt ? Date.parse(scan.finishedAt) : now);
  const duration = $derived(Math.max(0, Math.floor((endedAt - Date.parse(queued ? scan.createdAt : startedAt)) / 1000)));
  const elapsed = $derived(duration >= 3600 ? `${Math.floor(duration / 3600)}h ${Math.floor(duration % 3600 / 60)}m`
    : duration >= 60 ? `${Math.floor(duration / 60)}m ${duration % 60}s` : `${duration}s`);
  const title = $derived(queued ? 'Waiting for a scanner'
    : scan.status === 'running' ? (latest?.title || 'Scanning image')
    : scan.status === 'completed' ? 'Scan completed'
    : scan.status === 'cancelled' ? 'Scan cancelled' : 'Scan failed');

  $effect(() => {
    if (!scanning) return;
    now = Date.now();
    const timer = setInterval(() => { now = Date.now(); }, 1000);
    return () => clearInterval(timer);
  });
</script>

{#if scan.source !== 'import'}
  <section class="panel activity-panel" aria-labelledby="scan-activity">
    <div class="panel-title">
      <div class="activity-heading">
        {#if scanning}<span class="spinner" aria-hidden="true"></span>{:else}<ListChecks size={22} aria-hidden="true" />{/if}
        <div role="status">
          <h2 id="scan-activity">{title}</h2>
          {#if queued && progress?.queuePosition}<p>Queue position {progress.queuePosition}</p>
          {:else if scan.status === 'running' && latest}<p>{latest.detail}</p>
          {:else if scan.finishedAt}<p>{time(scan.finishedAt)}</p>{/if}
        </div>
      </div>
      <span class="duration" title={progress?.startedAt && !queued ? 'Time since a scanner started' : 'Time since the scan was queued'}>
        <Clock3 size={15} aria-hidden="true" />
        {queued ? 'Queued for' : progress?.startedAt ? 'Elapsed' : 'Total time'} {elapsed}
      </span>
    </div>
    {#if reconnecting && scanning}
      <p class="compact-empty" role="status">Reconnecting to live updates…</p>
    {/if}
    {#if entries.length && !queued}
      <details open={scanning}>
        <summary>Activity <span>{entries.length} steps</span></summary>
        <ol>
          {#each entries as entry (entry.step)}
            <li>
              <time datetime={entry.at}>{new Date(entry.at).toLocaleTimeString()}</time>
              <span>{entry.title}</span>
            </li>
          {/each}
        </ol>
      </details>
    {/if}
  </section>
{/if}

<style>
  .activity-heading { display: flex; align-items: flex-start; gap: .75rem; min-width: 0; }
  .activity-heading > :first-child { flex-shrink: 0; margin-top: .1rem; color: var(--accent-ink); }
  .duration { display: inline-flex; align-items: center; gap: .4rem; color: var(--muted); font-size: .82rem; font-variant-numeric: tabular-nums; }
  details { border-top: 1px solid var(--line); padding: .8rem 1.3rem; }
  summary { display: flex; align-items: center; gap: .3rem; width: fit-content; cursor: pointer; list-style: none; font-weight: 650; font-size: .86rem; }
  summary::-webkit-details-marker { display: none; }
  /* Same chevron as the app's other disclosures. */
  summary::after { content: ''; width: .42rem; height: .42rem; margin-left: .35rem; border: solid var(--muted); border-width: 0 1.5px 1.5px 0; transform: translateY(-2px) rotate(45deg); }
  details:not([open]) summary::after { transform: rotate(-45deg); }
  summary span { margin-left: .3rem; color: var(--muted); font-size: .78rem; font-weight: 500; }
  ol { list-style: none; margin: .6rem 0 0; padding: 0; }
  li { display: grid; grid-template-columns: 7rem 1fr; gap: .75rem; padding: .42rem 0; font-size: .86rem; }
  li + li { border-top: 1px solid var(--line); }
  time { color: var(--muted); font-variant-numeric: tabular-nums; }
  @media (max-width: 560px) {
    li { grid-template-columns: 5.4rem 1fr; gap: .5rem; }
  }
</style>
