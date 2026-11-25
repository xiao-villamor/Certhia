<script lang="ts">
  import { Clock3, ListChecks } from '@lucide/svelte';
  import { active, scannerName, time, type Scan, type ScanProgress } from './api.js';

  let { scan, progress, reconnecting }: { scan: Scan; progress?: ScanProgress; reconnecting: boolean } = $props();
  let now = $state(Date.now());
  const scanning = $derived(active(scan));
  const queued = $derived(scan.status === 'queued');
  const entries = $derived(progress?.activity ?? []);
  const latest = $derived(entries.at(-1));
  const downloading = $derived(scan.status === 'running' && latest?.step === 'image_download');
  const startedAt = $derived(progress?.startedAt || scan.createdAt);
  const endedAt = $derived(scan.finishedAt ? Date.parse(scan.finishedAt) : now);
  const duration = $derived(Math.max(0, Math.floor((endedAt - Date.parse(queued ? scan.createdAt : startedAt)) / 1000)));
  function elapsedText(seconds: number) {
    return seconds >= 3600 ? `${Math.floor(seconds / 3600)}h ${Math.floor(seconds % 3600 / 60)}m`
      : seconds >= 60 ? `${Math.floor(seconds / 60)}m ${seconds % 60}s` : `${seconds}s`;
  }
  function since(value: string) { return elapsedText(Math.max(0, Math.floor((endedAt - Date.parse(value)) / 1000))); }
  function stepTitle(step: string, title: string) {
    const match = /^(trivy|grype|syft|dockle|osv|dive)_(started|finished|failed)$/.exec(step);
    if (!match) return title;
    return match[2] === 'started' ? 'Running ' + scannerName(match[1]) : scannerName(match[1]) + ' ' + match[2];
  }
  const title = $derived(queued ? 'Waiting for a scanner'
    : scan.status === 'running' ? (latest ? stepTitle(latest.step, latest.title) : 'Scanning image')
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
  <!-- svelte-ignore a11y_no_noninteractive_tabindex (The scan activity shortcut moves focus here.) -->
  <section class="panel activity-panel" id="scan-activity" tabindex="-1" aria-labelledby="scan-activity-title">
    <div class="panel-title">
      <div class="activity-heading">
        {#if scanning}<span class="spinner" aria-hidden="true"></span>{:else}<ListChecks size={22} aria-hidden="true" />{/if}
        <div role="status">
          <h2 id="scan-activity-title">{title}</h2>
          {#if queued && progress?.queuePosition}<p>Queue position {progress.queuePosition}</p>
          {:else if scan.status === 'running' && latest}<p>{latest.detail}</p>
          {:else if scan.finishedAt}<p>{time(scan.finishedAt)}</p>{/if}
        </div>
      </div>
      <span class="duration" title={progress?.startedAt && !queued ? 'Time since a scanner started' : 'Time since the scan was queued'}>
        <Clock3 size={15} aria-hidden="true" />
        {queued ? 'Queued for' : progress?.startedAt ? 'Elapsed' : 'Total time'} {elapsedText(duration)}
      </span>
    </div>
    {#if queued}
      <div class="stage-meta"><a class="table-link" href="/#scan-activity">Open scan queue</a></div>
    {:else if scan.status === 'running' && latest}
      <div class="stage-meta">
        <span>{downloading ? 'Downloading for' : 'Current stage ·'} {since(latest.at)}</span>
        {#if progress?.workerHeartbeatAt}<span>Worker last checked in · {since(progress.workerHeartbeatAt)} ago</span>{/if}
      </div>
    {/if}
    {#if reconnecting && scanning}
      <p class="compact-empty" role="status">Reconnecting to live updates…</p>
    {/if}
    {#if entries.length && !queued}
      <div class="activity-steps">
        <ol>
          {#each entries as entry, i}
            <li>
              <time datetime={entry.at}>{new Date(entry.at).toLocaleTimeString()}</time>
              <span>{stepTitle(entry.step, entry.title)}
                {#if entries[i + 1] || scan.finishedAt}
                  <small class="field-help"> · {elapsedText(Math.max(0, Math.floor((Date.parse(entries[i + 1]?.at ?? scan.finishedAt!) - Date.parse(entry.at)) / 1000)))}</small>
                {/if}
              </span>
            </li>
          {/each}
        </ol>
      </div>
    {/if}
  </section>
{/if}

<style>
  .activity-panel { scroll-margin-top: 5rem; }
  .activity-heading { display: flex; align-items: flex-start; gap: .75rem; min-width: 0; }
  .activity-heading > :first-child { flex-shrink: 0; margin-top: .1rem; color: var(--accent-ink); }
  .duration { display: inline-flex; align-items: center; gap: .4rem; color: var(--muted); font-size: .82rem; font-variant-numeric: tabular-nums; }
  .stage-meta { display: flex; flex-wrap: wrap; gap: .4rem 1rem; padding: .1rem 1.3rem .7rem; color: var(--muted); font-size: var(--text-detail); }
  .activity-steps { padding: .65rem 1.15rem; }
  ol { list-style: none; margin: 0; padding: 0; }
  li { display: grid; grid-template-columns: 7rem 1fr; gap: .75rem; padding: .42rem 0; font-size: .86rem; }
  li + li { border-top: 1px solid var(--line); }
  time { color: var(--muted); font-variant-numeric: tabular-nums; }
  @media (max-width: 560px) {
    li { grid-template-columns: 5.4rem 1fr; gap: .5rem; }
  }
</style>
