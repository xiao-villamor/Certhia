<script lang="ts">
  import type { Scan } from './api.js';

  let { scans, error, hasOlder }: { scans?: Scan[]; error: string; hasOlder: boolean } = $props();

  const statuses = [
    { id: 'completed', label: 'Completed' },
    { id: 'failed', label: 'Failed' },
    { id: 'active', label: 'Active' },
    { id: 'cancelled', label: 'Cancelled' }
  ] as const;
  const weekday = new Intl.DateTimeFormat(undefined, { weekday: 'short' });
  const dateLabel = new Intl.DateTimeFormat(undefined, { weekday: 'long', month: 'short', day: 'numeric' });
  const days = $derived.by(() => {
    const today = new Date();
    const buckets = Array.from({ length: 7 }, (_, index) => {
      const date = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 6 + index);
      return { date, total: 0, counts: { completed: 0, failed: 0, active: 0, cancelled: 0 } };
    });
    const byDate = new Map(buckets.map(day => [day.date.getTime(), day]));
    for (const scan of scans ?? []) {
      const date = new Date(scan.createdAt);
      date.setHours(0, 0, 0, 0);
      const day = byDate.get(date.getTime());
      if (!day) continue;
      const status = scan.status === 'queued' || scan.status === 'running' ? 'active' : scan.status;
      day.counts[status]++;
      day.total++;
    }
    return buckets;
  });
  const max = $derived(Math.max(...days.map(day => day.total)));
  const partial = $derived(hasOlder && scans?.length && Date.parse(scans[scans.length - 1].createdAt) >= days[0].date.getTime());

  function describe(counts: (typeof days)[number]['counts']) {
    return statuses.filter(status => counts[status.id]).map(status => `${counts[status.id]} ${status.label.toLowerCase()}`).join(', ');
  }
</script>

<section class="panel" aria-labelledby="scan-volume-title">
  <div class="panel-title">
    <div><h2 id="scan-volume-title">Scan volume</h2><p>By creation day and current status · Last 7 days</p></div>
  </div>
  {#if !scans}
    <div class="compact-empty" role="status">{error ? 'Scan history is unavailable.' : 'Loading scan history…'}</div>
  {:else if !max}
    <p class="compact-empty">No scans or imports in the last 7 days.</p>
  {:else}
    <div class="volume-body">
      {#if partial}<p class="coverage">Based on the latest {scans.length} scans. Older scans may fall within this period.</p>{/if}
      <ul class="volume-plot" aria-hidden="true">
        {#each days as day (day.date.getTime())}
          <li title={`${dateLabel.format(day.date)} · ${describe(day.counts) || 'No scans'}`}>
            <div class="column">
              <strong>{day.total}</strong>
              {#each statuses as status (status.id)}
                {#if day.counts[status.id]}<span class={'bar ' + status.id} style:height={day.counts[status.id] / max * 80 + '%'}></span>{/if}
              {/each}
            </div>
            <span class="day">{weekday.format(day.date)}</span>
          </li>
        {/each}
      </ul>
      <ul class="legend" aria-label="Scan statuses">
        {#each statuses as status (status.id)}
          <li><span class={'bar ' + status.id} aria-hidden="true"></span>{status.label}</li>
        {/each}
      </ul>
      <details class="volume-details">
        <summary>Daily counts</summary>
        <dl>
          {#each days as day (day.date.getTime())}
            <div><dt>{dateLabel.format(day.date)}</dt><dd>{describe(day.counts) || 'No scans'}</dd></div>
          {/each}
        </dl>
      </details>
    </div>
  {/if}
</section>

<style>
  .volume-body { flex: 1; display: flex; flex-direction: column; gap: .85rem; padding: 1rem 1.15rem; }
  .coverage { color: var(--muted); font-size: .78rem; }
  .volume-plot { flex: 1; display: grid; grid-template-columns: repeat(7, minmax(0, 1fr)); gap: .35rem; margin: 0; padding: 0; list-style: none; }
  .volume-plot li { display: grid; grid-template-rows: minmax(6.25rem, 1fr) auto; gap: .38rem; text-align: center; }
  .column { display: flex; flex-direction: column; align-items: center; justify-content: end; border-bottom: 1px solid var(--line); }
  .column strong { flex: none; padding-bottom: .2rem; font: 650 .78rem var(--mono); }
  .column .bar { display: block; flex: none; width: min(55%, 1.65rem); }
  .bar.completed { background: var(--successful); }
  .bar.failed { background: var(--critical); }
  .bar.active { background: var(--accent); }
  .bar.cancelled { background: var(--control-line); }
  .day { color: var(--muted); font-size: var(--text-detail); }
  .legend { display: flex; flex-wrap: wrap; gap: .4rem .85rem; margin: 0; padding: 0; list-style: none; }
  .legend li { display: flex; align-items: center; gap: .35rem; color: var(--muted); font-size: var(--text-detail); }
  .legend .bar { width: .55rem; height: .55rem; border-radius: 2px; }
  .volume-details { color: var(--muted); font-size: .8rem; }
  .volume-details summary { width: fit-content; cursor: pointer; padding-block: .35rem; color: var(--accent-ink); font-weight: 750; }
  .volume-details dl { margin: .35rem 0 0; }
  .volume-details dl div { display: flex; flex-wrap: wrap; justify-content: space-between; column-gap: .65rem; padding-block: .3rem; border-top: 1px solid var(--line); }
  .volume-details dd { margin: 0; }
</style>
