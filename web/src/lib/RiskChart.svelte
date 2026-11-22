<script lang="ts">
  import type { Scan } from './api.js';
  let { scans, recentError, recentCursor }:
    { scans: Scan[] | undefined; recentError: string; recentCursor: string | null } = $props();
  let windowDays = $state(30);
  const points = $derived.by(() => {
    const end = Date.now();
    const duration = windowDays * 86400000;
    return (scans ?? []).filter(scan => scan.status === 'completed' && scan.counts
      && end - Date.parse(scan.createdAt) <= duration).map(scan => {
      const counts = scan.counts!;
      const risk = Math.min(100, counts.critical*12+counts.high*7+counts.medium*3+counts.low);
      const x = Math.max(1, Math.min(99, 100-(end-Date.parse(scan.createdAt))/duration*100));
      return {scan,risk,x};
    });
  });
</script>
<section class="panel">
  <div class="panel-title"><div><h2>Scan risk over time</h2><p>Severity-weighted score{recentCursor && scans ? ` · latest ${scans.length} scans` : ''}</p></div>
    <select aria-label="Risk chart period" bind:value={windowDays}><option value={7}>Last 7 days</option><option value={30}>Last 30 days</option><option value={90}>Last 90 days</option></select>
  </div>
  {#if !scans}
    <div class="compact-empty" role="status">{recentError ? 'Scan history is unavailable.' : 'Loading scan history…'}</div>
  {:else if points.length}
    <div class="risk-layout">
      <div class="risk-labels"><span>100</span><span>75</span><span>50</span><span>25</span><span>0</span></div>
      <div class="risk-plot">
        {#each points as point (point.scan.id)}
          <a href={'/scans/' + point.scan.id} style:left={point.x + '%'} style:bottom={point.risk + '%'}
            class:high-risk={point.risk >= 75} title={point.scan.reference + ' · Risk ' + point.risk} aria-label={point.scan.reference + ', risk ' + point.risk}></a>
        {/each}
      </div>
      <div class="risk-period"><span>{windowDays} days ago</span><span>Today</span></div>
    </div>
  {:else}<div class="compact-empty">{scans.length ? 'No completed reports in this period.' : 'Complete a scan to see its risk score.'}</div>{/if}
</section>
