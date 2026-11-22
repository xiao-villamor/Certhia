<script lang="ts">
  import { api, message, scannerName } from './api.js';
  let { scanId }: {scanId: string} = $props();
  type Observation = {advisory: string; package: string; version: string};
  type Scanner = 'trivy' | 'grype' | 'osv';
  type Entry = {status: string; reasons: string[]} & Partial<Record<Scanner, Observation | null>>;
  type Explanation = {agreed: number; autoResolved: number; needsReview: number; scanners?: Scanner[]; differences: Entry[]};
  const path = $derived('/scans/' + scanId + '/report/discrepancies');
  let open = $state(false);
  let retry = $state(0);
  let report = $state<Explanation>();
  let error = $state('');
  let limit = $state(25);
  const scanners = $derived(report?.scanners ?? ['trivy', 'grype'] as Scanner[]);
  $effect(() => {
    void retry;
    if (!open || report) return;
    const controller = new AbortController();
    error = '';
    void api<Explanation>(path, {signal: controller.signal}).then(value => {
      if (!controller.signal.aborted) report = value;
    }).catch(issue => { if (!controller.signal.aborted) error = message(issue); });
    return () => controller.abort();
  });
</script>

<details class="panel scanner-differences" bind:open>
  <summary>Scanner differences</summary>
  {#if open}
    {#if error}
      <p role="alert">{error}</p><button class="button secondary" onclick={() => retry++}>Try again</button>
    {:else if report}
      <div class="comparison-summary">
        <p class="field-help">{scanners.map(scannerName).join(' · ')}</p>
        <p>{report.agreed} agree · {report.autoResolved} automatically reconciled · {report.needsReview} need review</p>
        <a class="table-link" href={'/api' + path} download>Download discrepancy report</a>
      </div>
      {#each report.differences.slice(0, limit) as entry}
        {@const finding = entry.trivy ?? entry.grype ?? entry.osv}
        {#if finding}
          <div class="difference">
            <div><strong>{finding.advisory}</strong> · {finding.package} {finding.version}</div>
            <span class="badge neutral">{entry.status === 'auto_resolved' ? 'Reconciled' : 'Needs review'}</span>
            <p>{entry.reasons.join(' ')}</p>
            <ul aria-label="Scanner evidence">
              {#each scanners as scanner}
                {@const row = entry[scanner]}
                <li><strong>{scannerName(scanner)}</strong>
                  {#if row}{row.advisory} · {row.package} {row.version}{:else}<span class="field-help">No match in this group</span>{/if}
                </li>
              {/each}
            </ul>
          </div>
        {/if}
      {/each}
      {#if limit < report.differences.length}<button class="button secondary" onclick={() => limit += 25}>Show more</button>{/if}
    {:else}<p role="status">Comparing scanner observations…</p>{/if}
  {/if}
</details>

<style>
  .scanner-differences { display: grid; gap: .85rem; }
  summary { cursor: pointer; font-weight: 750; }
  .comparison-summary, .difference { margin-block-start: .8rem; }
  .difference { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: start; gap: .35rem .7rem; padding-top: .75rem; border-top: 1px solid var(--line); }
  .difference p, .difference ul { grid-column: 1 / -1; }
  .difference ul { list-style: none; margin: 0; padding: 0; font-size: var(--text-detail); overflow-wrap: anywhere; }
  .difference li strong { margin-inline-end: .4rem; }
  .comparison-summary a { display: inline-block; margin-block-start: .3rem; }
</style>
