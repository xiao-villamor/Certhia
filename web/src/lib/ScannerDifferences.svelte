<script lang="ts">
  import { scannerName } from './api.js';

  import AutoPage from './AutoPage.svelte';
  import { ReportPages } from './report-pages.svelte.js';

  let { scanId, completedScanners, incomplete = false, onFinding, active }:
    {scanId: string; completedScanners: string[]; incomplete?: boolean; onFinding: (advisory: string) => void; active: boolean} = $props();
  type Observation = {advisory: string; id?: string; aliases?: string[]; package: string; version: string; severity?: string; fixes?: string[]};
  type ResultStatus = 'auto_resolved' | 'needs_review';
  type Entry = {status: ResultStatus; reasons: string[]} & Partial<Record<string, Observation | null | string | string[]>>;
  type Summary = {agreed: number; autoResolved: number; needsReview: number; target?: string; scanners?: string[]};
  type Page = {items: Entry[]; nextCursor: string | null; summary: Summary};
  const pages = new ReportPages<Entry, Page>();
  const path = $derived('/scans/' + scanId + '/report/discrepancies');
  let filter = $state<ResultStatus | ''>('');
  let query = $state('');
  let report = $state<Summary>();
  $effect(() => { if (pages.first?.summary) report = pages.first.summary; });
  const scanners = $derived(report?.scanners?.length ? report.scanners : completedScanners);

  function scannerEvidence(entry: Entry, scanner: string): Observation | undefined {
    const value = entry[scanner];
    return value && typeof value === 'object' && !Array.isArray(value) ? value : undefined;
  }

  $effect(() => {
    const params = new URLSearchParams({limit:'10'});
    if (filter) params.set('status', filter);
    const term = query.trim();
    if (term) params.set('q', term);
    return pages.open('/scans/' + scanId + '/report/scanner-differences?' + params, term ? 180 : 0);
  });
</script>

<section class="scanner-differences" aria-labelledby="scanner-differences-title">
  <header class="difference-heading">
    <h3 id="scanner-differences-title">Scanner differences</h3>
    <small>{scanners.map(scannerName).join(' · ')}</small>
  </header>
  {#if report}
    <div class="comparison-summary">
      <div class="findings-counts" aria-label="Comparison totals">
        <span><strong>{report.agreed}</strong> agreed</span>
        <span><strong>{report.autoResolved}</strong> automatically reconciled</span>
        <span><strong>{report.needsReview}</strong> {report.needsReview === 1 ? 'needs review' : 'need review'}</span>
      </div>
      <a class="button secondary" href={'/api' + path} data-sveltekit-reload>Download discrepancy report</a>
    </div>
    {#if report.target}<p class="field-help">Comparison input · {report.target}</p>{/if}
    {#if incomplete}<p class="field-help">This scan is incomplete. The comparison covers the vulnerability reports that finished.</p>{/if}
    {#if !report.autoResolved && !report.needsReview}
      <p class="field-help" role="status">{report.agreed ? 'No differences in the recorded observations.' : 'No vulnerability observations were available to compare.'}</p>
    {:else}
      <div class="filters difference-filters" aria-label="Filter scanner differences">
        <button type="button" class="button secondary" aria-pressed={filter === ''} onclick={() => filter = ''}>All differences</button>
        <button type="button" class="button secondary" aria-pressed={filter === 'needs_review'} onclick={() => filter = 'needs_review'}>Needs review</button>
        <button type="button" class="button secondary" aria-pressed={filter === 'auto_resolved'} onclick={() => filter = 'auto_resolved'}>Reconciled</button>
        <label class="search"><input aria-label="Search scanner differences" placeholder="Search CVEs or packages" bind:value={query} /></label>
      </div>
      {#each pages.items as entry}
        {@const finding = scanners.map(scanner => scannerEvidence(entry, scanner)).find(Boolean)}
        {@const severityOnly = entry.reasons.length === 1 && entry.reasons[0].startsWith('Severity differs:')}
        {#if finding}
          <article class="difference">
            <header>
              <div><strong class="mono">{finding.advisory}</strong> · {finding.package} {finding.version}</div>
              <span class={'badge ' + (entry.status === 'auto_resolved' ? 'completed' : 'high')}>{severityOnly ? 'Severity only' : entry.status === 'auto_resolved' ? 'Reconciled' : 'Needs review'}</span>
            </header>
            {#if severityOnly}
              <p class="field-help">The scanners agree on this finding. {finding.fixes?.length ? `They report the same fix ${finding.fixes.join(', ')} and assign different severities.` : 'They assign different severities and none reports a fix.'}</p>
            {:else if entry.reasons.length}
              <ul class="reasons">{#each entry.reasons as reason}<li>{reason}</li>{/each}</ul>
            {/if}
            <ul class="engine-evidence" aria-label="Scanner evidence">
              {#each scanners as scanner (scanner)}
                {@const row = scannerEvidence(entry, scanner)}
                <li>
                  <strong>{scannerName(scanner)}</strong>
                  {#if row}
                    <span class="mono">{row.id || row.advisory} · {row.package} {row.version}</span>
                    {#if row.aliases?.length}<small>Aliases · {row.aliases.join(', ')}</small>{/if}
                    <small>{row.severity || 'Severity unavailable'} · {row.fixes?.length ? 'Reported fix ' + row.fixes.join(', ') : 'No fix reported'}</small>
                  {:else}
                    <span class="field-help">No matching observation in this group</span>
                  {/if}
                </li>
              {/each}
            </ul>
            <button class="text-button linked-finding" type="button" aria-label={'Find ' + finding.advisory + ' in findings'} onclick={() => onFinding(finding.advisory)}>Find in report</button>
          </article>
        {/if}
      {:else}{#if !pages.busy && !pages.error}<p class="field-help" role="status">No differences match the filters.</p>{/if}{/each}
    {/if}
  {/if}
  <AutoPage busy={pages.busy} more={!!pages.next} error={pages.error} label="scanner differences" load={() => pages.more()} {active} />
</section>

<style>
  .scanner-differences { padding: .85rem clamp(.75rem, 2.5vw, 1.15rem); }
  .difference-heading { display: flex; flex-wrap: wrap; align-items: baseline; gap: .25rem .9rem; padding-block-end: .7rem; border-bottom: 1px solid var(--line); }
  .difference-heading small { color: var(--muted); font-size: var(--text-detail); font-weight: 550; }
  .comparison-summary, .difference header { display: flex; flex-wrap: wrap; gap: .5rem 1rem; align-items: center; justify-content: space-between; }
  .comparison-summary, .difference-filters, .scanner-differences > p { margin-block-start: .75rem; }
  .findings-counts { display: flex; flex-wrap: wrap; gap: .35rem .9rem; font-size: var(--text-label); }
  .difference-filters button[aria-pressed='true'] { border-color: var(--accent-ink); color: var(--accent-ink); background: var(--accent-soft); }
  .difference { display: grid; gap: .5rem; margin-top: .85rem; padding-top: .85rem; border-top: 1px solid var(--line); overflow-wrap: anywhere; }
  .reasons { margin: 0; padding-inline-start: 1.15rem; font-size: var(--text-label); }
  .engine-evidence { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 11rem), 1fr)); gap: .5rem; list-style: none; margin: 0; padding: 0; }
  .engine-evidence li { display: grid; align-content: start; gap: .2rem; padding: .55rem; border: 1px solid var(--line); border-radius: var(--radius); font-size: var(--text-detail); }
  .engine-evidence small { color: var(--muted); font-size: inherit; }
  .linked-finding { justify-self: start; min-height: 32px; padding: .2rem 0; color: var(--accent-ink); font-size: var(--text-detail); }
</style>
