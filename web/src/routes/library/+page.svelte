<script lang="ts">
  import { productName } from '#lib/product.js';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { onDestroy } from 'svelte';
  import { ChevronDown, Search, SlidersHorizontal } from '@lucide/svelte';
  import { apiPage, classifications, imageName, message, shortDigest, type Finding } from '#lib/api.js';
  import { ecosystemGroup, ecosystemTypes, sortEcosystems } from '#lib/ecosystems.js';
  import FindingTracker from '#lib/FindingTracker.svelte';
  import IssueLink from '#lib/IssueLink.svelte';
  import { findingsByImage, trackingTarget, type Advisory } from '#lib/library.js';
  import { trackingStatus, type TrackingTarget } from '#lib/tracking.js';

  const levels = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const filterKeys = ['q', 'status', 'severity', 'fixable', 'ecosystem', 'linked', 'scope'];
  const filters = $derived(page.url.searchParams);
  const selectedPackage = $derived(filters.get('package') ?? '');
  const scope = $derived(filters.get('scope') === 'history' ? 'history' : '');
  const status = $derived(classifications.find(([value]) => value === filters.get('status'))?.[0] ?? '');
  const severity = $derived(levels.find(value => value === filters.get('severity')?.toUpperCase()) ?? '');
  const ecosystem = $derived(filters.get('ecosystem') ?? '');
  const fixable = $derived(filters.get('fixable') === 'true');
  const linked = $derived(filters.get('linked') === 'true');
  const hasFilters = $derived(filterKeys.some(key => filters.has(key)));
  const extraFilters = $derived(Boolean(scope || linked || ecosystem));
  const params = $derived.by(() => {
    const query = new URLSearchParams();
    if (!scope) query.set('latest', 'true');
    if (selectedPackage) query.set('package', selectedPackage);
    const text = filters.get('q')?.trim();
    if (text) query.set('q', text);
    if (severity) query.set('severity', severity);
    if (status) query.set('status', status);
    if (fixable) query.set('fixable', 'true');
    if (linked) query.set('linked', 'true');
    const types = ecosystemTypes(ecosystem);
    if (types) query.set('ecosystems', types);
    return query.toString();
  });

  let input = $state('');
  let searchTimer: ReturnType<typeof setTimeout>;
  let results = $state<Advisory[]>([]);
  let groups = $state<string[]>([]);
  let expanded = $state(false);
  let next = $state<string | null>(null);
  let loading = $state(true);
  let loadingMore = $state(false);
  let error = $state('');
  let notice = $state('');
  let tracking = $state<TrackingTarget>();
  let retry = $state(0);
  let controller: AbortController;
  const findings = $derived(findingsByImage(results).sort((left, right) =>
    levels.indexOf(left.finding.severity) - levels.indexOf(right.finding.severity)
    || left.image.reference.localeCompare(right.image.reference, undefined, {numeric:true})
    || left.finding.id.localeCompare(right.finding.id)));

  $effect(() => {
    input = filters.get('q') ?? '';
  });
  onDestroy(() => clearTimeout(searchTimer));

  function change(changes: Record<string, string>, replaceState = false) {
    clearTimeout(searchTimer);
    const url = new URL(page.url.href);
    for (const [key, value] of Object.entries({q: input.trim(), ...changes})) {
      if (value) url.searchParams.set(key, value);
      else url.searchParams.delete(key);
    }
    if (url.href !== page.url.href) void goto(url, { reset: false, replaceState });
  }
  function search(text: string) {
    input = text;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => change({q: text.trim()}, true), 170);
  }
  function clear() {
    input = '';
    change(Object.fromEntries(filterKeys.map(key => [key, ''])));
  }

  async function load(query: string, signal: AbortSignal, cursor?: string) {
    try {
      const data = await apiPage<Advisory[]>('/vulnerabilities?' + query, cursor, {signal});
      if (signal.aborted) return;
      const merged = new Map<string, Advisory>((cursor ? results : []).map(row => [row.finding.id, row]));
      for (const row of data.items) {
        const previous = merged.get(row.finding.id);
        merged.set(row.finding.id, previous ? {...previous, affected: [...previous.affected, ...row.affected]} : row);
      }
      results = [...merged.values()];
      groups = sortEcosystems([...groups, ...data.items.flatMap(({affected, finding}) =>
        affected.map(row => ecosystemGroup(row.ecosystem ?? finding.ecosystem))).filter(group => ecosystemTypes(group))]);
      next = data.next;
      error = '';
    } catch (issue) {
      if (!signal.aborted) error = message(issue);
    } finally {
      if (!signal.aborted) { loading = false; loadingMore = false; }
    }
  }

  $effect(() => {
    const query = params;
    retry;
    controller = new AbortController();
    const {signal} = controller;
    loading = true;
    loadingMore = false;
    error = '';
    next = null;
    results = [];
    void load(query, signal);
    return () => controller.abort();
  });

  function fixSummary(packages: Finding[]) {
    const versions = [...new Set(packages.map(row => row.fixed).filter(Boolean))];
    if (!versions.length) return 'None reported';
    if (packages.some(row => !row.fixed)) return 'Some packages';
    return versions.length === 1 ? versions[0] : versions.length + ' fixes reported';
  }

  function trackingSaved() {
    tracking = undefined;
    notice = 'Tracking saved.';
    retry += 1;
  }

  function reportPath(scanId: string, finding: string) {
    return '/scans/' + scanId + '?' + new URLSearchParams({finding, from: 'triage', advisoryFilters: filters.toString()});
  }
</script>

<svelte:head><title>Vulnerabilities · {productName}</title></svelte:head>
<FindingTracker target={tracking} dismiss={() => {tracking = undefined;}} onSaved={trackingSaved} />

<div class="page-heading">
  <div><h1>{selectedPackage ? 'Vulnerabilities in ' + selectedPackage : 'Vulnerabilities'}</h1><p>Track fixes and linked issues by image version.</p></div>
  {#if selectedPackage}<a class="button secondary" href="/library">All vulnerabilities</a>{/if}
</div>
{#if notice}<div class="notice success" role="status">{notice}</div>{/if}

<section class="panel vulnerability-panel" aria-label="Vulnerabilities">
  <div class="triage-toolbar">
    <label class="search"><Search size={17} aria-hidden="true" /><input type="search" aria-label="Search vulnerabilities" placeholder="CVE, package, image, or issue key" value={input} oninput={(event) => search(event.currentTarget.value)} /></label>
    <select aria-label="Filter vulnerabilities by status" value={status} onchange={(event) => change({status: event.currentTarget.value})}>
      <option value="">All statuses</option>
      {#each classifications as [value, label]}<option {value}>{label}</option>{/each}
    </select>
    <label class="inline-check fix-filter"><input type="checkbox" checked={fixable} onchange={(event) => change({fixable: event.currentTarget.checked ? 'true' : ''})} /> Fix available</label>
    <button class="button secondary" type="button" aria-controls="extra-filters" aria-expanded={expanded} onclick={() => {expanded = !expanded;}}>
      <SlidersHorizontal size={16} aria-hidden="true" /> Filters{extraFilters ? ' (active)' : ''}
    </button>
  </div>

  <div id="extra-filters" class="extra-filters" hidden={!expanded}>
    {#if groups.length || ecosystem}
      <label class="field"><span>Ecosystem</span><select value={ecosystem} onchange={(event) => change({ecosystem: event.currentTarget.value})}>
        <option value="">All ecosystems</option>
        {#each sortEcosystems([...groups, ...(ecosystem ? [ecosystem] : [])]) as group (group)}<option value={group}>{group}</option>{/each}
      </select></label>
    {/if}
    <label class="field"><span>Report scope</span><select value={scope} onchange={(event) => change({scope: event.currentTarget.value})}>
      <option value="">Latest scanned tags</option>
      <option value="history">Include older digests</option>
    </select></label>
    <label class="inline-check"><input type="checkbox" checked={linked} onchange={(event) => change({linked: event.currentTarget.checked ? 'true' : ''})} /> Linked issues only</label>
  </div>
  <div class="triage-filters">
    <div class="filters severity-filters" role="group" aria-label="Filter vulnerabilities by severity">
      {#each levels as level (level)}
        <button type="button" class="severity-filter" aria-pressed={severity === level} onclick={() => change({severity: level.toLowerCase()})}>{level ? level[0].toUpperCase() + level.slice(1).toLowerCase() : 'All severities'}</button>
      {/each}
    </div>
    <div class="result-summary" role="status">
      {#if !loading && results.length}<span>{findings.length}{next ? '+' : ''} {findings.length === 1 ? 'finding' : 'findings'}</span>{/if}
      {#if hasFilters && (loading || results.length || error)}<button type="button" class="text-button" onclick={clear}>Clear filters</button>{/if}
    </div>
  </div>

  {#if error}<div class="compact-empty" role="alert">{error} <button class="text-button" onclick={() => {retry += 1;}}>Retry</button></div>{/if}
  {#if loading}<div class="empty" role="status">Loading vulnerabilities…</div>
  {:else if !results.length && !error}
    <div class="empty">
      <h2>{hasFilters || selectedPackage ? 'No matching vulnerabilities' : 'No vulnerabilities in the latest scanned tags'}</h2>
      {#if hasFilters}<button type="button" class="button secondary" onclick={clear}>Clear filters</button>
      {:else if !selectedPackage}<button type="button" class="button secondary" onclick={() => change({scope: 'history'})}>Check scan history</button>{/if}
    </div>
  {:else if results.length}
    <div class="table-wrap">
      <!-- svelte-ignore a11y_no_redundant_roles (Explicit table roles preserve semantics when the responsive layout changes display.) -->
      <table class="vulnerability-table" role="table" aria-label="Vulnerability results">
        <thead>
          <tr><th scope="col">Image version</th><th scope="col">Advisory</th><th scope="col">Reported fix</th><th scope="col">Tracking</th><th scope="col">Linked issue</th></tr>
        </thead>
        <!-- svelte-ignore a11y_no_redundant_roles (The body uses block layout at narrow widths.) -->
        <tbody role="rowgroup">
          {#each findings as row (row.key)}
            {@const {image, finding, packages} = row}
            {@const names = [...new Set(packages.map(pkg => pkg.package))]}
            <!-- svelte-ignore a11y_no_redundant_roles (Rows use grid layout at narrow widths.) -->
            <tr role="row">
              <td class="image-cell" role="cell">
                <a class="table-link mono" href={reportPath(image.scanId, finding.id)} title={image.reference}>{imageName(image.reference)}</a>
                <small>{image.reference.includes('/') ? image.reference.split('/')[0] + ' · ' : ''}{image.platform}</small>
                {#if image.digest}<small title={image.digest} class="mono">{shortDigest(image.digest)}</small>{/if}
              </td>
              <td class="finding-cell" role="cell">
                <div class="advisory-cell">
                  <a class="table-link mono" href={'/library/' + encodeURIComponent(finding.id) + (filters.size ? '?' + filters : '')}>{finding.id}</a>
                  <span class={'severity ' + finding.severity.toLowerCase()}>{finding.severity.toLowerCase()}</span>
                </div>
                <small>{names.slice(0, 3).join(', ')}{names.length > 3 ? ' +' + (names.length - 3) : ''}</small>
              </td>
              <td class="fix-cell" role="cell"><span class="mobile-label" aria-hidden="true">Reported fix</span>{fixSummary(packages)}</td>
              <td class="tracking-cell" role="cell">
                <span class="mobile-label" aria-hidden="true">Tracking</span>
                <button class="status-chip" data-status={image.status ?? 'open'} type="button" aria-haspopup="dialog"
                  aria-label={'Review ' + finding.id + ' on ' + image.reference + ' (' + image.platform + ')'}
                  onclick={() => {notice = ''; tracking = trackingTarget(row);}}>
                  {trackingStatus(image.status)} <ChevronDown size={13} aria-hidden="true" />
                </button>
              </td>
              <td class="issue-cell" class:no-issue={!image.issue} role="cell">
                <span class="mobile-label" aria-hidden="true">Linked issue</span>
                {#if image.issue}<IssueLink issue={image.issue} />{:else}<span class="field-help">—</span>{/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <div class="panel-footer results-footer">
      <span>{findings.length} {findings.length === 1 ? 'finding' : 'findings'}{next ? ' loaded' : ''} · {scope ? 'Scan history' : 'Latest scanned tags'}</span>
      {#if next}<button class="button secondary" type="button" disabled={loadingMore} onclick={() => {
        if (next && !loadingMore) { loadingMore = true; void load(params, controller.signal, next); }
      }}>{loadingMore ? 'Loading…' : 'Load more'}</button>{/if}
    </div>
  {/if}
</section>

<style>
  .vulnerability-panel { container-type: inline-size; }
  .triage-toolbar, .extra-filters, .triage-filters { display: flex; flex-wrap: wrap; align-items: center; gap: .55rem .75rem; padding: .8rem 1.15rem; }
  .triage-toolbar .search { flex: 1 1 17rem; }
  .triage-toolbar .search :global(input) { width: 100%; max-width: none; }
  .fix-filter { min-height: 40px; }
  .extra-filters { align-items: end; background: var(--canvas); border-top: 1px solid var(--line); }
  .extra-filters[hidden] { display: none; }
  .extra-filters .inline-check { min-height: 40px; }
  .triage-filters { justify-content: space-between; padding-block: .48rem .72rem; border-bottom: 1px solid var(--line); }
  .severity-filters { gap: .3rem; }
  .severity-filter { min-height: 34px; padding: .32rem .65rem; border: 1px solid transparent; border-radius: var(--radius); background: transparent; color: var(--muted); font: inherit; font-size: .82rem; font-weight: 650; }
  .severity-filter:hover { background: var(--inset); color: var(--ink); }
  .severity-filter[aria-pressed="true"] { color: var(--accent-ink); border-color: var(--line); background: var(--accent-soft); }
  .vulnerability-table th:first-child, .vulnerability-table th:nth-child(2) { width: 26%; }
  .vulnerability-table td { vertical-align: top; }
  .tracking-cell button { max-width: 100%; white-space: normal; text-align: start; }
  .tracking-cell button :global(svg) { flex: none; }
  .mobile-label { display: none; }
  .advisory-cell { display: flex; align-items: center; flex-wrap: wrap; gap: .32rem .52rem; }
  .result-summary { display: flex; align-items: center; gap: .85rem; margin-inline-start: auto; color: var(--muted); font-size: .8rem; font-weight: 700; }
  .result-summary .text-button { color: var(--accent-ink); font-size: .8rem; }
  .results-footer { justify-content: space-between; font-size: .78rem; color: var(--muted); }
  @media (max-width: 540px) {
    .triage-toolbar, .triage-filters, .extra-filters { padding-inline: .75rem; }
  }
  @container (max-width: 47rem) {
    .vulnerability-table, .vulnerability-table tbody { display: block; }
    .vulnerability-table :is(thead, .no-issue) { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
    .vulnerability-table tbody tr {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      align-items: start;
      gap: .75rem 1rem;
      padding: 1rem;
    }
    .vulnerability-table tbody tr + tr { border-top: 1px solid var(--line); }
    .vulnerability-table td { display: block; padding: 0; border: 0; }
    .image-cell, .finding-cell, .issue-cell { grid-column: 1 / -1; }
    .image-cell > a { font-size: .9375rem; }
    .mobile-label { display: block; margin-bottom: .23rem; color: var(--muted); font-size: var(--text-detail); font-weight: 700; }
    .tracking-cell button { min-height: 44px; }
  }
</style>
