<script lang="ts">
  import { auth } from '#lib/auth.svelte.js';
  import { productName } from '#lib/product.js';
  import { replaceState } from '$app/navigation';
  import { page } from '$app/state';
  import { onMount } from 'svelte';
  import { ArrowUpRight, Download, GitCompareArrows } from '@lucide/svelte';
  import { active, api, apiPage, imageName, message, platforms, post, repositoryName, scannerName, time, type Change, type Comparison, type Observation, type Registry, type Scan, allRegistries } from '#lib/api.js';

  import AdvisoryDetails from '#lib/AdvisoryDetails.svelte';
  import ConfigDialog from '#lib/ConfigDialog.svelte';
  import IssueLink from '#lib/IssueLink.svelte';
  import { findingReportPath, trackerName, type TrackerIssue } from '#lib/tracking.js';

  let scans = $state<Scan[]>([]);
  let registries = $state<Registry[]>([]);
  let mode = $state('reports');
  let acrossRepositories = $state(false);
  let targetSearch = $state('');
  let targetSearchApplied = '';
  let baselines = $state<Scan[]>([]);
  let baselineNext = $state<string | null>(null);
  let baselineLoading = $state(false);
  let suggestedBaseline = $state('');
  let baselineRequest: AbortController | undefined;
  let beforeRef = $state('');
  let afterRef = $state('');
  let beforeRegistry = $state('');
  let afterRegistry = $state('');
  let platform = $state('linux/amd64');
  let waiting = $state<{baseline:string;target:string;publication?:string}>();
  let timer: ReturnType<typeof setTimeout>;
  let baseline = $state('');
  let target = $state('');
  let result = $state<Comparison>();
  let inspected = $state<Observation>();
  let loading = $state(true);
  let paging = $state(false);
  let next = $state<string | null>(null);
  let busy = $state(false);
  let issue = $state('');
  let controller: AbortController;
  let registryRequest = false;
  let detectionFilter = $state<Observation['status'] | ''>('');
  let severityFilter = $state('');
  let fixFilter = $state(false);
  let search = $state('');
  let linkNotice = $state('');
  const severities = ['critical', 'high', 'medium', 'low', 'unknown'];
  const severityOf = (item: Observation) => severities.find(value => value === item.severity?.toLowerCase()) ?? 'unknown';
  const selectedTarget = $derived(scans.find(scan => scan.id === target));
  const selectedBaseline = $derived(baselines.find(scan => scan.id === baseline) ?? scans.find(scan => scan.id === baseline));
  const selectedRepository = $derived(selectedTarget ? repositoryName(selectedTarget.reference) : '');
  const publicationView = $derived(page.url.searchParams.has('publication'));
  const endpoint = '/scans?status=completed';
  const vulnerabilityChanges = {
    Added: { label: 'Newly detected', tone: 'high' },
    Removed: { label: 'No longer detected', tone: 'completed' },
    'Still detected': { label: 'Still detected', tone: 'neutral' }
  } as const;

  const observations = $derived.by(() => {
    const needle = search.trim().toLowerCase();
    return (result?.changes.observations ?? []).filter(item =>
      (!detectionFilter || item.status === detectionFilter) &&
      (!severityFilter || (severityFilter === 'high+'
        ? ['high', 'critical'].includes(severityOf(item)) : severityOf(item) === severityFilter)) &&
      (!fixFilter || item.fixAvailable) &&
      (!needle || item.name.toLowerCase().includes(needle) || item.ecosystem.toLowerCase().includes(needle))
    ).sort((a, b) => severities.indexOf(severityOf(a)) - severities.indexOf(severityOf(b)) || a.name.localeCompare(b.name));
  });

  function comparisonUrl(comparison: Comparison) {
    const params = new URLSearchParams({baseline: comparison.baseline.id, target: comparison.target.id});
    if (comparison.publication) params.set('publication', comparison.publication);
    return '/compare?' + params;
  }

  function showResult(comparison: Comparison) {
    result = comparison;
    if (!publicationView) {
      includeReports([comparison.baseline, comparison.target]);
      baseline = comparison.baseline.id;
      target = comparison.target.id;
      if (page.url.pathname + page.url.search !== comparisonUrl(comparison)) {
        replaceState(comparisonUrl(comparison), page.state);
      }
    }
  }

  function clearResult() {
    result = undefined;
    inspected = undefined;
    detectionFilter = '';
    severityFilter = '';
    fixFilter = false;
    search = '';
    linkNotice = '';
  }

  async function copyComparison(comparison: Comparison) {
    const link = new URL(comparisonUrl(comparison), window.location.origin).href;
    try {
      await navigator.clipboard.writeText(link);
      linkNotice = 'Comparison link copied.';
    } catch {
      linkNotice = link;
    }
  }

  function includeReports(rows: Scan[]) {
    const entries = new Map(scans.map(scan => [scan.id, scan]));
    for (const scan of rows) entries.set(scan.id, scan);
    scans = [...entries.values()].sort((a, b) => b.id.localeCompare(a.id));
  }

  async function loadReports(signal: AbortSignal, cursor?: string) {
    const params = new URLSearchParams({limit:'50'});
    if (targetSearchApplied) params.set('q', targetSearchApplied);
    const history = await apiPage<Scan[]>(endpoint + '&' + params, cursor, {signal});
    if (signal.aborted) return;
    if (!cursor) scans = scans.filter(scan => scan.id === target);
    includeReports(history.items);
    next = history.next;
  }

  async function searchTargets(event: SubmitEvent) {
    event.preventDefault();
    if (paging) return;
    targetSearchApplied = targetSearch.trim();
    paging = true;
    issue = '';
    try { await loadReports(controller.signal); }
    catch (error) { if (!controller.signal.aborted) issue = message(error); }
    finally { paging = false; }
  }

  async function loadBaselines(cursor?: string | null, suggest = false) {
    baselineRequest?.abort();
    const after = selectedTarget;
    if (!after) return;
    const request = baselineRequest = new AbortController();
    const {signal} = request;
    baselineLoading = true;
    if (!cursor) {
      suggestedBaseline = '';
      baselines = scans.filter(scan => scan.id === baseline);
      baselineNext = null;
    }
    const params = new URLSearchParams({platform:after.platform,limit:'50'});
    if (!acrossRepositories) params.set('repository', repositoryName(after.reference));
    try {
      const [history, suggestion] = await Promise.all([
        apiPage<Scan[]>(endpoint + '&' + params, cursor, {signal}),
        suggest && !acrossRepositories
          ? api<{id:string | null}>('/scans/' + after.id + '/previous-version', {signal})
          : undefined,
      ]);
      if (signal.aborted) return;
      const choices = new Map(baselines.map(scan => [scan.id,scan]));
      for (const scan of history.items) {
        if (scan.id !== after.id) choices.set(scan.id,scan);
      }
      if (suggestion?.id && !baseline) {
        const proposed = choices.get(suggestion.id) ?? await findReport(suggestion.id, signal);
        if (signal.aborted) return;
        choices.set(proposed.id, proposed);
        suggestedBaseline = proposed.id;
        baseline = proposed.id;
      }
      baselines = [...choices.values()].sort((a,b) => b.id.localeCompare(a.id));
      baselineNext = history.next;
    } catch (error) {
      if (!signal.aborted) issue = message(error);
    } finally {
      if (!signal.aborted) baselineLoading = false;
    }
  }

  function changeTarget() {
    baseline = '';
    clearResult();
    issue = '';
    void loadBaselines(null, true);
  }

  function reportLabel(scan: Scan): string {
    const repo = repositoryName(scan.reference);
    const version = scan.reference.slice(repo.length);
    const sharedContext = !acrossRepositories && repo === selectedRepository && scan.platform === selectedTarget?.platform;
    const label = sharedContext
      ? version.startsWith(':') ? version.slice(1) : version.startsWith('@') ? version.slice(1, 20) + '…' : imageName(scan.reference)
      : scan.reference + ' · ' + scan.platform;
    return label + ' · ' + time(scan.finishedAt ?? scan.createdAt);
  }

  async function findReport(id: string, signal: AbortSignal) {
    const report = scans.find(scan => scan.id === id) ?? await api<Scan>('/scans/' + encodeURIComponent(id) + '/report/summary', {signal});
    if (report.status !== 'completed') throw new Error('Select a completed scan report.');
    return report;
  }

  onMount(() => {
    controller = new AbortController();
    const {signal} = controller;
    void (async () => {
      try {
        const targetId = page.url.searchParams.get('target');
        const baselineId = page.url.searchParams.get('baseline');
        const publication = page.url.searchParams.get('publication');
        if (page.url.searchParams.has('publication')) {
          if (!publication || !targetId || !baselineId) throw new Error('This publication link is missing a publication or scan ID.');
          waiting = { baseline: baselineId, target: targetId, publication };
          busy = true;
          await check();
          return;
        }
        await loadReports(signal);
        const [after, before] = await Promise.all([
          targetId ? findReport(targetId, signal) : scans[0],
          baselineId ? findReport(baselineId, signal) : undefined
        ]);
        if (!after || signal.aborted) return;
        includeReports(before ? [before, after] : [after]);
        target = after.id;
        if (before) {
          baseline = before.id;
          acrossRepositories = repositoryName(before.reference) !== repositoryName(after.reference);
        }
        await loadBaselines(null, !before);
        if (targetId && baselineId && baseline && target !== baseline) await compareReports();
      } catch (error) {if (!signal.aborted) issue = message(error);}
      finally {if (!signal.aborted) loading = false;}
    })();
    return () => {controller.abort(); baselineRequest?.abort(); clearTimeout(timer);};
  });

  async function loadMoreReports() {
    if (!next || paging) return;
    paging = true; issue = '';
    try {await loadReports(controller.signal, next);}
    catch (error) {if (!controller.signal.aborted) issue = message(error);}
    finally {paging = false;}
  }

  async function showReferences() {
    mode = 'references';
    if (!afterRef && selectedTarget) {
      afterRef = selectedTarget.reference;
      platform = selectedTarget.platform;
    }
    if (registryRequest) return;
    registryRequest = true;
    try {registries = await allRegistries();}
    catch (error) {issue = message(error); registryRequest = false;}
  }

  async function compareReports(event?: SubmitEvent) {
    event?.preventDefault();
    if (!baseline || !target || baseline === target || busy) return;
    busy = true; issue = ''; clearResult();
    try {showResult(await api<Comparison>('/compare?' + new URLSearchParams({baseline,target}), {signal: controller.signal}));}
    catch (error) {if (!controller.signal.aborted) issue = message(error);}
    finally {busy = false;}
  }

  async function check() {
    if (!waiting) return;
    try {
      const ids = waiting;
      const { signal } = controller;
      const [before, after] = await Promise.all([
        api<Scan>('/scans/' + encodeURIComponent(ids.baseline), {signal}),
        api<Scan>('/scans/' + encodeURIComponent(ids.target), {signal})
      ]);
      if (signal.aborted) return;
      if (active(before) || active(after)) {
        timer = setTimeout(check, 2200);
        return;
      }
      if (before.status !== 'completed' || after.status !== 'completed') {
        throw new Error(before.error || after.error || 'A scan failed to complete.');
      }
      const params = new URLSearchParams({baseline: ids.baseline, target: ids.target});
      if (ids.publication) params.set('publication', ids.publication);
      showResult(await api<Comparison>('/compare?' + params, {signal}));
    } catch (error) {
      if (!controller.signal.aborted) issue = message(error);
    }
    waiting = undefined;
    busy = false;
  }

  async function plan(event: SubmitEvent) {
    event.preventDefault();
    busy = true; issue = ''; clearResult(); waiting = undefined;
    try {
      waiting = await api('/compare/plan', post({
        baseline:{reference:beforeRef,registryId:beforeRegistry || null,platform},
        target:{reference:afterRef,registryId:afterRegistry || null,platform},
      }));
      void check();
    } catch (error) {issue = message(error); busy = false;}
  }

  function scannerList(scanners: string[]) {
    return scanners.map(scannerName).join(', ') || 'None';
  }

  function limitedCoverage(comparison: Comparison) {
    return !comparison.scanners.length || comparison.scanners.length < comparison.baselineScanners.length
      || comparison.scanners.length < comparison.targetScanners.length;
  }

  const noSharedScanners = 'Vulnerability changes are unavailable because these reports have no shared scanner results.';

  function linkedIssues(comparison: Comparison, advisory: string): { issue: TrackerIssue; report?: string }[] {
    const before = Object.hasOwn(comparison.baselineIssues, advisory) ? comparison.baselineIssues[advisory] : undefined;
    const after = Object.hasOwn(comparison.targetIssues, advisory) ? comparison.targetIssues[advisory] : undefined;
    if (before && after && before.url !== after.url) {
      return [{issue: before, report: 'Earlier report'}, {issue: after, report: 'Newer report'}];
    }
    const issue = after ?? before;
    return issue ? [{issue}] : [];
  }

  function download(comparison: Comparison) {
    const escape = (value: string) => value.replace(/[\r\n]/g, ' ').replace(/[\\|<>&`*\[\]]/g, character => '\\' + character);
    const lines = ['# Release security changelog', '', '- Platform: ' + comparison.target.platform,
      '- Scanners used for vulnerability comparison: ' + escape(scannerList(comparison.scanners))];
    if (limitedCoverage(comparison)) {
      lines.push('- Earlier report scanners: ' + escape(scannerList(comparison.baselineScanners)),
        '- Newer report scanners: ' + escape(scannerList(comparison.targetScanners)));
    }
    const reports = [
      ['Baseline', comparison.baseline, comparison.baselineDigest],
      ['Target', comparison.target, comparison.targetDigest]
    ] as const;
    for (const [label, scan, digest] of reports) {
      const url = new URL('/scans/' + scan.id, window.location.origin);
      lines.push('- ' + label + ': [' + escape(scan.reference) + '](' + url.href + ') · ' + (scan.finishedAt ?? scan.createdAt)
        + (digest ? ' · `' + digest + '`' : ''));
    }
    lines.push('', comparison.scanners.length
      ? 'Detections describe these scan reports. Scanner or advisory database changes can affect the results.'
      : noSharedScanners, '');
    if (comparison.selected.length) {
      lines.push('## Selected patch advisories', '');
      for (const entry of comparison.selected) {
        lines.push('- ' + escape(entry.id) + ' · ' + (entry.detected ? 'Still detected' : 'No longer detected'));
      }
      lines.push('');
    }
    const detectionSections = comparison.scanners.length ? Object.entries(vulnerabilityChanges) : [];
    for (const [status, change] of detectionSections) {
      const items = comparison.changes.observations.filter(item => item.status === status);
      lines.push('## ' + change.label + ' (' + items.length + ')', '');
      if (items.length) {
        lines.push('| Advisory and package | Ecosystem | Baseline | Target | Linked issue |', '| --- | --- | --- | --- | --- |');
        for (const item of items) {
          const tickets = linkedIssues(comparison, item.advisory).map(({issue, report}) => {
            const title = issue.key || trackerName(issue.tracker) + ' issue';
            const url = issue.url.replaceAll('(', '%28').replaceAll(')', '%29').replaceAll('|', '%7C');
            return (report ? report + ' ' : '') + '[' + escape(title) + '](' + url + ')';
          });
          const details = [item.name, item.ecosystem, item.before.join(', ') || '—', item.after.join(', ') || '—'].map(escape);
          lines.push('| ' + [...details, tickets.join(', ') || '—'].join(' | ') + ' |');
        }
      } else {
        lines.push('None reported.');
      }
      lines.push('');
    }
    lines.push('## Package changes', '');
    if (!comparison.changes.inventoryAvailable) {
      lines.push('Package inventory unavailable in one or both reports.');
    } else if (!comparison.changes.packages.length) {
      lines.push('No package versions changed.');
    } else {
      lines.push('| Package | Ecosystem | Change | Baseline | Target |', '| --- | --- | --- | --- | --- |');
      for (const item of comparison.changes.packages) {
        lines.push('| ' + [item.name, item.ecosystem, item.status, item.before.join(', ') || '—', item.after.join(', ') || '—'].map(escape).join(' | ') + ' |');
      }
    }
    const url = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    const slug = (value: string) => imageName(value).replace(/[^A-Za-z0-9._-]+/g, '-').slice(-64);
    link.download = 'certhia-' + slug(comparison.baseline.reference) + '-to-' + slug(comparison.target.reference)
      + '-' + comparison.target.platform.replaceAll('/', '-') + '-' + comparison.target.id.slice(-8) + '-changelog.md';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 30_000);
  }
</script>

<svelte:head><title>Report comparison · {productName}</title></svelte:head>
<div class="page-heading">
  <div><h1>{publicationView ? 'Published image comparison' : 'Compare image versions'}</h1><p>See which vulnerabilities and packages changed between two versions of an image.</p></div>
  {#if result}
    <div class="filters">
      <button class="button secondary" onclick={() => result && copyComparison(result)}>Copy comparison link</button>
      <button class="button secondary" onclick={() => result && download(result)}><Download size={17} /> Download security changelog</button>
    </div>
  {/if}
</div>
{#if linkNotice}<p class="field-help break" role="status">{linkNotice}</p>{/if}
{#if issue}<div class="notice error" role="alert">{issue}</div>{/if}
{#if publicationView}
  {#if !waiting && !result && !issue}<p role="status">Loading published image scan…</p>{/if}
  {#if waiting}
    <div class="notice success" role="status">Waiting for the <a href={'/scans/' + waiting.target}>published image scan</a>.
      <a href={'/scans/' + waiting.baseline}>Open source report</a>
    </div>
  {:else if issue}
    <a class="button secondary" href="/patches">Back to patch history</a>
  {/if}
{:else}
<div class="tabs">
  <button class:tab-active={mode === 'reports'} aria-pressed={mode === 'reports'} disabled={busy} onclick={() => {mode='reports';}}>Compare saved reports</button>
  {#if auth.operator}<button class:tab-active={mode === 'references'} aria-pressed={mode === 'references'} disabled={busy} onclick={showReferences}>Scan tags or digests</button>{/if}
</div>
{#if mode === 'references'}
  <form class="panel form-panel wide" onsubmit={plan}>
    <p class="field-help">Enter the tags or digests you want to compare. Certhia reuses matching completed scans and queues a scan for any version it still needs.</p>
    <div class="form-grid">
      <fieldset class="field compare-side"><legend>Earlier image</legend>
        <label class="field"><span>Image reference</span><input class="mono" required bind:value={beforeRef} placeholder={selectedRepository ? selectedRepository + ':older-tag' : 'registry.example.com/team/image:v1'} /></label>
        <label class="field"><span>Registry credentials</span><select bind:value={beforeRegistry}><option value="">Anonymous</option>
          {#each registries as registry}<option value={registry.id}>{registry.name}</option>{/each}</select></label>
      </fieldset>
      <fieldset class="field compare-side"><legend>Newer image</legend>
        <label class="field"><span>Image reference</span><input class="mono" required bind:value={afterRef} placeholder="registry.example.com/team/image:v2" /></label>
        <label class="field"><span>Registry credentials</span><select bind:value={afterRegistry}><option value="">Anonymous</option>
          {#each registries as registry}<option value={registry.id}>{registry.name}</option>{/each}</select></label>
      </fieldset>
    </div>
    <label class="field"><span>Platform</span><select bind:value={platform}>{#each platforms as item}<option>{item}</option>{/each}</select></label>
    <div class="actions"><button class="button primary" disabled={busy}><GitCompareArrows size={17} /> {busy ? 'Preparing comparison…' : 'Scan and compare'}</button></div>
  </form>
  {#if waiting}<div class="notice success" role="status">Waiting for the <a href={'/scans/' + waiting.baseline}>baseline</a> and <a href={'/scans/' + waiting.target}>target</a> reports.</div>{/if}
{:else if loading}
  <div class="panel empty" role="status">Loading completed scans…</div>
{:else}
  <section class="panel comparison-picker" aria-label="Choose scan reports">
    <form class="report-search" onsubmit={searchTargets}>
      <label class="field"><span>Find an image</span>
        <input type="search" bind:value={targetSearch} placeholder="Search repository or tag" /></label>
      <button type="submit" class="button secondary" disabled={paging || busy}>Search reports</button>
      {#if next}<button type="button" class="button secondary" disabled={paging || busy} onclick={loadMoreReports}>Load older target reports</button>{/if}
    </form>
    {#if scans.length}
      <form onsubmit={compareReports}>
        <div class="comparison-scope">
          <div class="scope-context">
            {#if selectedTarget}
              {#if !acrossRepositories}<strong class="mono break">{selectedRepository}</strong>{/if}
              <span class="field-help">{selectedTarget.platform}</span>
            {/if}
          </div>
          <label class="inline-check"><input type="checkbox" bind:checked={acrossRepositories} disabled={busy} onchange={changeTarget} /> Compare across repositories</label>
        </div>
        <div class="form-grid report-pair">
          <div class="report-choice">
            <label class="field"><span>Newer report</span>
              <select bind:value={target} required disabled={busy} onchange={changeTarget}>
                <option value="">Choose a newer report</option>
                {#each scans as scan}<option value={scan.id}>{reportLabel(scan)}</option>{/each}
              </select>
            </label>
            {#if selectedTarget}<a class="table-link" href={'/scans/' + selectedTarget.id}>Open newer report</a>{/if}
          </div>
          <div class="report-choice">
            <label class="field"><span>Earlier report</span>
              <select bind:value={baseline} required disabled={busy || baselineLoading || !target} onchange={clearResult}>
                <option value="">{baselineLoading ? 'Loading versions…' : 'Choose an earlier report'}</option>
                {#each baselines as scan}<option value={scan.id}>{reportLabel(scan)}</option>{/each}
              </select>
            </label>
            {#if selectedBaseline}
              <a class="table-link" href={'/scans/' + selectedBaseline.id}>Open earlier report</a>
            {:else if selectedTarget && !baselineLoading && !baselines.length && !baselineNext}
              <p class="field-help">No other completed reports for {acrossRepositories ? selectedTarget.platform : selectedRepository + ' on ' + selectedTarget.platform}.</p>
              {#if auth.operator}<button type="button" class="text-button other-version" onclick={showReferences}>Scan another tag</button>{/if}
            {/if}
            {#if baselineNext}<button type="button" class="text-button other-version" disabled={baselineLoading || busy} onclick={() => loadBaselines(baselineNext)}>Load older versions</button>{/if}
          </div>
        </div>
        <div class="actions">
          {#if baseline && suggestedBaseline === baseline}<p class="field-help">Suggested previous version selected.</p>{/if}
          <button class="button primary" disabled={busy || baselineLoading || !baseline || !target || baseline === target}><GitCompareArrows size={17} /> {busy ? 'Comparing…' : 'Compare reports'}</button>
        </div>
      </form>
    {:else}
      <div class="compact-empty">No completed reports match this search.</div>
    {/if}
  </section>
{/if}
{/if}

{#snippet changes(items: Change[], empty: string)}
  {#if !items.length}
    <div class="compact-empty">{empty}</div>
  {:else}
    <div class="table-wrap"><table>
      <thead><tr><th>Name</th><th>Change</th><th>Baseline</th><th>Target</th></tr></thead>
      <tbody>{#each items as item}
        <tr>
          <td><strong class="mono">{item.name}</strong><small>{item.ecosystem}</small></td>
          <td><span class={'badge change-' + item.status.toLowerCase()}>{item.status}</span></td>
          <td class="mono">{item.before.join(', ') || '—'}</td><td class="mono">{item.after.join(', ') || '—'}</td>
        </tr>
      {/each}</tbody>
    </table></div>
  {/if}
{/snippet}

{#snippet issueLinks(tickets: ReturnType<typeof linkedIssues>)}
  {#each tickets as {issue, report} (issue.url)}
    <div class="comparison-issue">
      {#if report}<small>{report}</small>{/if}
      <IssueLink {issue} />
    </div>
  {/each}
{/snippet}

{#snippet reportEvidence(label: string, scan: Scan, values: string[])}
  <section class="report-evidence">
    <h3>{label}</h3>
    <p class="field-help break">{scan.reference}</p>
    {#if values.length}
      <ul class="mono">
        {#each values as value}<li>{value}</li>{/each}
      </ul>
    {:else}
      <p class="field-help">No detection from the compared scanners.</p>
    {/if}
  </section>
{/snippet}

{#if result}
  {@const comparison = result}
  {@const urgent = comparison.changes.observations.filter(item => item.status === 'Added' && ['critical', 'high'].includes(severityOf(item))).length}
  <section class="panel">
    <div class="panel-title">
      <div><h2>Release security changelog</h2>
        <p><a class="table-link" href={'/scans/' + comparison.baseline.id}>{imageName(comparison.baseline.reference)}</a>
          → <a class="table-link" href={'/scans/' + comparison.target.id}>{comparison.publication ? 'Published scan' : imageName(comparison.target.reference)}</a>
          · {comparison.target.platform}{#if comparison.scanners.length && !limitedCoverage(comparison)} · {scannerList(comparison.scanners)}{/if}</p>
        {#if comparison.publication}<p class="mono break">{comparison.target.reference}</p>{/if}
      </div>
    </div>
    {#if limitedCoverage(comparison)}
      <div class="panel-footer scanner-coverage">
        {#if comparison.scanners.length}
          <p><strong>Vulnerability changes use shared scanner results from {scannerList(comparison.scanners)}.</strong></p>
        {:else}
          <p><strong>{noSharedScanners}</strong></p>
        {/if}
        <dl>
          <div><dt>Earlier report</dt><dd>{scannerList(comparison.baselineScanners)}</dd></div>
          <div><dt>Newer report</dt><dd>{scannerList(comparison.targetScanners)}</dd></div>
        </dl>
      </div>
    {/if}
    {#if comparison.selected.length}
      <div class="panel-footer">
        <h3>Selected patch advisories</h3>
        <ul>
          {#each comparison.selected as entry (entry.id)}
            <li><a class="table-link mono" href={findingReportPath(entry.detected ? comparison.target.id : comparison.baseline.id, entry.id, true)}>{entry.id}</a>
              · {entry.detected ? 'Still detected' : 'No longer detected'}</li>
          {/each}
        </ul>
      </div>
    {/if}
    {#if comparison.scanners.length}
      <div class="panel-footer field-help">Each row pairs an advisory and package. Updates to scanner data can affect detections.</div>
      <div class="panel-footer filters" aria-label="Vulnerability observation filters">
        <button class="button secondary" aria-pressed={!detectionFilter} onclick={() => detectionFilter = ''}>All observations</button>
        {#each Object.keys(vulnerabilityChanges) as key (key)}
          {@const status = key as Observation['status']}
          {@const total = comparison.changes.observations.filter(item => item.status === status).length}
          <button class="button secondary" aria-pressed={detectionFilter === status} onclick={() => detectionFilter = status}>
            {vulnerabilityChanges[status].label} · {total}
          </button>
        {/each}
      </div>
      <div class="panel-footer filters" aria-label="Severity and fix filters">
        <button class="button secondary" aria-pressed={detectionFilter === 'Added' && severityFilter === 'high+'}
          onclick={() => {detectionFilter = 'Added'; severityFilter = 'high+';}}>New high or critical · {urgent}</button>
        <select aria-label="Filter observations by severity" bind:value={severityFilter}>
          <option value="">All severities</option>
          <option value="high+">High or critical</option>
          {#each severities as severity}<option value={severity}>{severity[0].toUpperCase() + severity.slice(1)}</option>{/each}
        </select>
        <label class="inline-check"><input type="checkbox" bind:checked={fixFilter} /> Has reported fix</label>
        <label class="search"><input aria-label="Search comparison findings" placeholder="Search CVEs or packages" bind:value={search} /></label>
        <span class="field-help" role="status">{observations.length} matching pairs</span>
      </div>
      {#if observations.length}
        <div class="table-wrap"><table>
          <thead><tr><th>Advisory and package</th><th>Observation</th><th>Linked issue</th><th>Baseline</th><th>Target</th></tr></thead>
          <tbody>{#each observations as item}
            {@const state = vulnerabilityChanges[item.status]}
            {@const tickets = linkedIssues(comparison, item.advisory)}
            <tr>
              <td><button type="button" class="table-link mono inspect-finding" aria-haspopup="dialog" onclick={() => {inspected = item;}}>{item.name}</button>
                <small>{item.ecosystem}</small></td>
              <td><span class={'badge finding-change ' + state.tone}>{state.label}</span>
                <small><span class={'severity ' + severityOf(item)}>{severityOf(item)}</span></small></td>
              <td>{#if tickets.length}{@render issueLinks(tickets)}{:else}—{/if}</td>
              <td class="mono">{item.before.join(', ') || '—'}</td>
              <td class="mono">{item.after.join(', ') || '—'}</td>
            </tr>
          {/each}</tbody>
        </table></div>
      {:else}
        <div class="compact-empty">No observations in this view.</div>
      {/if}
    {/if}
  </section>
  <section class="panel">
    <div class="panel-title"><div><h2>Package changes</h2></div><span class="badge neutral">{result.changes.packages.length}</span></div>
    {@render changes(result.changes.packages, result.changes.inventoryAvailable ? 'No package versions changed.' : 'One or both reports lack a package inventory.')}
  </section>
  <ConfigDialog id="comparison-finding" title={inspected?.name ?? 'Vulnerability details'} description={inspected?.ecosystem}
    open={!!inspected} dismiss={() => {inspected = undefined;}}>
    {#if inspected}
      {@const state = vulnerabilityChanges[inspected.status]}
      {@const tickets = linkedIssues(comparison, inspected.advisory)}
      <div><span class={'badge finding-change ' + state.tone}>{state.label}</span></div>
      <div class="report-evidence-grid">
        {@render reportEvidence('Earlier report', comparison.baseline, inspected.before)}
        {@render reportEvidence('Newer report', comparison.target, inspected.after)}
      </div>
      {#if tickets.length}
        <section class="observation-issues">
          <h3>Linked issue{tickets.length > 1 ? 's' : ''}</h3>
          {@render issueLinks(tickets)}
        </section>
      {/if}
      <AdvisoryDetails id={inspected.advisory} summaryFallback />
    {/if}
    {#snippet actions()}
      {#if inspected?.before.length}
        <a class="button secondary" href={findingReportPath(comparison.baseline.id, inspected.advisory, true)} target="_blank" rel="noopener noreferrer">Open earlier scan <ArrowUpRight size={15} aria-hidden="true" /></a>
      {/if}
      {#if inspected?.after.length}
        <a class="button secondary" href={findingReportPath(comparison.target.id, inspected.advisory, true)} target="_blank" rel="noopener noreferrer">Open newer scan <ArrowUpRight size={15} aria-hidden="true" /></a>
      {/if}
    {/snippet}
  </ConfigDialog>
{/if}


<style>
  .comparison-picker { max-width: 68rem; }
  .report-search { display: flex; flex-wrap: wrap; align-items: end; gap: .6rem; padding: .9rem 1.15rem; border-bottom: 1px solid var(--line); }
  .report-search .field { flex: 1 1 15rem; max-width: 27rem; }
  .comparison-scope { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: .4rem 1rem; padding: .65rem 1.15rem .1rem; }
  .scope-context { display: flex; flex-wrap: wrap; align-items: baseline; gap: .3rem .65rem; min-width: 0; font-size: var(--text-label); }
  .report-pair { padding: .6rem 1.15rem 1rem; }
  .comparison-picker .actions { padding: .8rem 1.15rem; border-top: 1px solid var(--line); }
  .comparison-picker .actions button { margin-inline-start: auto; }
  .other-version { justify-self: start; min-height: 32px; padding: 0; color: var(--accent-ink); font-size: var(--text-label); }
  .compare-side { gap: .8rem; padding: .85rem; }
  .compare-side legend { padding-inline: .3rem; color: var(--ink); }
  .report-choice { display: grid; align-content: start; gap: .4rem; min-width: 0; }
  .report-choice select { height: 44px; min-height: 44px; white-space: nowrap; overflow: hidden; }
  .report-choice option { white-space: normal; }
  .report-choice .table-link { width: fit-content; font-size: .8rem; }
  .scanner-coverage { display: grid; gap: .65rem; font-size: var(--text-label); }
  .scanner-coverage p, .scanner-coverage dl, .scanner-coverage dd { margin: 0; }
  .scanner-coverage dl { display: flex; flex-wrap: wrap; gap: .4rem 1.5rem; }
  .scanner-coverage dt { color: var(--muted); }
  .finding-change { text-transform: none; }
  .comparison-issue + .comparison-issue { margin-top: .35rem; }
  .comparison-issue small { display: block; margin-top: 0; color: var(--muted); }
  .inspect-finding { padding: 0; border: 0; background: none; text-align: start; overflow-wrap: anywhere; }
  :global(#comparison-finding-title) { overflow-wrap: anywhere; }
  .report-evidence-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 13rem), 1fr)); gap: 1rem; }
  .report-evidence { display: grid; align-content: start; gap: .35rem; padding-block: .65rem; border-block: 1px solid var(--line); }
  .report-evidence h3, .observation-issues h3 { font-size: .9rem; }
  .report-evidence ul { display: grid; gap: .25rem; margin: 0; padding: 0; list-style: none; font-size: var(--text-label); overflow-wrap: anywhere; }
  .observation-issues h3 { margin-bottom: .45rem; }
</style>
