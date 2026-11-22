<script lang="ts">
  import { auth } from '#lib/auth.svelte.js';
  import { productName } from '#lib/product.js';
  import { page } from '$app/state';
  import { onMount } from 'svelte';
  import { Download, GitCompareArrows } from '@lucide/svelte';
  import { active, api, apiPage, imageName, message, platforms, post, time, type Change, type Comparison, type Observation, type Registry, type Scan, allRegistries } from '#lib/api.js';

  import IssueLink from '#lib/IssueLink.svelte';
  import { findingReportPath } from '#lib/tracking.js';

  let scans = $state<Scan[]>([]);
  let registries = $state<Registry[]>([]);
  let mode = $state('reports');
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
  let loading = $state(true);
  let paging = $state(false);
  let next = $state<string | null>(null);
  let busy = $state(false);
  let issue = $state('');
  let controller: AbortController;
  let registryRequest = false;
  let detectionFilter = $state<Observation['status'] | ''>('');
  const selectedTarget = $derived(scans.find(scan => scan.id === target));
  const selectedBaseline = $derived(scans.find(scan => scan.id === baseline));
  const publicationView = $derived(page.url.searchParams.has('publication'));
  const endpoint = '/scans?status=completed';
  const vulnerabilityChanges = {
    Added: { label: 'Newly detected', tone: 'high' },
    Removed: { label: 'No longer detected', tone: 'completed' },
    'Still detected': { label: 'Still detected', tone: 'neutral' }
  } as const;

  function includeReports(rows: Scan[]) {
    const entries = new Map(scans.map(scan => [scan.id, scan]));
    for (const scan of rows) entries.set(scan.id, scan);
    scans = [...entries.values()].sort((a, b) => b.id.localeCompare(a.id));
  }

  async function loadReports(signal: AbortSignal, cursor?: string) {
    const history = await apiPage<Scan[]>(endpoint, cursor, {signal});
    if (!signal.aborted) { includeReports(history.items); next = history.next; }
  }

  async function findReport(id: string, signal: AbortSignal) {
    const report = scans.find(scan => scan.id === id) ?? await api<Scan>('/scans/' + encodeURIComponent(id), {signal});
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
        if (before) baseline = before.id;
        else if (targetId) {
          const previous = await api<{id: string | null}>('/scans/' + after.id + '/previous', {signal});
          if (previous.id) {
            const report = await findReport(previous.id, signal);
            if (signal.aborted) return;
            includeReports([report]);
            baseline = report.id;
          }
        }
        if (targetId && baseline && target !== baseline) await compareReports();
      } catch (error) {if (!signal.aborted) issue = message(error);}
      finally {if (!signal.aborted) loading = false;}
    })();
    return () => {controller.abort(); clearTimeout(timer);};
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
    if (registryRequest) return;
    registryRequest = true;
    try {registries = await allRegistries();}
    catch (error) {issue = message(error); registryRequest = false;}
  }

  async function compareReports(event?: SubmitEvent) {
    event?.preventDefault();
    if (!baseline || !target || baseline === target || busy) return;
    busy = true; issue = ''; result = undefined; detectionFilter = '';
    try {result = await api('/compare?' + new URLSearchParams({baseline,target}), {signal: controller.signal});}
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
      result = await api('/compare?' + params, {signal});
    } catch (error) {
      if (!controller.signal.aborted) issue = message(error);
    }
    waiting = undefined;
    busy = false;
  }

  async function plan(event: SubmitEvent) {
    event.preventDefault();
    busy = true; issue = ''; result = undefined; waiting = undefined; detectionFilter = '';
    try {
      waiting = await api('/compare/plan', post({
        baseline:{reference:beforeRef,registryId:beforeRegistry || null,platform},
        target:{reference:afterRef,registryId:afterRegistry || null,platform},
      }));
      void check();
    } catch (error) {issue = message(error); busy = false;}
  }

  function download(comparison: Comparison) {
    const escape = (value: string) => value.replace(/[\r\n]/g, ' ').replace(/[\\|<>&`*\[\]]/g, character => '\\' + character);
    const lines = ['# Release security changelog', '', '- Platform: ' + comparison.target.platform,
      '- Vulnerability scanners: ' + comparison.scanners.map(escape).join(', ')];
    const reports = [
      ['Baseline', comparison.baseline, comparison.baselineDigest],
      ['Target', comparison.target, comparison.targetDigest]
    ] as const;
    for (const [label, scan, digest] of reports) {
      const url = new URL('/scans/' + scan.id, window.location.origin);
      lines.push('- ' + label + ': [' + escape(scan.reference) + '](' + url.href + ') · ' + (scan.finishedAt ?? scan.createdAt)
        + (digest ? ' · `' + digest + '`' : ''));
    }
    lines.push('', 'Detections describe these scan reports. Scanner or advisory database changes can affect the results.', '');
    if (comparison.selected.length) {
      lines.push('## Selected patch advisories', '');
      for (const entry of comparison.selected) {
        lines.push('- ' + escape(entry.id) + ' · ' + (entry.detected ? 'Still detected' : 'No longer detected'));
      }
      lines.push('');
    }
    for (const [status, change] of Object.entries(vulnerabilityChanges)) {
      const items = comparison.changes.observations.filter(item => item.status === status);
      lines.push('## ' + change.label + ' (' + items.length + ')', '');
      if (items.length) {
        lines.push('| Advisory and package | Ecosystem | Baseline | Target |', '| --- | --- | --- | --- |');
        for (const item of items) {
          lines.push('| ' + [item.name, item.ecosystem, item.before.join(', ') || '—', item.after.join(', ') || '—'].map(escape).join(' | ') + ' |');
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
    link.download = 'release-security-changelog.md';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 30_000);
  }
</script>

<svelte:head><title>Report comparison · {productName}</title></svelte:head>
<div class="page-heading">
  <div><h1>{publicationView ? 'Published image comparison' : 'Report comparison'}</h1><p>Review vulnerability observations and package version changes between reports.</p></div>
  {#if result}<button class="button secondary" onclick={() => result && download(result)}><Download size={17} /> Download security changelog</button>{/if}
</div>
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
  <button class:tab-active={mode === 'reports'} aria-pressed={mode === 'reports'} disabled={busy} onclick={() => {mode='reports';}}>Completed reports</button>
  {#if auth.operator}<button class:tab-active={mode === 'references'} aria-pressed={mode === 'references'} disabled={busy} onclick={showReferences}>Image references</button>{/if}
</div>
{#if mode === 'references'}
  <form class="panel form-panel wide" onsubmit={plan}>
    <div class="form-grid">
      <fieldset class="field compare-side"><legend>Baseline image</legend>
        <label class="field"><span>Image reference</span><input class="mono" required bind:value={beforeRef} placeholder="registry.example.com/team/image:v1" /></label>
        <label class="field"><span>Registry credentials</span><select bind:value={beforeRegistry}><option value="">Anonymous</option>
          {#each registries as registry}<option value={registry.id}>{registry.name}</option>{/each}</select></label>
      </fieldset>
      <fieldset class="field compare-side"><legend>Target image</legend>
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
{:else if scans.length < 2}
  <div class="panel empty">
    <span class="empty-icon"><GitCompareArrows size={26} strokeWidth={1.5} /></span>
    <h3>Two completed scans are required</h3>
    <p>Scan two images or import their Trivy reports to compare them.</p>
    {#if auth.operator}<a class="button primary" href="/scans/new">New scan</a>{/if}
  </div>
{:else}
  <form class="panel form-panel wide" onsubmit={compareReports}>
    <div class="form-grid">
      <div class="report-choice"><label class="field"><span>Baseline</span><select bind:value={baseline} required disabled={busy} onchange={() => { result = undefined; }}>
        <option value="">Choose a baseline</option>
        {#each scans as scan}<option value={scan.id}>{scan.reference} · {scan.platform} · {time(scan.createdAt)}</option>{/each}
      </select></label>{#if selectedBaseline}<a class="table-link" href={'/scans/' + selectedBaseline.id}>Open baseline report</a>{/if}</div>
      <div class="report-choice"><label class="field"><span>Target</span><select bind:value={target} required disabled={busy} onchange={() => { result = undefined; }}>
        <option value="">Choose a target</option>
        {#each scans as scan}<option value={scan.id}>{scan.reference} · {scan.platform} · {time(scan.createdAt)}</option>{/each}
      </select></label>{#if selectedTarget}<a class="table-link" href={'/scans/' + selectedTarget.id}>Open target report</a>{/if}</div>
    </div>
    <div class="actions">
      {#if next}<button type="button" class="button secondary" disabled={paging || busy} onclick={loadMoreReports}>{paging ? 'Loading…' : 'Load older reports'}</button>{/if}
      <button class="button primary" disabled={busy || !baseline || !target || baseline === target}><GitCompareArrows size={17} /> {busy ? 'Comparing…' : 'Compare reports'}</button>
    </div>
  </form>
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

{#if result}
  {@const comparison = result}
  {@const observations = comparison.changes.observations.filter(item => !detectionFilter || item.status === detectionFilter)}
  <section class="panel">
    <div class="panel-title">
      <div><h2>Release security changelog</h2>
        <p><a class="table-link" href={'/scans/' + comparison.baseline.id}>{imageName(comparison.baseline.reference)}</a>
          → <a class="table-link" href={'/scans/' + comparison.target.id}>{comparison.publication ? 'Published scan' : imageName(comparison.target.reference)}</a>
          · {comparison.target.platform} · {comparison.scanners.join(', ')}</p>
        {#if comparison.publication}<p class="mono break">{comparison.target.reference}</p>{/if}
      </div>
    </div>
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
    {#if observations.length}
      <div class="table-wrap"><table>
        <thead><tr><th>Advisory and package</th><th>Observation</th><th>Baseline</th><th>Target</th></tr></thead>
        <tbody>{#each observations as item}
          {@const state = vulnerabilityChanges[item.status]}
          {@const beforeIssue = Object.hasOwn(comparison.baselineIssues, item.advisory) ? comparison.baselineIssues[item.advisory] : undefined}
          {@const afterIssue = Object.hasOwn(comparison.targetIssues, item.advisory) ? comparison.targetIssues[item.advisory] : undefined}
          <tr>
            <td><a class="table-link mono" href={findingReportPath(item.status === 'Removed' ? comparison.baseline.id : comparison.target.id, item.advisory, true)}>{item.name}</a>
              <small>{item.ecosystem}</small></td>
            <td><span class={'badge finding-change ' + state.tone}>{state.label}</span></td>
            <td class="mono">{item.before.join(', ') || '—'}{#if item.before.length && beforeIssue}<small><IssueLink issue={beforeIssue} /></small>{/if}</td>
            <td class="mono">{item.after.join(', ') || '—'}{#if item.after.length && afterIssue}<small><IssueLink issue={afterIssue} /></small>{/if}</td>
          </tr>
        {/each}</tbody>
      </table></div>
    {:else}
      <div class="compact-empty">No observations in this view.</div>
    {/if}
  </section>
  <section class="panel">
    <div class="panel-title"><div><h2>Package changes</h2></div><span class="badge neutral">{result.changes.packages.length}</span></div>
    {@render changes(result.changes.packages, result.changes.inventoryAvailable ? 'No package versions changed.' : 'One or both reports lack a package inventory.')}
  </section>
{/if}


<style>
  .compare-side { gap: .8rem; padding: .85rem; }
  .compare-side legend { padding-inline: .3rem; color: var(--ink); }
  .report-choice { display: grid; align-content: start; gap: .4rem; min-width: 0; }
  .report-choice .table-link { width: fit-content; font-size: .8rem; }
  .finding-change { text-transform: none; }
</style>
