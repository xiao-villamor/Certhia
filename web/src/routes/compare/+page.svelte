<script lang="ts">
  import { auth } from '#lib/auth.svelte.js';
  import { productName } from '#lib/product.js';
  import { page } from '$app/state';
  import { onMount } from 'svelte';
  import { Download, GitCompareArrows } from '@lucide/svelte';
  import { active, api, apiPage, imageName, message, platforms, post, repositoryName, time, type Change, type Comparison, type Registry, type Scan, allRegistries } from '#lib/api.js';

  let scans = $state<Scan[]>([]);
  let registries = $state<Registry[]>([]);
  let mode = $state('reports');
  let beforeRef = $state('');
  let afterRef = $state('');
  let beforeRegistry = $state('');
  let afterRegistry = $state('');
  let platform = $state('linux/amd64');
  let waiting = $state<{baseline:string;target:string}>();
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
  const selectedTarget = $derived(scans.find(scan => scan.id === target));
  const selectedBaseline = $derived(scans.find(scan => scan.id === baseline));
  const endpoint = '/scans?status=completed';
  const vulnerabilityChanges = {
    Added: { label: 'Newly detected', tone: 'high' },
    Removed: { label: 'No longer detected', tone: 'completed' },
    Changed: { label: 'Changed', tone: 'neutral' }
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
          const params = new URLSearchParams({ status: 'completed', platform: after.platform, repository: repositoryName(after.reference), limit: '1' });
          const {items} = await apiPage<Scan[]>('/scans?' + params, after.id, {signal});
          if (signal.aborted) return;
          includeReports(items);
          baseline = items[0]?.id ?? '';
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
    busy = true; issue = ''; result = undefined;
    try {result = await api('/compare?' + new URLSearchParams({baseline,target}), {signal: controller.signal});}
    catch (error) {if (!controller.signal.aborted) issue = message(error);}
    finally {busy = false;}
  }

  async function check() {
    if (!waiting) return;
    try {
      const ids = waiting;
      const [before, after] = await Promise.all([api<Scan>('/scans/' + ids.baseline),api<Scan>('/scans/' + ids.target)]);
      if (active(before) || active(after)) {
        timer = setTimeout(check, 2200);
        return;
      }
      if (before.status !== 'completed' || after.status !== 'completed') {
        throw new Error(before.error || after.error || 'A scan failed to complete.');
      }
      result = await api('/compare?' + new URLSearchParams(ids));
    } catch (error) {issue = message(error);}
    waiting = undefined;
    busy = false;
  }

  async function plan(event: SubmitEvent) {
    event.preventDefault();
    busy = true; issue = ''; result = undefined; waiting = undefined;
    try {
      waiting = await api('/compare/plan', post({
        baseline:{reference:beforeRef,registryId:beforeRegistry || null,platform},
        target:{reference:afterRef,registryId:afterRegistry || null,platform},
      }));
      void check();
    } catch (error) {issue = message(error); busy = false;}
  }

  function download(comparison: Comparison) {
    const escape = (value: string) => value.replace(/[\r\n]/g, ' ').replace(/[\\|<>&`*\[\]]/g, (character) => '\\' + character);
    const lines = ['# Container image comparison', '', '- Baseline: ' + escape(comparison.baseline.reference) + ' (' + comparison.baseline.platform + ')',
      '- Target: ' + escape(comparison.target.reference) + ' (' + comparison.target.platform + ')', '',
      'Finding changes may reflect differences in advisory data between scans.', ''];
    const groups: [string, Change[]][] = [['Package changes', comparison.changes.packages], ['Vulnerability finding changes', comparison.changes.findings]];
    for (const [title, changes] of groups) {
      lines.push('## ' + title, '');
      if (title === 'Package changes' && !comparison.changes.inventoryAvailable) {
        lines.push('Package inventory unavailable in one or both reports.', '');
      } else if (!changes.length) {
        lines.push('No changes.', '');
      } else {
        lines.push('| Name | Ecosystem | Change | Baseline | Target |', '| --- | --- | --- | --- | --- |');
        for (const change of changes) {
          lines.push('| ' + [change.name, change.ecosystem, change.status, change.before.join(', ') || '—', change.after.join(', ') || '—'].map(escape).join(' | ') + ' |');
        }
        lines.push('');
      }
    }
    const url = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'image-comparison.md';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 30_000);
  }
</script>

<svelte:head><title>Report comparison · {productName}</title></svelte:head>
<div class="page-heading">
  <div><h1>Report comparison</h1><p>Review package version and vulnerability finding changes between reports.</p></div>
  {#if result}<button class="button secondary" onclick={() => result && download(result)}><Download size={17} /> Download Markdown</button>{/if}
</div>
{#if issue}<div class="notice error" role="alert">{issue}</div>{/if}
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

{#snippet changes(items: Change[], empty: string, comparison?: Comparison)}
  {#if !items.length}
    <div class="compact-empty">{empty}</div>
  {:else}
    <div class="table-wrap"><table>
      <thead><tr><th>Name</th><th>Change</th><th>Baseline</th><th>Target</th></tr></thead>
      <tbody>{#each items as item}
        {@const change = comparison ? vulnerabilityChanges[item.status] : undefined}
        <tr>
          <td>
            {#if comparison}
              <a class="table-link mono" href={'/scans/' + (item.status === 'Removed' ? comparison.baseline.id : comparison.target.id) + '?' + new URLSearchParams({finding: item.name.split(' · ', 1)[0]})}>{item.name}</a>
            {:else}<strong class="mono">{item.name}</strong>{/if}
            <small>{item.ecosystem}</small>
          </td>
          <td><span class={'badge ' + (change?.tone ?? 'change-' + item.status.toLowerCase())} class:finding-change={!!change}>{change?.label ?? item.status}</span></td>
          <td class="mono">{item.before.join(', ') || '—'}</td><td class="mono">{item.after.join(', ') || '—'}</td>
        </tr>
      {/each}</tbody>
    </table></div>
  {/if}
{/snippet}

{#if result}
  {#if result.baseline.platform !== result.target.platform}
    <div class="notice warning" role="status">These reports use different platforms. Some changes may reflect architecture differences.</div>
  {/if}
  <section class="panel">
    <div class="panel-title">
      <div><h2>Vulnerability changes</h2><p>{imageName(result.baseline.reference)} → {imageName(result.target.reference)}</p></div>
      {#if result.changes.findings.length}<div class="filters">
        {#each Object.entries(vulnerabilityChanges) as [status, change] (status)}
          {@const count = result.changes.findings.filter(finding => finding.status === status).length}
          {#if count}<span class={'badge finding-change ' + change.tone}>{count} {change.label.toLowerCase()}</span>{/if}
        {/each}
      </div>{/if}
    </div>
    {@render changes(result.changes.findings, 'No vulnerability findings changed.', result)}
    <div class="panel-footer field-help">Changes can reflect updates to the vulnerability database.</div>
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
