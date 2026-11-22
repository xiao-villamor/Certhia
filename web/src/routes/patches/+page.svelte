<script lang="ts">
  import { auth } from '#lib/auth.svelte.js';
  import { productName } from '#lib/product.js';
  import { page } from '$app/state';
  import { onMount } from 'svelte';
  import { ArrowRight, Download, PackageCheck, Wrench } from '@lucide/svelte';
  import { api, apiPage, imageName, message, post, time, type Registry, type Scan, allRegistries } from '#lib/api.js';

  interface PackageUpdate {package:string; fixed:string; installed:string|null; advisories:string[];}
  interface Patch {id:string; scanId:string; reference:string; status:string; createdAt:string; error:string|null; packages:PackageUpdate[];}
  interface Analysis {image:string; packages:PackageUpdate[]; canBuild:boolean;}
  let scans = $state<Scan[]>([]);
  let registries = $state<Registry[]>([]);
  let patches = $state<Patch[]>([]);
  let scanId = $state('');
  let analysis = $state<Analysis>();
  let analyzing = $state(false);
  let loadingScans = $state(true);
  const selectedScan = $derived(scans.find(scan => scan.id === scanId));
  const reportFindings = $derived(selectedScan?.counts ? selectedScan.counts.critical + selectedScan.counts.high
    + selectedScan.counts.medium + selectedScan.counts.low + selectedScan.counts.unknown : undefined);
  let busy = $state(false);
  let issue = $state('');
  let feedback = $state('');
  let selected = $state<Patch>();
  let advisories = $state<string[]>([]);
  let allAdvisories = $derived([...new Set(analysis?.packages.flatMap(item => item.advisories) || [])]);
  let reference = $state('');
  let registryId = $state('');

  let next=$state<string|null>(null);
  async function refresh(append=false) {
    try { const result=await apiPage<Patch[]>('/patches/history',append ? next : null); patches=append?[...patches,...result.items]:result.items;next=result.next; }
    catch (error) {issue = message(error);}
  }
  onMount(() => {
    void refresh();
    void api<Scan[]>('/scans').then(result => {
      scans = result.filter(scan => scan.status === 'completed');
      scanId = page.url.searchParams.get('scan') || (scans.length === 1 ? scans[0].id : '');
      if (page.url.searchParams.has('scan') && scanId) void inspect();
    }).catch(error => {issue = message(error);}).finally(() => {loadingScans = false;});
    if (auth.operator) void allRegistries().then(result => {registries = result;}).catch(error => {issue = message(error);});
    const timer = setInterval(() => {if (patches.some(patch => ['queued','running'].includes(patch.status))) void refresh();},3000);
    return () => clearInterval(timer);
  });
  async function inspect() {
    if (busy || !scanId) return;
    busy = true; analyzing = true; analysis = undefined; issue = ''; feedback = '';
    try {
      analysis = await api('/patches/analyze/' + scanId);
      advisories = [...allAdvisories];
    }
    catch (error) {issue = message(error);}
    finally {busy = false; analyzing = false;}
  }
  async function execute(dryRun:boolean) {
    busy = true; issue = ''; feedback = '';
    try {
      await api('/patches/execute', post({scanId,dryRun,selectedVulnIds:advisories.length === allAdvisories.length ? undefined : advisories}));
      await refresh();
      feedback = dryRun ? 'Patch plan saved.' : 'Patch build queued.';
    } catch (error) {issue = message(error);}
    finally {busy = false;}
  }
  async function publish(event: SubmitEvent) {
    event.preventDefault();
    if (!selected || !confirm('Publish this patched image to ' + reference + '?')) return;
    busy = true; issue = ''; feedback = '';
    try {
      const result = await api<{reference:string}>('/patches/' + selected.id + '/publish', post({reference,registryId:registryId || null}));
      feedback = 'Image published to ' + result.reference;
      selected = undefined;
    } catch (error) {issue = message(error);}
    finally {busy = false;}
  }
</script>
<svelte:head><title>Patch builder · {productName}</title></svelte:head>
<div class="page-heading"><div><h1>Patch builder</h1><p>Plan and build operating-system package updates from Trivy reports.</p></div></div>
{#if issue}<div class="notice error" role="alert">{issue}</div>{/if}
{#if feedback}<div class="notice success" role="status">{feedback}</div>{/if}
<div class="patch-workbench">
<section class="panel" aria-labelledby="patch-source-title">
  <div class="panel-title"><h2 id="patch-source-title">Source report</h2></div>
  <form class="form-panel wide" onsubmit={(event) => {event.preventDefault(); void inspect();}}>
    <label class="field"><span>Completed scan</span>
      <select bind:value={scanId} onchange={() => {analysis = undefined;}} disabled={busy || loadingScans || !scans.length}>
        <option value="">{loadingScans ? 'Loading reports…' : scans.length ? 'Choose a report' : 'No completed reports'}</option>
        {#if scanId && !selectedScan}<option value={scanId}>Linked scan</option>{/if}
        {#each scans as scan (scan.id)}<option value={scan.id}>{scan.reference} · {scan.platform} · {time(scan.createdAt)}</option>{/each}
      </select>
    </label>
    {#if selectedScan}
      <dl class="patch-source-meta">
        <div><dt>Platform</dt><dd class="mono">{selectedScan.platform}</dd></div>
        <div><dt>Report findings</dt><dd>{reportFindings ?? '—'}</dd></div>
      </dl>
      <a class="table-link source-link" href={'/scans/' + scanId}>Open scan report <ArrowRight size={14} aria-hidden="true" /></a>
    {/if}
    <div class="actions">
      {#if auth.operator && !loadingScans && !scans.length}<a class="button secondary" href="/scans/new?mode=import">Import report</a>{/if}
      <button class="button primary" disabled={busy || !scanId}><Wrench size={16} aria-hidden="true" /> {analyzing ? 'Analyzing…' : 'Analyze patches'}</button>
    </div>
  </form>
</section>

<section class="panel patch-review" aria-labelledby="patch-review-title" aria-busy={analyzing}>
  <div class="panel-title"><div><h2 id="patch-review-title">Patch candidates</h2>
    {#if analysis}<p class="mono break">{imageName(analysis.image)} · {analysis.packages.length} {analysis.packages.length === 1 ? 'package' : 'packages'}</p>{/if}</div>
  </div>
  {#if analysis}
    {#if analysis.packages.length}
      <div class="table-wrap"><table><thead><tr><th>Package</th><th>Installed</th><th>Fixed version</th><th>Advisories</th></tr></thead>
        <tbody>{#each analysis.packages as item}<tr><td>{item.package}</td><td class="mono">{item.installed || '—'}</td><td class="mono">{item.fixed}</td><td><div class="candidate-advisories">{#each item.advisories as advisory}<label class="inline-check"><input type="checkbox" disabled={busy || !auth.operator} checked={advisories.includes(advisory)} onchange={(event) => {advisories = event.currentTarget.checked ? [...advisories, advisory] : advisories.filter(id => id !== advisory);}} /> {advisory}</label>{/each}</div></td></tr>{/each}</tbody>
      </table></div>
      {#if auth.operator}<div class="panel-footer patch-actions">
        {#if !analysis.canBuild}<p>Building requires BuildKit and a scanned registry image with a recorded digest.</p>{/if}
        <div class="filters">
          <button class="button secondary" onclick={() => execute(true)} disabled={busy || !advisories.length}>Save dry run</button>
          <button class="button primary" onclick={() => execute(false)} disabled={busy || !analysis.canBuild || !advisories.length}><PackageCheck size={16} aria-hidden="true" /> Build patched image</button>
        </div>
      </div>{/if}
    {:else}
      <div class="empty"><h3>No OS package updates found</h3><p>The selected report has no OS findings with a fixed version.</p></div>
    {/if}
  {:else}
    <div class="empty" role="status">
      {#if analyzing}<p>Analyzing the selected report…</p>
      {:else}<h3>Choose a source report</h3><p>Analyze it to review fixed versions and select advisories for a patch plan.</p>{/if}
    </div>
  {/if}
</section>
</div>
{#if selected}
<form class="panel form-panel" onsubmit={publish}>
  <h2>Publish patched image</h2>
  <label class="field"><span>Destination image reference</span><input class="mono" bind:value={reference} placeholder="registry.example.com/team/app:patched" required /></label>
  <label class="field"><span>Destination registry</span><select bind:value={registryId}><option value="">Anonymous</option>
    {#each registries as registry}<option value={registry.id}>{registry.name}</option>{/each}</select></label>
  <div class="actions"><button type="button" class="button secondary" onclick={() => {selected = undefined;}}>Cancel</button>
    <button class="button primary" disabled={busy}>Publish image</button></div>
</form>
{/if}
<section class="panel"><div class="panel-title"><h2>Patch history</h2></div>
  {#if !patches.length}<div class="compact-empty">Saved dry runs and image builds will appear here.</div>
  {:else}<div class="table-wrap"><table><thead><tr><th>Image</th><th>Status</th><th>Updates</th><th>Created</th><th>Actions</th></tr></thead>
    <tbody>{#each patches as patch (patch.id)}<tr>
      <td><a class="table-link mono" href={'/scans/' + patch.scanId}>{patch.reference}</a></td><td>{patch.status}{#if patch.error}<small>{patch.error}</small>{/if}</td>
      <td>{patch.packages.length}</td><td>{time(patch.createdAt)}</td>
      <td>{#if patch.status === 'completed'}<div class="filters"><a class="button secondary" href={'/api/patches/' + patch.id + '/download'} data-sveltekit-reload><Download size={17} /> OCI archive</a>
        {#if auth.operator}<button class="button secondary" onclick={() => {selected = patch;}}>Publish</button>{/if}</div>{:else}—{/if}</td>
    </tr>{/each}</tbody></table></div>{/if}
  {#if next}<button class="button secondary" onclick={() => refresh(true)}>Load more patches</button>{/if}
</section>


<style>
  .patch-workbench { display: grid; grid-template-columns: minmax(16rem, 1fr) minmax(0, 1.55fr); gap: 1rem; margin-bottom: 1.25rem; }
  .patch-workbench .panel { margin: 0; }
  .patch-source-meta { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .55rem; margin: 0; }
  .patch-source-meta div { padding: .65rem .75rem; background: var(--canvas); border-radius: 6px; }
  .patch-source-meta dt { color: var(--muted); font-size: .75rem; }
  .patch-source-meta dd { margin: .3rem 0 0; font-weight: 800; }
  .source-link { display: inline-flex; align-items: center; gap: .4rem; width: fit-content; font-size: .82rem; }
  .patch-review .empty { min-height: 10.5rem; align-content: center; }
  .patch-actions { display: grid; gap: .65rem; border-top: 1px solid var(--line); background: var(--canvas); }
  .candidate-advisories { display: flex; flex-wrap: wrap; column-gap: .7rem; }
  @media (max-width: 1060px) {
    .patch-workbench { grid-template-columns: 1fr; }
    .patch-review .empty { min-height: auto; padding-block: 1.5rem; }
  }
</style>
