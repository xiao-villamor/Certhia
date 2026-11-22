<script lang="ts">
  import { auth } from '#lib/auth.svelte.js';
  import { productName, productSlug } from '#lib/product.js';
  import { onMount, tick } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { Bell, Check, ChevronDown, ChevronRight, Columns3, ClipboardCheck, Copy, Download, GitCompareArrows, Package, RotateCcw, Search, ShieldAlert } from '@lucide/svelte';
  import { allPages, active, api, apiFetch, classifications, imageName, message, post, repositoryName, time, type Finding, type ImageWatch, type Registry, type ScanDetail, type ScanProgress, allRegistries } from '#lib/api.js';
  import { findingColumns, defaultFindingColumns, readFindingColumns, saveFindingColumns, type FindingColumn } from '#lib/finding-columns.js';
  import { detectionKey, findingDetectors } from '#lib/finding-evidence.js';
  import { ecosystemGroup, sortEcosystems } from '#lib/ecosystems.js';
  import Status from '#lib/Status.svelte';
  import ScanActivity from '#lib/ScanActivity.svelte';
  import FindingTracker from '#lib/FindingTracker.svelte';
  import IssueLink from '#lib/IssueLink.svelte';
  import { classificationsPath, trackingStatus, type FindingTracking, type TrackingTarget } from '#lib/tracking.js';

  let scan = $state<ScanDetail>();
  let tracking = $state<TrackingTarget>();
  let sources = $state<string[]>([]);
  let artifactStatus = $state<'loading' | 'ready' | 'error'>('loading');
  let columns = $state<FindingColumn[]>([...defaultFindingColumns]);
  let columnMenu = $state<HTMLDetailsElement>();
  let digestCopied = $state(false);
  let copiedTimer: ReturnType<typeof setTimeout> | undefined;
  async function copyDigest(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      digestCopied = true;
      clearTimeout(copiedTimer);
      copiedTimer = setTimeout(() => { digestCopied = false; }, 1600);
    } catch {
      issue = 'Could not copy the digest. Hover over it to see the full value.';
    }
  }
  function setColumns(next: FindingColumn[]) {
    columns = findingColumns.filter(column => next.includes(column.id)).map(column => column.id);
    try { saveFindingColumns(columns); } catch { /* The choice still applies to this page view. */ }
  }
  function closeColumnMenu(event: Event) {
    if (columnMenu?.open && !(event.target instanceof Node && columnMenu.contains(event.target))) columnMenu.open = false;
  }
  let evidence = $state<{ scanId: string; detectors: Map<string, string[]>; unavailable: boolean }>();
  let cbomBusy = $state(false);
  let cbomIssue = $state('');
  const visibleColumns = $derived(findingColumns.filter(column => columns.includes(column.id)));
  const needsEvidence = $derived(columns.includes('scanners') || !!tracking?.details.length);
  const evidencePending = $derived(needsEvidence && scan?.id !== evidence?.scanId);
  const sbomAvailable = $derived(!!scan?.report?.inventoryAvailable || sources.includes('sbom'));
  const cbomCandidate = $derived(sources.some(source => source === 'sbom' || source === 'cbom'));
  const demo = $derived(scan?.reference.startsWith('demo-fixtures.invalid/'));
  const focusedFinding = $derived(page.url.searchParams.get('finding') ?? '');

  async function viewFindings() {
    tab = 'findings';
    limit = 100;
    await tick();
    const section = document.getElementById('scan-findings');
    section?.focus({ preventScroll: true });
    section?.scrollIntoView({ block: 'start' });
  }
  const advisoryFilters = $derived(new URLSearchParams(page.url.searchParams.get('advisoryFilters') ?? ''));

  onMount(() => {
    const refresh = () => { columns = readFindingColumns(); };
    refresh();
    window.addEventListener('storage', refresh);
    return () => window.removeEventListener('storage', refresh);
  });

  function detectors(finding: Finding): string[] {
    return evidence?.scanId === scan?.id ? evidence?.detectors.get(detectionKey(finding)) ?? [] : [];
  }

  $effect(() => {
    const id = scan?.id;
    if (!id || !scan?.report?.findings.length || !needsEvidence || evidence?.scanId === id) return;
    const controller = new AbortController();
    void findingDetectors(id, controller.signal).then(found => {
      if (!controller.signal.aborted) evidence = { scanId: id, detectors: found, unavailable: false };
    }).catch(() => {
      if (!controller.signal.aborted) evidence = { scanId: id, detectors: new Map(), unavailable: true };
    });
    return () => controller.abort();
  });

  async function downloadCbom() {
    if (!scan || cbomBusy) return;
    const id = scan.id;
    cbomBusy = true;
    cbomIssue = '';
    try {
      const response = await apiFetch('/scans/' + id + '/report/cbom');
      if (!response.ok) {
        const result = await response.json().catch(() => null);
        throw new Error(result?.error ?? 'Could not download the CBOM.');
      }
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement('a');
      link.href = url;
      link.download = `${productSlug}-${id}.cbom.cdx.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      if (scan?.id === id) cbomIssue = message(error);
    } finally {
      cbomBusy = false;
    }
  }
  let issue = $state('');
  let tab = $state<'findings' | 'packages' | 'checks'>('findings');
  let query = $state('');
  let ecosystem = $state('');
  let stateFilter = $state('');
  let limit = $state(100);
  let triage = $state<Record<string, FindingTracking>>({});
  let busy = $state(false);
  let downloadsOpen = $state(false);
  let format = $state('pdf');
  let progress = $state<ScanProgress>();
  let reconnecting = $state(false);
  let viewingLayers = $state(false);
  let layerData = $state<{layers:{digest:string;size:number;mediaType:string}[];compressedBytes:number;repeatedBytes:number}>();
  let selectedLayer = $state<{index:number;files:{path:string;type:string;size:number}[];uncompressedBytes:number;truncated:boolean}>();
  let layerLoading = $state<number>();
  let publishing = $state(false);
  let registries = $state<Registry[]>([]);
  let destination = $state('');
  let destinationRegistry = $state('');
  let feedback = $state('');
  let watch = $state<ImageWatch | null>();
  let watchBusy = $state(false);
  let watchIssue = $state('');

  async function enableWatch() {
    if (!scan || watchBusy) return;
    const id = scan.id;
    watchBusy = true; watchIssue = '';
    try {
      const result = await api<ImageWatch>('/scans/' + id + '/watch', {method:'PUT'});
      if (scan?.id === id) watch = result;
    } catch (error) {
      if (scan?.id === id) watchIssue = message(error);
    } finally { watchBusy = false; }
  }

  async function layers() {
    if (!scan) return;
    viewingLayers = true; busy = true; issue = '';
    try {layerData = await api('/images/' + scan.id + '/layers');}
    catch (error) {issue = message(error);}
    finally {busy = false;}
  }
  async function inspectLayer(index:number) {
    if (!scan) return;
    layerLoading = index; selectedLayer = undefined; issue = '';
    try {selectedLayer = await api('/images/' + scan.id + '/layers/' + index + '/files');}
    catch (error) {issue = message(error);}
    finally {layerLoading = undefined;}
  }
  async function openPublish() {
    publishing = true;
    try {registries = await allRegistries();} catch (error) {issue = message(error);}
  }
  async function publish(event: SubmitEvent) {
    event.preventDefault();
    if (!scan || !confirm('Publish this image to ' + destination + '?')) return;
    busy = true; issue = ''; feedback = '';
    try {
      const result = await api<{reference:string}>('/images/' + scan.id + '/publish',
        post({reference:destination,registryId:destinationRegistry || null}));
      feedback = 'Image published to ' + result.reference;
      publishing = false;
    } catch (error) {issue = message(error);}
    finally {busy = false;}
  }
  const checks = $derived(scan?.report?.checks.filter(item => [item.title, item.category, item.severity, item.target].some(
    value => value.toLowerCase().includes(needle))) ?? []);
  const needle = $derived(query.trim().toLowerCase());
  const findingGroups = $derived.by(() => {
    const groups = new Map<string, Finding[]>();
    for (const item of scan?.report?.findings ?? []) {
      const group = ecosystemGroup(item.ecosystem);
      const items = groups.get(group);
      if (items) items.push(item);
      else groups.set(group, [item]);
    }
    for (const items of groups.values()) items.sort((a, b) =>
      severityRank(a.severity) - severityRank(b.severity) || a.id.localeCompare(b.id, undefined, {numeric: true}));
    return groups;
  });
  const ecosystems = $derived(sortEcosystems(findingGroups.keys()));
  const findings = $derived.by(() => {
    const groups: { name: string; items: Finding[]; total: number }[] = [];
    let total = 0;
    for (const name of ecosystems) {
      if (ecosystem && name !== ecosystem) continue;
      const items = findingGroups.get(name) ?? [];
      const matches = needle || stateFilter ? items.filter(item =>
        (!stateFilter || (triage[item.id]?.status ?? 'open') === stateFilter) &&
        (!needle || [item.id, item.package, item.severity, item.ecosystem, item.title, name, triage[item.id]?.issue?.key ?? '']
          .some(value => value.toLowerCase().includes(needle)))) : items;
      if (matches.length && total < limit) {
        groups.push({name, items:matches.slice(0, limit - total), total:matches.length});
      }
      total += matches.length;
    }
    return {groups, total};
  });
  const inventory = $derived(scan?.report?.packages.filter(item => [item.name, item.ecosystem, item.version].some(
    part => part.toLowerCase().includes(needle))) ?? []);
  const severity = ['critical', 'high', 'medium', 'low', 'unknown'] as const;
  function severityRank(value: string) {
    const rank = severity.indexOf(value.toLowerCase() as typeof severity[number]);
    return rank < 0 ? severity.length : rank;
  }
  const countShown = $derived(tab === 'findings' ? findings.total : tab === 'packages' ? inventory.length : checks.length);

  async function loadTriage(id: string, signal?: AbortSignal) {
    try {
      const list = await allPages<FindingTracking>(classificationsPath(id), {signal});
      if (!signal?.aborted && id === page.params.id) {
        triage = Object.fromEntries(list.map(item => [item.finding, item]));
      }
    } catch (error) {
      if (!signal?.aborted && id === page.params.id) issue = message(error);
    }
  }
  function edit(finding: Finding) {
    if (scan) tracking = {scanId:scan.id, reference:scan.reference, platform:scan.platform, digest:scan.report?.digest, finding:finding.id, details:[finding]};
  }
  function trackingSaved() {
    tracking = undefined;
    if (scan) void loadTriage(scan.id);
  }
  async function action(kind: string) {
    if (!scan || busy) return;
    busy = true;
    issue = '';
    try {
      const path = '/scans/' + scan.id;
      if (kind === 'cancel') {
        await api(path + '/cancel', post({}));
        scan = await api(path);
      } else {
        const result = await api<{ id: string }>(path + '/rescan', post({}));
        await goto('/scans/' + result.id);
      }
    } catch (error) { issue = message(error); }
    finally { busy = false; }
  }

  $effect(() => {
    const id = page.params.id;
    const finding = page.url.searchParams.get('finding');
    query = finding ?? '';
    tab = 'findings';
    ecosystem = '';
    stateFilter = '';
    limit = 100;
    tracking = undefined;
    cbomIssue = '';
    triage = {};
    watch = undefined; watchIssue = '';
    const controller = new AbortController();
    if (id) void loadTriage(id, controller.signal);
    scan = undefined;
    issue = '';
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    let listener: EventSource | undefined;
    progress = undefined; reconnecting = false; layerData = undefined; selectedLayer = undefined; viewingLayers = false; sources = []; artifactStatus = 'loading';
    async function refresh() {
      try {
        const result = await api<ScanDetail>('/scans/' + id);
        if (disposed) return;
        scan = result;
        issue = '';
        if (active(result)) {
          if (!listener) {
            listener = new EventSource('/api/scans/' + id + '/events');
            listener.addEventListener('progress', (event: MessageEvent) => {
              if (disposed) return;
              const snapshot = JSON.parse(event.data) as ScanProgress;
              progress = snapshot;
              reconnecting = false;
              if (snapshot.status === 'queued' || snapshot.status === 'running') {
                if (scan) scan = {...scan, status:snapshot.status};
              } else {
                listener?.close();
                listener = undefined;
                void refresh();
              }
            });
            listener.onerror = () => {
              listener?.close(); listener = undefined;
              if (!disposed) {
                reconnecting = true;
                timer = setTimeout(refresh, 2200);
              }
            };
          }
        } else {
          reconnecting = false;
          void api<ScanProgress>('/scans/' + id + '/progress')
            .then(snapshot => { if (!disposed) progress = snapshot; }).catch(() => {});
          if (result.report) {
            if (finding) void tick().then(() => {
              if (!disposed) document.getElementById('scan-findings')?.scrollIntoView({block: 'start'});
            });
            void api<ImageWatch | null>('/scans/' + id + '/watch', {signal:controller.signal})
              .then(item => {if (!disposed) watch = item;})
              .catch(error => {if (!disposed) watchIssue = message(error);});
            void api<{scanners:string[]}>('/scans/' + id + '/scanner-results')
              .then(result => { if (!disposed) { sources = result.scanners; artifactStatus = 'ready'; } })
              .catch(() => { if (!disposed) artifactStatus = 'error'; });
          }
        }
      } catch (error) {
        if (!disposed) issue = message(error);
      }
    }
    void refresh();
    return () => { disposed = true; controller.abort(); clearTimeout(timer); listener?.close(); };
  });
</script>

<svelte:document onclick={closeColumnMenu} onkeydown={(event) => { if (event.key === 'Escape' && columnMenu?.open) columnMenu.open = false; }} />
<svelte:head><title>Scan report · {productName}</title></svelte:head>

<FindingTracker target={tracking} scanners={tracking?.details.flatMap(detectors) ?? []} {evidencePending}
  evidenceUnavailable={evidence?.scanId === scan?.id && !!evidence?.unavailable} dismiss={() => {tracking = undefined;}} onSaved={trackingSaved} />
{#if issue}<div class="notice error" role="alert">{issue}</div>{/if}
{#if feedback}<div class="notice success" role="status">{feedback}</div>{/if}
{#if scan}
  <div class="page-heading">
    <div><a class="crumb" href="/">Scan desk</a><h1 class="reference-title">{imageName(scan.reference)}</h1><p class="mono break">{scan.reference}</p>{#if demo}<p><span class="badge neutral">Demo image</span></p>{/if}</div>
    <div class="filters">
      {#if auth.operator && active(scan)}
        <button class="button secondary" onclick={() => action('cancel')} disabled={busy}>Cancel scan</button>
      {:else if auth.operator && scan.source !== 'archive' && !demo}
        <button class="button secondary" onclick={() => action('rescan')} disabled={busy}><RotateCcw size={16} aria-hidden="true" /> {scan.status === 'failed' ? 'Retry scan' : 'Rescan'}</button>
      {/if}
      {#if scan.report}
        <button class="button primary" type="button" aria-controls="scan-findings" onclick={viewFindings}><ShieldAlert size={16} aria-hidden="true" /> View findings</button>
        <a class="button secondary" href={'/compare?target=' + scan.id}><GitCompareArrows size={17} /> Compare report</a>
      {/if}
    </div>
  </div>

  <ScanActivity {scan} {progress} {reconnecting} />

  <div class="panel scan-meta">
    <div><span>Status</span><Status status={scan.status} /></div>
    <div><span>Platform</span><strong class="mono">{scan.platform}</strong></div>
    <div><span>Created</span><strong>{time(scan.createdAt)}</strong></div>
    <div><span>Source</span><strong>{({import:'Imported report',registry:'Registry',docker:'Local Docker',archive:'Image archive',kubernetes:'Kubernetes',swarm:'Docker Swarm'})[scan.source] || scan.source}</strong></div>
    {#if scan.report?.os}<div><span>Operating system</span><strong>{scan.report.os}</strong></div>{/if}
    {#if scan.report?.sizeBytes}<div><span>Image size</span><strong>{(scan.report.sizeBytes / 1048576).toFixed(1)} MiB</strong></div>{/if}
    {#if scan.report?.digest}
      {@const digest = scan.report.digest}
      <div class="digest">
        <span>Image digest</span>
        <span class="digest-value">
          <code class="mono" title={digest}>{digest.length > 30 ? digest.slice(0, 19) + '…' + digest.slice(-8) : digest}</code>
          <button type="button" class="copy-button" aria-label="Copy image digest" onclick={() => copyDigest(digest)}>
            {#if digestCopied}<Check size={14} aria-hidden="true" /> Copied{:else}<Copy size={14} aria-hidden="true" /> Copy{/if}
          </button>
        </span>
      </div>
    {/if}
  </div>

  {#if scan.error}<div class="notice error" role="alert">{scan.error}
    {#if scan.status === 'failed'}<a class="table-link" href={'/images?' + new URLSearchParams({q: repositoryName(scan.reference)})}>View image history</a>{/if}
  </div>{/if}
  {#if scan.report}
    <div class="severity-strip" role="group" aria-label="Vulnerabilities by severity">
      {#each severity as label}
        <div><span class={'severity ' + label}>{label}</span><strong>{scan.report.counts[label]}</strong></div>
      {/each}
    </div>
    <!-- svelte-ignore a11y_no_noninteractive_tabindex (The View findings shortcut moves focus here.) -->
    <section class="panel" id="scan-findings" aria-labelledby="report-content-title" tabindex="-1">
      <div class="panel-title report-title">
        <div><h2 id="report-content-title">Report contents</h2>
          {#if focusedFinding && page.url.searchParams.has('advisoryFilters')}
            {@const fromTriage = page.url.searchParams.get('from') === 'triage'}
            <a class="table-link focused-advisory" href={'/library' + (fromTriage ? '' : '/' + encodeURIComponent(focusedFinding)) + (advisoryFilters.size ? '?' + advisoryFilters : '')}>
              {fromTriage ? 'Back to triage' : 'Back to ' + focusedFinding}
            </a>
          {/if}
        </div>
        <div class="filters" role="group" aria-label="Report exports">
          {#if sbomAvailable}
            <a class="button secondary" href={'/api/scans/' + scan.id + (scan.report.inventoryAvailable ? '/report/sbom' : '/scanner-results/sbom')} data-sveltekit-reload><Download size={15} aria-hidden="true" /> SBOM</a>
          {:else}<button type="button" class="button secondary" disabled aria-describedby="sbom-availability">SBOM</button>{/if}
          {#if cbomCandidate}
            <button type="button" class="button secondary" disabled={cbomBusy} aria-describedby={cbomIssue ? 'cbom-availability' : undefined}
              onclick={downloadCbom}><Download size={15} aria-hidden="true" /> {cbomBusy ? 'Downloading…' : 'CBOM'}</button>
          {/if}
          {#if scan.report.findings.length}
            <a class="button secondary" href={'/api/scans/' + scan.id + '/report/vex'} data-sveltekit-reload><Download size={15} aria-hidden="true" /> OpenVEX</a>
          {:else}<button type="button" class="button secondary" disabled aria-describedby="vex-availability">OpenVEX</button>{/if}
          <a class="button secondary" href="#report-downloads" onclick={() => {downloadsOpen = true;}}>More downloads</a>
        </div>
      </div>
      {#if !sbomAvailable || !scan.report.findings.length || cbomIssue}
        <div class="report-export-status">
          {#if !sbomAvailable}<p id="sbom-availability">SBOM requires a package inventory.</p>{/if}
          {#if cbomIssue}<p id="cbom-availability" role="alert">{cbomIssue}</p>{/if}
          {#if !scan.report.findings.length}<p id="vex-availability">OpenVEX requires at least one finding.</p>{/if}
        </div>
      {/if}
      <div class="panel-title">
        <div class="tabs compact" role="group" aria-label="Report views">
          <button class:tab-active={tab === 'findings'} aria-pressed={tab === 'findings'} onclick={() => { tab = 'findings'; limit = 100; }}>
            <ShieldAlert size={17} /> Findings ({scan.report.findings.length})
          </button>
          <button class:tab-active={tab === 'packages'} aria-pressed={tab === 'packages'} onclick={() => { tab = 'packages'; limit = 100; }}>
            <Package size={17} /> Packages ({scan.report.counts.packages})
          </button>
          <button class:tab-active={tab === 'checks'} aria-pressed={tab === 'checks'} onclick={() => {tab = 'checks'; limit = 100;}}>
            <ClipboardCheck size={17} /> Checks ({scan.report.checks.length})
          </button>
        </div>
        <div class="filters">
          {#if tab === 'findings'}
            <details class="column-menu" bind:this={columnMenu}>
              <summary class="button secondary"><Columns3 size={15} aria-hidden="true" /> Columns</summary>
              <div class="column-popover" role="group" aria-label="Visible findings columns">
                <p>Finding and severity are always shown.</p>
                {#each findingColumns as column (column.id)}
                  <label class="inline-check"><input type="checkbox" checked={columns.includes(column.id)}
                    onchange={(event) => setColumns(event.currentTarget.checked ? [...columns, column.id] : columns.filter(id => id !== column.id))} /> {column.label}</label>
                {/each}
                <button type="button" class="text-button" onclick={() => setColumns([...defaultFindingColumns])}>Restore defaults</button>
              </div>
            </details>
          {/if}
          {#if tab === 'findings' && ecosystems.length > 1}
            <select aria-label="Filter findings by ecosystem" bind:value={ecosystem} onchange={() => {limit = 100;}}>
              <option value="">All ecosystems</option>
              {#each ecosystems as name (name)}<option value={name}>{name} ({findingGroups.get(name)?.length})</option>{/each}
            </select>
          {/if}
          {#if tab === 'findings' && findingGroups.size}
            <select aria-label="Filter findings by status" bind:value={stateFilter} onchange={() => {limit = 100;}}>
              <option value="">All statuses</option>
              {#each classifications as [value,label]}<option {value}>{label}</option>{/each}
            </select>
          {/if}
          {#if (tab === 'findings' && scan.report.findings.length) || (tab === 'packages' && scan.report.counts.packages) || (tab === 'checks' && scan.report.checks.length)}
            <label class="search"><Search size={17} aria-hidden="true" /><input aria-label="Filter report" placeholder="Filter report" bind:value={query} oninput={() => { limit = 100; }} /></label>
          {/if}
        </div>
      </div>
      <!-- svelte-ignore a11y_no_noninteractive_tabindex (Report tables can scroll horizontally on narrow screens.) -->
      <div class="table-wrap" role="region" aria-labelledby="report-content-title" tabindex="0">
        {#if tab === 'findings' && !scan.report.findings.length}
          <div class="empty report-empty">
            <h3>No vulnerabilities reported</h3>
            {#if scan.report.inventoryAvailable}
              <p>Review the package inventory for this scan.</p>
              <button class="button secondary" onclick={() => { tab = 'packages'; limit = 100; }}>View packages</button>
            {/if}
          </div>
        {:else if tab === 'findings'}
          <table class="findings-table">
            <thead><tr><th scope="col">Finding</th><th scope="col">Severity</th>{#each visibleColumns as column (column.id)}<th scope="col">{column.label}</th>{/each}</tr></thead>
            {#each findings.groups as group (group.name)}
              <tbody>
                <tr class="ecosystem-heading"><th colspan={2 + visibleColumns.length} scope="rowgroup">{group.name} <span>{group.total}</span></th></tr>
                {#each group.items as item}
                  {@const annotation = triage[item.id]}
                  <tr>
                    <td><button type="button" class="finding-button table-link mono" aria-haspopup="dialog" aria-label={'View details for ' + item.id}
                      onclick={() => edit(item)}>{item.id}<ChevronRight size={15} aria-hidden="true" /></button>{#if item.title}<small>{item.title}</small>{/if}</td>
                    <td><span class={'severity ' + item.severity.toLowerCase()}>{item.severity.toLowerCase()}</span></td>
                    {#each visibleColumns as column (column.id)}
                      <td>
                        {#if column.id === 'package'}{item.package}<small>{item.ecosystem}</small>
                        {:else if column.id === 'installed'}<span class="mono version">{item.installed || '—'}</span>
                        {:else if column.id === 'fix'}<span class="mono version">{item.fixed || '—'}</span>
                        {:else if column.id === 'scanners'}
                          {#each detectors(item) as detector (detector)}<span class="badge neutral detector">{detector}</span>
                          {:else}<span class="field-help">{evidencePending ? 'Loading…' : evidence?.unavailable ? 'Unavailable' : 'Not recorded'}</span>{/each}
                        {:else if column.id === 'tracking'}
                          <button type="button" class="status-chip" data-status={annotation?.status ?? 'open'} aria-haspopup="dialog" aria-label={(auth.operator ? 'Edit' : 'View') + ' tracking for ' + item.id}
                            onclick={() => edit(item)}>{trackingStatus(annotation?.status)} <ChevronDown size={13} aria-hidden="true" /></button>
                        {:else if annotation?.issue}<IssueLink issue={annotation.issue} />
                        {:else}<span class="field-help">—</span>{/if}
                      </td>
                    {/each}
                  </tr>
                {/each}
              </tbody>
            {:else}<tbody><tr><td colspan={2 + visibleColumns.length}>No findings match the filters.</td></tr></tbody>{/each}
          </table>
        {:else if tab === 'packages'}
          <table>
            <thead><tr><th>Package</th><th>Ecosystem</th><th>Version</th></tr></thead>
            <tbody>
              {#each inventory.slice(0, limit) as item}
                <tr><td class="mono">{item.name}</td><td>{item.ecosystem}</td><td class="mono">{item.version}</td></tr>
              {:else}<tr><td colspan="3">{scan.report.inventoryAvailable ? 'No packages match the filter.' : 'This report has no package inventory.'}</td></tr>{/each}
            </tbody>
          </table>
        {:else}
          <table><thead><tr><th>Type</th><th>Check</th><th>Severity</th><th>Target</th></tr></thead>
            <tbody>{#each checks.slice(0, limit) as check}<tr>
              <td>{check.category}</td><td><strong>{check.title}</strong>{#if check.detail}<small>{check.detail}</small>{/if}</td>
              <td><span class={'severity ' + check.severity.toLowerCase()}>{check.severity.toLowerCase() || '—'}</span></td><td class="mono">{check.target}</td>
            </tr>{:else}<tr><td colspan="4">No matching image checks.</td></tr>{/each}</tbody>
          </table>
        {/if}
      </div>
      {#if countShown > limit}<div class="panel-footer"><button class="button secondary" onclick={() => { limit += 100; }}>Show 100 more</button></div>{/if}
    </section>
    <details class="panel form-disclosure report-downloads" id="report-downloads" bind:open={downloadsOpen}>
      <summary><span><Download size={17} aria-hidden="true" /> Report downloads</span></summary>
      <div class="disclosure-body download-grid">
      <div class="download-group"><h3>Formatted report</h3><div class="inline-input">
        <select aria-label="Report format" bind:value={format}>
          <option value="pdf">PDF</option><option value="xlsx">Excel</option><option value="markdown">Markdown</option>
          <option value="json">JSON</option>{#if sources.includes('trivy')}<option value="raw">Raw Trivy JSON</option>{/if}
          <option value="zip">ZIP bundle</option>
        </select>
        <a class="button secondary" href={'/api/scans/' + scan.id + '/report/' + format} data-sveltekit-reload><Download size={17} /> Download report</a>
      </div></div>
      {#if sources.length}<div class="download-group"><h3>Scanner artifacts</h3><div class="filters">{#each sources as source}
        <a class="button secondary" href={'/api/scans/' + scan.id + '/scanner-results/' + source} data-sveltekit-reload>{source.toUpperCase()} artifact</a>
      {/each}</div></div>{/if}
    </div>
    </details>
    <section class="panel form-panel wide">
      <h2>Image actions</h2>
      <div class="filters">
        <a class="button secondary" href={'/api/images/' + scan.id + '/archive'} data-sveltekit-reload><Download size={17} /> Download image archive</a>
        {#if auth.operator}<button class="button secondary" disabled={busy} onclick={openPublish}>Publish image</button>{/if}
        <button class="button secondary" disabled={busy} onclick={layers}>Inspect image layers</button>
        <a class="button secondary" href={'/patches?scan=' + scan.id}>Analyze patches</a>
        {#if auth.operator && !demo && scan.source !== 'docker' && scan.source !== 'archive'}
          <a class="button secondary" href={'/scheduled-scans?' + new URLSearchParams({image:scan.reference,platform:scan.platform})}>Schedule rescans</a>
        {/if}
        {#if auth.operator && watch === null}
          <button type="button" class="button secondary" disabled={watchBusy} onclick={enableWatch}>
            <Bell size={16} aria-hidden="true" /> Watch new vulnerabilities
          </button>
        {:else if auth.operator && watch}
          <a class="button secondary" href="/settings#image-watches"><Bell size={16} aria-hidden="true" /> Manage image watch</a>
        {/if}
      </div>
      {#if watch}<p class="field-help" role="status">Watching {scan.platform} for advisories detected on future scans.</p>{/if}
      {#if watchIssue}<div class="notice error" role="alert">{watchIssue}</div>{/if}
      {#if publishing}
        <form class="form-panel" onsubmit={publish}>
          <label class="field"><span>Destination image</span><input class="mono" required bind:value={destination} placeholder="registry.example.com/team/app:tag" /></label>
          <label class="field"><span>Destination credentials</span><select bind:value={destinationRegistry}><option value="">Anonymous</option>
          {#each registries as registry}<option value={registry.id}>{registry.name}</option>{/each}</select></label>
          <div class="actions"><button type="button" class="button secondary" onclick={() => {publishing = false;}}>Cancel</button><button class="button primary" disabled={busy}>Publish</button></div>
        </form>
      {/if}
      {#if viewingLayers && layerData}
        <p>{layerData.layers.length} layers · {(layerData.compressedBytes / 1048576).toFixed(1)} MiB compressed · {(layerData.repeatedBytes / 1048576).toFixed(1)} MiB repeated</p>
        <div class="table-wrap"><table><thead><tr><th>Layer digest</th><th>Size</th><th>Media type</th><th>Files</th></tr></thead>
        <tbody>{#each layerData.layers as layer, index}<tr><td class="mono">{layer.digest}</td><td>{(layer.size / 1048576).toFixed(2)} MiB</td><td>{layer.mediaType}</td>
          <td><button class="button secondary" disabled={layerLoading !== undefined} onclick={() => inspectLayer(index)}>{layerLoading === index ? 'Reading…' : 'View files'}</button></td></tr>{/each}</tbody></table></div>
      {/if}
      {#if selectedLayer}
        <h3>Layer {selectedLayer.index + 1} files</h3>
        <p>{(selectedLayer.uncompressedBytes / 1048576).toFixed(2)} MiB uncompressed{selectedLayer.truncated ? ' · First 500 entries' : ''}</p>
        <div class="table-wrap"><table><thead><tr><th>Path</th><th>Type</th><th>Bytes</th></tr></thead>
          <tbody>{#each selectedLayer.files as file}<tr><td class="mono">{file.path}</td><td>{file.type}</td><td>{file.size.toLocaleString()}</td></tr>{/each}</tbody>
        </table></div>
      {/if}
    </section>
  {/if}
{:else if !issue}
  <div class="empty" role="status">Loading scan…</div>
{/if}

<style>
  .digest-value { display: flex; align-items: center; gap: .55rem; min-width: 0; }
  .digest-value code { font-size: .82rem; font-weight: 600; white-space: nowrap; }
  .copy-button { display: inline-flex; align-items: center; gap: .3rem; min-height: 28px; padding: .15rem .5rem; border: 1px solid var(--line); border-radius: 6px; background: var(--surface); color: var(--muted); font-size: .74rem; font-weight: 750; }
  .copy-button:hover { border-color: var(--control-line); background: var(--inset); color: var(--ink); }
  .table-wrap:focus-visible { outline-offset: -3px; }
  #scan-findings { scroll-margin-top: 5rem; }
  .focused-advisory { display: inline-block; margin-top: .24rem; font-size: .78rem; }
  .report-export-status { display: flex; flex-wrap: wrap; gap: .4rem 1rem; padding: .55rem 1.15rem; border-bottom: 1px solid var(--line); background: var(--canvas); color: var(--muted); font-size: .78rem; }
  .report-export-status [role="alert"] { color: var(--critical); }
  /* The columns popover may extend past a short report, so this panel rounds its own last child instead of clipping. */
  #scan-findings { overflow: visible; }
  #scan-findings > :last-child { border-radius: 0 0 var(--radius) var(--radius); }
  .column-menu { position: relative; }
  .column-menu > summary { list-style: none; }
  .column-menu > summary::-webkit-details-marker { display: none; }
  .column-menu[open] > summary { background: var(--inset); border-color: var(--muted); }
  .column-popover { position: absolute; z-index: 4; top: calc(100% + .35rem); right: 0; display: grid; gap: .15rem; width: max-content; min-width: 14rem; padding: .55rem; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); box-shadow: 0 .5rem 1.5rem rgb(15 23 42 / 14%); }
  .column-popover p { padding: .2rem .35rem .4rem; color: var(--muted); font-size: .74rem; }
  .column-popover .inline-check { padding: .25rem .35rem; border-radius: 5px; font-weight: 650; }
  .column-popover .inline-check:hover { background: var(--inset); }
  .column-popover .text-button { justify-self: start; margin-top: .25rem; padding: .3rem .35rem; color: var(--accent-ink); font-size: .78rem; }
  .findings-table thead th { min-width: 6.5rem; }
  .findings-table thead th:first-child { min-width: 10rem; }
  .finding-button { display: inline-flex; align-items: center; gap: .25rem; border: 0; padding: .15rem 0; background: transparent; text-align: start; overflow-wrap: anywhere; }
  .finding-button :global(svg) { flex: none; }
  .detector { margin: .15rem .22rem .15rem 0; text-transform: none; }
  .report-empty { padding-block: 1.85rem; }
  .report-downloads > summary > span { display: inline-flex; align-items: center; gap: .55rem; }
  .report-downloads .download-grid { grid-template-columns: repeat(auto-fit, minmax(min(100%, 15rem), 1fr)); gap: 1rem; padding: 1.1rem; }
  .download-group { display: grid; align-content: start; gap: .5rem; }
  .download-group h3 { font-size: .88rem; }

  .ecosystem-heading th {
    background: var(--inset);
    border-top: 1px solid var(--line);
    color: var(--ink);
    font-family: inherit;
    font-size: .85rem;
    text-transform: none;
    letter-spacing: normal;
  }
  .ecosystem-heading span { margin-left: .45rem; color: var(--muted); font: .75rem var(--mono); }
  @media (max-width: 620px) {
    .severity-strip { grid-template-columns: repeat(auto-fit, minmax(min(100%, 5.5rem), 1fr)); }
    .severity-strip > div { justify-items: start; gap: .35rem; padding: .5rem; }
    .severity-strip strong { font-size: 1.1rem; }
  }
</style>
