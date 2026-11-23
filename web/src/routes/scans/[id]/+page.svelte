<script lang="ts">
  import { auth } from '#lib/auth.svelte.js';
  import { productName, productSlug } from '#lib/product.js';
  import { onMount, tick } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { Bell, Check, ChevronDown, ChevronRight, Columns3, Copy, Download, GitCompareArrows, RotateCcw, Search } from '@lucide/svelte';
  import { active, api, apiFetch, imageName, message, scannerName, post, repositoryName, time, type Finding, type ImageWatch, type Registry, type ScanDetail, type ScanProgress, allRegistries } from '#lib/api.js';
  import { findingColumns, defaultFindingColumns, readFindingColumns, saveFindingColumns, type FindingColumn } from '#lib/finding-columns.js';
  import { detectionKey, findingDescription } from '#lib/finding-evidence.js';
  import { ecosystemGroup, sortEcosystems } from '#lib/ecosystems.js';
  import AutoPage from '#lib/AutoPage.svelte';
  import { ReportPages } from '#lib/report-pages.svelte.js';
  import Status from '#lib/Status.svelte';
  import ConfigDialog from '#lib/ConfigDialog.svelte';
  import ScannerDifferences from '#lib/ScannerDifferences.svelte';
  import { vulnerabilityScannerIds } from '#lib/api.js';
  import ScanActivity from '#lib/ScanActivity.svelte';
  import FindingTracker from '#lib/FindingTracker.svelte';
  import IssueLink from '#lib/IssueLink.svelte';
  import { classificationsPath, effectiveTrackingStatus, trackingFilters, trackingStatus, type FindingTracking, type TrackingTarget } from '#lib/tracking.js';

  type Facet = { ecosystem: string; severity: string; count: number };
  type Summary = ScanDetail & {facets: Facet[]};
  type ReportFinding = Finding & {tracking: FindingTracking};
  type FindingPage = {items: ReportFinding[]; nextCursor: string | null; facets?: Facet[]; evidenceAvailable: boolean};
  const findingPages = new ReportPages<ReportFinding, FindingPage>();
  let findingRevision = $state(0);
  let scan = $state<Summary>();
  let tracking = $state<TrackingTarget>();
  let sources = $state<string[]>([]);
  let artifactStatus = $state<'loading' | 'ready' | 'error'>('loading');
  let columns = $state<FindingColumn[]>([...defaultFindingColumns]);
  let columnMenu = $state<HTMLDetailsElement>();
  let imageMenu = $state<HTMLDetailsElement>();
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
  function closeOutsideMenus(event: Event) {
    if (!(event.target instanceof Node)) return;
    for (const menu of [columnMenu, imageMenu]) {
      if (menu?.open && !menu.contains(event.target)) menu.open = false;
    }
  }
  function closeImageMenu(restoreFocus = false) {
    if (!imageMenu?.open) return;
    imageMenu.open = false;
    if (restoreFocus) imageMenu.querySelector('summary')?.focus();
  }
  function dismissMenu(event: KeyboardEvent) {
    if (event.key !== 'Escape') return;
    for (const menu of [columnMenu, imageMenu]) {
      if (menu?.open) {
        const restoreFocus = menu.contains(document.activeElement);
        menu.open = false;
        if (restoreFocus) menu.querySelector('summary')?.focus();
      }
    }
  }
  let cbomBusy = $state(false);
  let cbomIssue = $state('');
  const visibleColumns = $derived(findingColumns.filter(column => columns.includes(column.id)));
  const sbomAvailable = $derived(!!scan?.report?.inventoryAvailable || sources.includes('sbom'));
  const cbomCandidate = $derived(sources.some(source => source === 'sbom' || source === 'cbom'));
  const demo = $derived(scan?.reference.startsWith('demo-fixtures.invalid/'));
  const sourceLabels: Record<string, string> = {import:'Imported report',registry:'Registry',docker:'Local Docker',archive:'Image archive',kubernetes:'Kubernetes',swarm:'Docker Swarm'};
  const scanId = $derived(page.params.id);
  const focusedFinding = $derived(page.url.searchParams.get('finding') ?? '');

  async function jumpTo(sectionId: string) {
    await tick();
    const section = document.getElementById(sectionId);
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
    return finding.detectedBy?.map(scannerName) ?? [];
  }

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
      link.download = /filename="([A-Za-z0-9._-]+)"/.exec(response.headers.get('Content-Disposition') ?? '')?.[1]
        ?? `${productSlug}-${id}.cbom.cdx.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      if (scan?.id === id) cbomIssue = message(error);
    } finally {
      cbomBusy = false;
    }
  }
  let issue = $state('');
  type ReportView = 'findings' | 'packages' | 'checks' | 'scanners' | 'downloads';
  const completedScanners = $derived((scan?.report?.scanners ?? []).filter(id => vulnerabilityScannerIds.has(id)));
  const requestedView = $derived(page.url.searchParams.get('view'));
  const tab = $derived<ReportView>(requestedView === 'scanners' && completedScanners.length >= 2 ? 'scanners'
    : requestedView === 'packages' || requestedView === 'checks' || requestedView === 'downloads' ? requestedView : 'findings');
  const requestedTracking = $derived(page.url.searchParams.get('track') === '1');
  let scannerTabVisited = $state(false);
  let searches = $state({findings:'', packages:'', checks:''});
  let severityFilter = $state<typeof severity[number] | ''>('');
  let ecosystem = $state('');
  let collapsedGroups = $state(new Set<string>());
  let stateFilter = $state('');
  let limit = $state(100);
  let busy = $state(false);
  async function selectView(view: ReportView) {
    if (tab === view) return;
    const url = new URL(page.url.href);
    if (view === 'findings') url.searchParams.delete('view');
    else url.searchParams.set('view', view);
    url.hash = '';
    limit = 100;
    await goto(url, {reset: false});
  }
  $effect(() => { if (tab === 'scanners') scannerTabVisited = true; });
  async function readFinding(advisory: string) {
    clearFindingFilters();
    collapsedGroups = new Set();
    searches.findings = advisory;
    await selectView('findings');
    await jumpTo('scan-findings');
  }
  const reportFormats = [['pdf', 'PDF'], ['xlsx', 'Excel'], ['markdown', 'Markdown'], ['json', 'JSON'], ['zip', 'ZIP bundle']] as const;
  let progress = $state<ScanProgress>();
  let reconnecting = $state(false);
  let viewingLayers = $state(false);
  let layersBusy = $state(false);
  let layersIssue = $state('');
  let layerData = $state<{layers:{digest:string;size:number;mediaType:string}[];compressedBytes:number;repeatedBytes:number}>();
  let selectedLayer = $state<{index:number;files:{path:string;type:string;size:number}[];uncompressedBytes:number;truncated:boolean}>();
  let layerLoading = $state<number>();
  let publishing = $state(false);
  let publishIssue = $state('');
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
    if (!scan || layersBusy) return;
    const id = scan.id;
    closeImageMenu(true);
    viewingLayers = true; layerData = undefined; selectedLayer = undefined; layersBusy = true; layersIssue = '';
    try {
      const result = await api<typeof layerData>('/images/' + id + '/layers');
      if (scanId === id) layerData = result;
    } catch (error) {
      if (scanId === id) layersIssue = message(error);
    } finally {
      if (scanId === id) layersBusy = false;
    }
  }
  async function inspectLayer(index:number) {
    if (!scan) return;
    const id = scan.id;
    layerLoading = index; selectedLayer = undefined; layersIssue = '';
    try {
      const result = await api<typeof selectedLayer>('/images/' + id + '/layers/' + index + '/files');
      if (scanId === id) selectedLayer = result;
    } catch (error) {
      if (scanId === id) layersIssue = message(error);
    } finally {
      if (scanId === id) layerLoading = undefined;
    }
  }
  async function openPublish() {
    if (!scan) return;
    const id = scan.id;
    closeImageMenu(true);
    publishing = true;
    publishIssue = '';
    try {
      const result = await allRegistries();
      if (scanId === id) registries = result;
    } catch (error) {
      if (scanId === id) publishIssue = message(error);
    }
  }
  async function publish(event: SubmitEvent) {
    event.preventDefault();
    if (!scan || !confirm('Publish this image to ' + destination + '?')) return;
    busy = true; publishIssue = ''; feedback = '';
    try {
      const result = await api<{reference:string}>('/images/' + scan.id + '/publish',
        post({reference:destination,registryId:destinationRegistry || null}));
      feedback = 'Image published to ' + result.reference;
      publishing = false;
    } catch (error) {publishIssue = message(error);}
    finally {busy = false;}
  }
  const checks = $derived(scan?.report?.checks.filter(item => [item.title, item.category, item.severity, item.target].some(
    value => value.toLowerCase().includes(searches.checks.trim().toLowerCase()))) ?? []);
  const needle = $derived(searches.findings.trim().toLowerCase());
  const hasFindingFilters = $derived(!!(needle || stateFilter || ecosystem || severityFilter));
  function clearFindingFilters() {
    searches.findings = '';
    ecosystem = '';
    stateFilter = '';
    severityFilter = '';
    limit = 100;
  }
  const findingGroups = $derived.by(() => {
    const groups = new Map<string, Set<string>>();
    for (const facet of scan?.facets ?? []) {
      const group = ecosystemGroup(facet.ecosystem);
      const types = groups.get(group) ?? new Set<string>();
      types.add(facet.ecosystem);
      groups.set(group, types);
    }
    return groups;
  });
  const ecosystems = $derived(sortEcosystems(findingGroups.keys()));
  const totalFindings = $derived((scan?.facets ?? []).reduce((sum, facet) => sum + facet.count, 0));
  $effect(() => {
    void findingRevision;
    const report = scan?.report;
    if (!report || !totalFindings) return findingPages.open('');
    const selected = ecosystems.filter(name => !ecosystem || name === ecosystem);
    const params = new URLSearchParams({
      limit:'50',
      groups:JSON.stringify(selected.map(name => [...findingGroups.get(name) ?? []])),
    });
    if (!ecosystem && collapsedGroups.size) {
      params.set('collapsed', JSON.stringify(selected.filter(name => collapsedGroups.has(name)).flatMap(name => [...findingGroups.get(name) ?? []])));
    }
    if (needle) params.set('q', needle);
    if (severityFilter) params.set('severity', severityFilter);
    if (stateFilter) params.set('status', stateFilter);
    return findingPages.open('/scans/' + scan!.id + '/report/findings?' + params, needle ? 180 : 0);
  });
  function showEcosystem(name: string) {
    ecosystem = name;
    limit = 100;
  }
  function toggleGroup(name: string) {
    const next = new Set(collapsedGroups);
    if (!next.delete(name)) next.add(name);
    collapsedGroups = next;
  }
  const findings = $derived.by(() => {
    const counts = new Map<string, number>();
    for (const facet of findingPages.first?.facets ?? []) {
      const name = ecosystemGroup(facet.ecosystem);
      counts.set(name, (counts.get(name) ?? 0) + facet.count);
    }
    const grouped = new Map<string, ReportFinding[]>();
    for (const row of findingPages.items) {
      const name = ecosystemGroup(row.ecosystem);
      const items = grouped.get(name) ?? [];
      items.push(row);
      grouped.set(name, items);
    }
    const groups = ecosystems.flatMap(name => {
      const total = counts.get(name) ?? 0;
      const collapsed = !ecosystem && collapsedGroups.has(name);
      const items = grouped.get(name) ?? [];
      return total && (collapsed || items.length) ? [{name, total, collapsed, items}] : [];
    });
    return {groups, total:[...counts.values()].reduce((sum, count) => sum + count, 0)};
  });
  const inventory = $derived(scan?.report?.packages.filter(item => [item.name, item.ecosystem, item.version].some(
    part => part.toLowerCase().includes(searches.packages.trim().toLowerCase()))) ?? []);
  const severity = ['critical', 'high', 'medium', 'low', 'unknown'] as const;
  const severityCounts = $derived.by(() => {
    const counts = {critical:0, high:0, medium:0, low:0, unknown:0};
    for (const facet of scan?.facets ?? []) counts[facet.severity in counts ? facet.severity as keyof typeof counts : 'unknown'] += facet.count;
    return counts;
  });
  const countShown = $derived(tab === 'packages' ? inventory.length : checks.length);
  let editRequest: AbortController | undefined;
  async function edit(advisory: string) {
    if (!scan) return;
    const current = scan;
    editRequest?.abort();
    const controller = editRequest = new AbortController();
    try {
      const url = '/scans/' + current.id + '/report/findings?' + new URLSearchParams({advisory, limit:'100'});
      const details: Finding[] = [];
      let cursor: string | null = null;
      do {
        const next: FindingPage = await api<FindingPage>(url + (cursor ? '&cursor=' + encodeURIComponent(cursor) : ''), {signal:controller.signal});
        details.push(...next.items);
        cursor = next.nextCursor;
      } while (cursor);
      if (!controller.signal.aborted && details.length && scan?.id === current.id) {
        tracking = {scanId:current.id, reference:current.reference, platform:current.platform,
          digest:current.report?.digest, finding:advisory, details};
      }
    } catch (error) {
      if (!controller.signal.aborted) issue = message(error);
    }
  }
  async function trackingSaved() {
    const target = tracking;
    tracking = undefined;
    if (!target || target.scanId !== scan?.id) return;
    if (stateFilter || needle) {
      findingRevision++;
      return;
    }
    try {
      const [updated] = await api<FindingTracking[]>(classificationsPath(target.scanId, target.finding));
      if (scan?.id === target.scanId) {
        findingPages.items = findingPages.items.map(item => item.id === target.finding
          ? {...item,tracking:updated ?? {finding: target.finding, status:'open', note:''}} : item);
      }
    } catch {
      findingRevision++;
    }
  }
  async function action(kind: string) {
    if (!scan || busy) return;
    busy = true;
    issue = '';
    try {
      const path = '/scans/' + scan.id;
      if (kind === 'cancel') {
        await api(path + '/cancel', post({}));
        scan = await api(path + '/report/summary');
      } else {
        const result = await api<{ id: string }>(path + '/rescan', post({}));
        await goto('/scans/' + result.id);
      }
    } catch (error) { issue = message(error); }
    finally { busy = false; }
  }

  $effect(() => {
    const id = scanId;
    const finding = focusedFinding;
    const openTracking = requestedTracking;
    scannerTabVisited = false;
    collapsedGroups = new Set();
    searches = {findings:finding, packages:'', checks:''};
    severityFilter = '';
    ecosystem = '';
    stateFilter = '';
    limit = 100;
    tracking = undefined;
    cbomIssue = '';
    watch = undefined; watchIssue = '';
    const controller = new AbortController();
    scan = undefined;
    issue = '';
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    let listener: EventSource | undefined;
    progress = undefined; reconnecting = false; layerData = undefined; selectedLayer = undefined; viewingLayers = false; layersBusy = false; layersIssue = ''; layerLoading = undefined;
    publishing = false; publishIssue = ''; destination = ''; destinationRegistry = ''; sources = []; artifactStatus = 'loading';
    async function refresh() {
      try {
        const result = await api<Summary>('/scans/' + id + '/report/summary', {signal:controller.signal});
        if (disposed) return;
        scan = result;
        issue = '';
        if (openTracking && finding && result.report) {
          void edit(finding);
        }
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
    return () => { disposed = true; controller.abort(); editRequest?.abort(); clearTimeout(timer); listener?.close(); };
  });
</script>

<svelte:document onclick={closeOutsideMenus} onfocusin={closeOutsideMenus} onkeydown={dismissMenu} />
<svelte:head><title>Scan report · {productName}</title></svelte:head>

<FindingTracker target={tracking} findingSources={tracking && new Map(tracking.details.map(detail => [detectionKey(detail), detectors(detail)]))} evidenceUnavailable={findingPages.first?.evidenceAvailable === false} dismiss={() => {tracking = undefined;}} onSaved={trackingSaved} />
{#if issue}<div class="notice error" role="alert">{issue}</div>{/if}
{#if feedback}<div class="notice success" role="status">{feedback}</div>{/if}
{#if scan}
  <div class="page-heading scan-heading">
    <div><a class="crumb" href="/">Scan desk</a><h1 class="reference-title">{imageName(scan.reference)}</h1><p class="mono break">{scan.reference}</p>{#if demo}<p><span class="badge neutral">Demo image</span></p>{/if}</div>
    <div class="filters scan-commands">
      {#if auth.operator && active(scan)}
        <button class="button secondary" onclick={() => action('cancel')} disabled={busy}>Cancel scan</button>
      {:else if auth.operator && !demo && (scan.status === 'failed' || scan.status === 'cancelled')}
        <a class="button primary" href={'/scans/new?retry=' + scan.id}>Edit and retry</a>
        {#if scan.source !== 'archive'}<button class="button secondary" onclick={() => action('rescan')} disabled={busy}>Retry scan</button>{/if}
      {:else if auth.operator && scan.source !== 'archive' && !demo}
        <button class="button secondary" onclick={() => action('rescan')} disabled={busy}><RotateCcw size={16} aria-hidden="true" /> Rescan</button>
      {/if}
      {#if scan.report}
        <a class="button secondary" href={'/compare?target=' + scan.id}><GitCompareArrows size={17} aria-hidden="true" /> Compare versions</a>
        <details class="image-menu" bind:this={imageMenu}>
          <summary class="button secondary">Image actions <ChevronDown size={16} aria-hidden="true" /></summary>
          <div class="image-menu-panel" role="group" aria-label="Image actions">
            <a href={'/api/images/' + scan.id + '/archive'} data-sveltekit-reload onclick={() => closeImageMenu(true)}>Download image archive</a>
            <button type="button" aria-haspopup="dialog" disabled={layersBusy} onclick={layers}>Inspect image layers</button>
            <a href={'/patches?scan=' + scan.id} onclick={() => closeImageMenu()}>Analyze patches</a>
            {#if auth.operator}
              {#if !demo && scan.source !== 'docker' && scan.source !== 'archive'}
                <a href={'/scheduled-scans?' + new URLSearchParams({image:scan.reference,platform:scan.platform})} onclick={() => closeImageMenu()}>Schedule rescans</a>
              {/if}
              {#if watch === null}
                <button type="button" disabled={watchBusy} onclick={() => {closeImageMenu(true); void enableWatch();}}><Bell size={16} aria-hidden="true" /> Watch new vulnerabilities</button>
              {:else if watch}
                <a href="/settings#image-watches" onclick={() => closeImageMenu()}><Bell size={16} aria-hidden="true" /> Manage image watch</a>
              {/if}
              <button type="button" class="publish-action" aria-haspopup="dialog" disabled={busy} onclick={openPublish}>Publish image</button>
            {/if}
          </div>
        </details>
      {/if}
    </div>
  </div>

  {#if !scan.report}<ScanActivity {scan} {progress} {reconnecting} />{/if}

    <section class="panel" id="image-details" aria-labelledby="image-details-title">
      <div class="panel-title image-details-title">
        <h2 id="image-details-title">Image details</h2>
        {#if scan.report && scan.source !== 'import'}<a class="table-link metadata-link" href="#scan-activity">Scan activity</a>{/if}
      </div>
      <div class="scan-meta">
        <div><span>Status</span><Status status={scan.status} /></div>
        <div><span>Platform</span><strong class="mono">{scan.platform}</strong></div>
        {#if scan.report?.scanners?.length}<div><span>Scanners</span><strong>{scan.report.scanners.map(scannerName).join(', ')}</strong></div>{/if}
        <div><span>Created</span><strong>{time(scan.createdAt)}</strong></div>
        <div><span>Source</span><strong>{sourceLabels[scan.source] || scan.source}</strong></div>
        {#if scan.report?.os}<div><span>Operating system</span><strong>{scan.report?.os}</strong></div>{/if}
        {#if scan.report?.sizeBytes}<div><span>Image size</span><strong>{scan.report.sizeBytes < 1024 ? scan.report.sizeBytes + ' B' : scan.report.sizeBytes < 1048576 ? (scan.report.sizeBytes / 1024).toFixed(1) + ' KiB' : (scan.report.sizeBytes / 1048576).toFixed(1) + ' MiB'}</strong></div>{/if}
        {#if scan.report?.digest}
          {@const digest = scan.report?.digest}
          <div class="digest"><span>Image digest</span><span class="digest-value">
            <code class="mono" title={digest}>{digest.length > 30 ? digest.slice(0, 19) + '…' + digest.slice(-8) : digest}</code>
            <button type="button" class="copy-button" aria-label="Copy image digest" onclick={() => copyDigest(digest)}>
              {#if digestCopied}<Check size={14} aria-hidden="true" /> Copied{:else}<Copy size={14} aria-hidden="true" /> Copy{/if}
            </button>
          </span></div>
        {/if}
      </div>
    </section>
  {#if watch}<p class="field-help image-watch-status" role="status">Watching {scan.platform} for advisories detected on future scans.</p>{/if}
  {#if watchIssue}<div class="notice error" role="alert">{watchIssue}</div>{/if}

  {#if scan.error}<div class="notice error" role="alert">{scan.error}
    {#if scan.status === 'failed'}<a class="table-link" href={'/images?' + new URLSearchParams({q: repositoryName(scan.reference)})}>View image history</a>{/if}
  </div>{/if}
  {#if scan.report}
    {#if scan.report.observationComplete === false}
      <div class="notice warning" role="status">Vulnerability observations are incomplete. This report shows recorded detections.</div>
    {/if}
    <!-- svelte-ignore a11y_no_noninteractive_tabindex (Direct finding links move focus to the report.) -->
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
        <button type="button" class="button secondary" aria-pressed={tab === 'downloads'} onclick={async () => {await selectView('downloads'); await jumpTo('report-downloads-title');}}>
          <Download size={16} aria-hidden="true" /> Downloads
        </button>
      </div>
      <div class="tabs compact report-views" role="group" aria-label="Report views">
        <button type="button" class:tab-active={tab === 'findings'} aria-pressed={tab === 'findings'} onclick={() => selectView('findings')}>
          Findings <span>{totalFindings}</span>
        </button>
        <button type="button" class:tab-active={tab === 'packages'} aria-pressed={tab === 'packages'} onclick={() => selectView('packages')}>
          Packages <span>{scan.report.counts.packages}</span>
        </button>
        <button type="button" class:tab-active={tab === 'checks'} aria-pressed={tab === 'checks'} onclick={() => selectView('checks')}>
          Image checks <span>{scan.report.checks.length}</span>
        </button>
        {#if completedScanners.length >= 2}
          <button type="button" class:tab-active={tab === 'scanners'} aria-pressed={tab === 'scanners'} onclick={() => selectView('scanners')}>
            Scanner differences
          </button>
        {/if}
      </div>

      {#if scannerTabVisited || tab === 'scanners'}
        <div hidden={tab !== 'scanners'}>
          {#key scan.id}<ScannerDifferences scanId={scan.id} {completedScanners} incomplete={scan.report.observationComplete === false} onFinding={readFinding} active={tab === 'scanners'} />{/key}
        </div>
      {/if}
      {#if tab === 'downloads'}
        <section class="report-downloads" aria-labelledby="report-downloads-title">
          <!-- svelte-ignore a11y_no_noninteractive_tabindex (The downloads control moves focus here.) -->
          <h3 id="report-downloads-title" tabindex="-1">Report downloads</h3>
          <div class="download-group">
            <h4>Formatted report</h4>
            <div class="filters">
              {#each reportFormats as [format, label]}
                <a class="button secondary" href={'/api/scans/' + scan.id + '/report/' + format} data-sveltekit-reload>{label}</a>
              {/each}
              {#if totalFindings}<a class="button secondary" href={'/api/scans/' + scan.id + '/report/vex'} data-sveltekit-reload>OpenVEX</a>{/if}
            </div>
          </div>
          <div class="download-group">
            <h4>Package inventory</h4>
            <div class="filters">
              {#if sbomAvailable}
                <a class="button secondary" href={'/api/scans/' + scan.id + (scan.report.inventoryAvailable ? '/report/sbom' : '/scanner-results/sbom')} data-sveltekit-reload>Download CycloneDX SBOM</a>
              {/if}
              {#if scan.report.inventoryAvailable}
                <a class="button secondary" href={'/api/scans/' + scan.id + '/report/spdx'} data-sveltekit-reload>Download SPDX JSON</a>
              {/if}
              {#if cbomCandidate}
                <button type="button" class="button secondary" disabled={cbomBusy} onclick={downloadCbom}>{cbomBusy ? 'Downloading…' : 'CBOM'}</button>
              {/if}
            </div>
            {#if !sbomAvailable}
              <p class="field-help" role="status">
                {#if artifactStatus === 'loading'}Checking for a scanner SBOM…
                {:else if artifactStatus === 'error'}Could not check for a scanner SBOM. <a class="table-link" href={page.url.pathname + page.url.search} data-sveltekit-reload>Reload report</a>
                {:else}This scan has no package inventory to export.{/if}
              </p>
            {/if}
            {#if cbomIssue}<p role="alert" class="export-error">{cbomIssue}</p>{/if}
          </div>
          {#if sources.length || completedScanners.length >= 2}
            <div class="download-group">
              <h4>Scanner evidence</h4>
              <div class="filters">
                {#each sources as source}
                  <a class="button secondary" href={'/api/scans/' + scan.id + '/scanner-results/' + source} data-sveltekit-reload>{source === 'scheduled-sbom' ? 'Retained CycloneDX SBOM' : source === 'sbom' ? 'Scanner-produced SBOM' : scannerName(source) + ' artifact'}</a>
                {/each}
                {#if completedScanners.length >= 2}<a class="button secondary" href={'/api/scans/' + scan.id + '/report/discrepancies'} data-sveltekit-reload>Discrepancy report</a>{/if}
              </div>
            </div>
          {/if}
        </section>
      {:else if tab !== 'scanners'}
        {#if tab === 'findings' && ecosystems.length > 1}
          <div class="ecosystem-filters" role="group" aria-label="Filter findings by ecosystem">
            <span class="field-help ecosystem-label">Ecosystem</span>
            <button type="button" aria-pressed={!ecosystem} onclick={() => showEcosystem('')}>All</button>
            {#each ecosystems as name (name)}
              <button type="button" aria-pressed={ecosystem === name} onclick={() => showEcosystem(name)}>{name}</button>
            {/each}
          </div>
        {/if}
        {#if tab === 'findings' && totalFindings}
          <div class="finding-severities" role="group" aria-label="Filter findings by severity">
            {#each severity as level}
              {#if severityCounts[level] > 0}
                <button type="button" class="severity-filter" aria-pressed={severityFilter === level} onclick={() => {severityFilter = severityFilter === level ? '' : level; limit = 100;}}>
                  <span class={'severity ' + level}>{level}</span>
                  <strong>{severityCounts[level]}</strong>
                </button>
              {/if}
            {/each}
          </div>
        {/if}
        <div class="report-toolbar filters">
          {#if (tab === 'findings' && totalFindings) || (tab === 'packages' && scan.report.counts.packages) || (tab === 'checks' && scan.report.checks.length)}
            <label class="search"><Search size={17} aria-hidden="true" /><input aria-label={tab === 'findings' ? 'Filter report' : tab === 'packages' ? 'Search packages' : 'Search image checks'} placeholder={tab === 'findings' ? 'Search CVEs or packages' : tab === 'packages' ? 'Search packages' : 'Search image checks'} bind:value={searches[tab]} oninput={() => { limit = 100; }} /></label>
          {/if}
          {#if tab === 'findings' && totalFindings}
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
          {#if tab === 'findings' && findingGroups.size}
            <select aria-label="Filter findings by status" bind:value={stateFilter} onchange={() => {limit = 100;}}>
              <option value="">All statuses</option>
              {#each trackingFilters as [value,label]}<option {value}>{label}</option>{/each}
            </select>
          {/if}
          {#if tab === 'findings' && hasFindingFilters}
            {#if findingPages.first}<span class="field-help" role="status">{findings.total} matching {findings.total === 1 ? 'finding' : 'findings'}</span>{/if}
            <button type="button" class="text-button clear-filters" onclick={clearFindingFilters}>Clear filters</button>
          {/if}
        </div>
      <!-- svelte-ignore a11y_no_noninteractive_tabindex (Report tables can scroll horizontally on narrow screens.) -->
      <div class="table-wrap" role="region" aria-labelledby="report-content-title" tabindex="0">
        {#if tab === 'findings' && !totalFindings}
          <div class="empty report-empty">
            <h3>No vulnerabilities reported</h3>
            {#if scan.report.inventoryAvailable}
              <p>Review the package inventory for this scan.</p>
              <button class="button secondary" onclick={() => selectView('packages')}>View packages</button>
            {/if}
          </div>
        {:else if tab === 'findings'}
          <table class="findings-table">
            <thead><tr><th scope="col">Finding</th><th scope="col">Severity</th>{#each visibleColumns as column (column.id)}<th scope="col">{column.label}</th>{/each}</tr></thead>
            {#each findings.groups as group (group.name)}
              <tbody>
                <tr class="ecosystem-heading"><th colspan={2 + visibleColumns.length} scope="rowgroup">
                  {#if ecosystem}
                    {group.name} <span>{group.total}</span>
                  {:else}
                    <button type="button" aria-expanded={!group.collapsed} onclick={() => toggleGroup(group.name)}>
                      <ChevronRight size={16} aria-hidden="true" /> {group.name} <span>{group.total}</span>
                    </button>
                  {/if}
                </th></tr>
                {#each group.items as item}
                  {@const annotation = item.tracking}
                  <tr class="finding-row">
                    <td><button type="button" class="finding-button table-link mono" aria-haspopup="dialog" aria-label={'View details for ' + item.id}
                      onclick={() => edit(item.id)}><span>{item.id}</span><ChevronRight size={15} aria-hidden="true" /></button>{#if item.aliases?.length}<small class="mono">Aliases · {item.aliases.join(', ')}</small>{/if}{#if item.title}<small class="finding-summary">{findingDescription(item.title).summary}</small>{/if}
                      <div class="mobile-finding-summary">
                        <small>{item.package} · {item.installed || 'Version unavailable'}</small>
                        <small>{item.fixed ? 'Fix · ' + item.fixed : 'No fix reported'}</small>
                        <small>Tracking · {trackingStatus(effectiveTrackingStatus(annotation))}</small>
                        {#if detectors(item).length}<small>Detected by · {detectors(item).join(', ')}</small>{/if}
                        {#if annotation?.issue}<IssueLink issue={annotation.issue} />{/if}
                      </div>
                    </td>
                    <td><span class={'severity ' + item.severity.toLowerCase()}>{item.severity.toLowerCase()}</span></td>
                    {#each visibleColumns as column (column.id)}
                      <td>
                        {#if column.id === 'package'}{item.package}<small>{item.ecosystem}</small>
                        {:else if column.id === 'installed'}<span class="mono version">{item.installed || '—'}</span>
                        {:else if column.id === 'fix'}<span class="mono version">{item.fixed || '—'}</span>
                        {:else if column.id === 'scanners'}
                          {#each detectors(item) as detector (detector)}<span class="badge neutral detector">{detector}</span>
                          {:else}<span class="field-help">{findingPages.first?.evidenceAvailable === false ? 'Unavailable' : 'Not recorded'}</span>{/each}
                        {:else if column.id === 'tracking'}
                          <button type="button" class="status-chip" data-status={effectiveTrackingStatus(annotation)} aria-haspopup="dialog" aria-label={(auth.operator ? 'Edit' : 'View') + ' tracking for ' + item.id}
                            onclick={() => edit(item.id)}>{trackingStatus(effectiveTrackingStatus(annotation))} <ChevronDown size={13} aria-hidden="true" /></button>
                        {:else if annotation?.issue}<IssueLink issue={annotation.issue} />
                        {:else}<span class="field-help">—</span>{/if}
                      </td>
                    {/each}
                  </tr>
                {/each}
              </tbody>
            {:else}{#if !findingPages.busy && !findingPages.error}<tbody><tr><td colspan={2 + visibleColumns.length}>No findings match the filters.</td></tr></tbody>{/if}{/each}
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
        {#if tab === 'findings'}
          <AutoPage busy={findingPages.busy} more={!!findingPages.next} error={findingPages.error} label="findings" load={() => findingPages.more()} />
        {:else if countShown > limit}<div class="panel-footer"><button class="button secondary" onclick={() => { limit += 100; }}>Show 100 more</button></div>{/if}
      {/if}
    </section>
    <ScanActivity {scan} {progress} {reconnecting} />
    <ConfigDialog id="publish-image" title="Publish image" description={scan.reference} open={publishing} {busy}
      dismiss={() => {publishing = false;}} onsubmit={publish}>
      <label class="field"><span>Destination image</span><input class="mono" required bind:value={destination} placeholder="registry.example.com/team/app:tag" /></label>
      <label class="field"><span>Destination credentials</span><select bind:value={destinationRegistry}>
        <option value="">Anonymous</option>
        {#each registries as registry}<option value={registry.id}>{registry.name}</option>{/each}
      </select></label>
      {#if publishIssue}<p class="notice error" role="alert">{publishIssue}</p>{/if}
      {#snippet actions()}
        <button type="button" class="button secondary" disabled={busy} onclick={() => {publishing = false;}}>Cancel</button>
        <button type="submit" class="button primary" disabled={busy}>Publish</button>
      {/snippet}
    </ConfigDialog>

    <ConfigDialog id="image-layers" title="Image layers" description={scan.reference} open={viewingLayers}
      dismiss={() => {viewingLayers = false;}}>
      {#if layersIssue}<p class="notice error" role="alert">{layersIssue}</p>{/if}
      {#if layersBusy}<p role="status">Loading image layers…</p>
      {:else if !layerData}<button type="button" class="button secondary" onclick={layers}>Try again</button>
      {:else}
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
      {#snippet actions()}
        <button type="button" class="button secondary" onclick={() => {viewingLayers = false;}}>Close</button>
      {/snippet}
    </ConfigDialog>
  {/if}
{:else if !issue}
  <div class="empty" role="status">Loading scan…</div>
{/if}

<style>
  .scan-heading { margin-bottom: .85rem; }
  .scan-commands { position: relative; max-width: 100%; }
  .image-menu > summary { list-style: none; }
  .image-menu > summary::-webkit-details-marker { display: none; }
  .image-menu[open] > summary { background: var(--accent-soft); border-color: var(--accent-ink); color: var(--accent-ink); }
  .image-menu-panel { position: absolute; inset-block-start: calc(100% + .35rem); inset-inline-end: 0; z-index: 8; display: grid; gap: .15rem; width: 15rem; max-width: 100%; padding: .35rem; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); box-shadow: 0 .45rem 1.2rem color-mix(in srgb, var(--rail) 15%, transparent); }
  .image-menu-panel :is(a, button) { display: flex; align-items: center; gap: .4rem; min-height: 42px; border: 0; border-radius: var(--radius); padding: .45rem .65rem; background: var(--surface); color: var(--ink); font-size: var(--text-label); font-weight: 650; text-decoration: none; text-align: start; }
  .image-menu-panel :is(a, button):hover:not(:disabled) { background: var(--inset); }
  .image-menu-panel .publish-action { border-top: 1px solid var(--line); border-radius: 0 0 var(--radius) var(--radius); }
  #image-details { margin-bottom: .85rem; }
  .image-details-title { padding-block: .5rem; }
  .scan-meta { display: flex; flex-wrap: wrap; align-items: center; gap: .4rem 1.15rem; padding: .65rem 1rem; }
  .scan-meta > div { display: inline-flex; flex-wrap: wrap; align-items: baseline; gap: .2rem .4rem; }
  .scan-meta > div:first-child { align-items: center; }
  .scan-meta .digest-value { flex-wrap: wrap; }
  .metadata-link { display: inline-flex; align-items: center; margin-inline-start: auto; min-height: 30px; font-size: var(--text-detail); }
  .image-watch-status { margin: .2rem 0 .75rem; }
  .digest-value { display: flex; align-items: center; gap: .55rem; min-width: 0; }
  .digest-value code { font-size: .82rem; font-weight: 600; white-space: nowrap; }
  .copy-button { display: inline-flex; align-items: center; gap: .3rem; min-height: 28px; padding: .15rem .5rem; border: 1px solid var(--line); border-radius: 6px; background: var(--surface); color: var(--muted); font-size: .74rem; font-weight: 750; }
  .copy-button:hover { border-color: var(--control-line); background: var(--inset); color: var(--ink); }
  .table-wrap:focus-visible { outline-offset: -3px; }
  #scan-findings, #report-downloads-title, #image-details { scroll-margin-top: 5rem; }
  .focused-advisory { display: inline-block; margin-top: .24rem; font-size: .78rem; }
  .report-title { padding-block: .7rem; }
  .report-title .button[aria-pressed='true'] { border-color: var(--accent-ink); color: var(--accent-ink); background: var(--accent-soft); }
  .report-views.tabs { border-bottom: 1px solid var(--line); gap: .25rem; padding-inline: .9rem; }
  .report-views button { justify-content: center; min-height: 44px; }
  .report-views button span { font-variant-numeric: tabular-nums; font-weight: 600; }
  .report-toolbar { padding: .6rem 1rem; border-bottom: 1px solid var(--line); }
  .report-toolbar:empty { display: none; }
  .ecosystem-filters { display: flex; align-items: center; flex-wrap: wrap; gap: .35rem; padding: .65rem 1rem 0; }
  .ecosystem-label { margin-inline-end: .25rem; }
  .ecosystem-filters button { min-height: 34px; padding: .3rem .62rem; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); color: var(--ink); font-size: var(--text-label); font-weight: 650; }
  .ecosystem-filters button:hover { background: var(--inset); border-color: var(--control-line); }
  .ecosystem-filters button[aria-pressed='true'] { border-color: var(--accent-ink); background: var(--accent-soft); color: var(--accent-ink); }
  .finding-severities { display: flex; gap: .4rem; flex-wrap: wrap; padding: .65rem 1rem 0; }
  .severity-filter { display: inline-flex; gap: .42rem; align-items: center; min-height: 40px; padding: .3rem .45rem; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); color: var(--ink); font-size: var(--text-label); }
  .severity-filter:hover { background: var(--inset); border-color: var(--control-line); }
  .severity-filter[aria-pressed='true'] { background: var(--accent-soft); border-color: var(--accent-ink); }
  .severity-filter strong { font-variant-numeric: tabular-nums; }
  .clear-filters { color: var(--accent-ink); font-size: var(--text-label); min-height: 32px; }
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
  .findings-table thead th:first-child { min-width: 11rem; }
  .finding-button { display: inline-flex; align-items: center; gap: .25rem; border: 0; padding: .15rem 0; background: transparent; text-align: start; overflow-wrap: anywhere; }
  .finding-button :global(svg) { flex: none; }
  .finding-summary { display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2; line-clamp: 2; overflow: hidden; }
  .detector { margin: .15rem .22rem .15rem 0; text-transform: none; }
  .report-empty { padding-block: 1.85rem; }
  .report-downloads { display: grid; gap: .9rem; padding: 1rem 1.15rem; }
  .mobile-finding-summary { display: none; }
  .download-group { display: grid; align-content: start; gap: .5rem; }
  .download-group + .download-group { border-top: 1px solid var(--line); padding-top: .75rem; }
  .download-group h4 { margin: 0; font-size: var(--text-label); }
  .export-error { color: var(--critical); }

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
  .ecosystem-heading:has(button) th { padding-block: .15rem; }
  .ecosystem-heading button { display: flex; align-items: center; gap: .35rem; width: 100%; padding: .35rem 0; min-height: 40px; border: 0; background: transparent; color: inherit; font: inherit; font-weight: 750; text-align: start; }
  .ecosystem-heading button:hover { color: var(--accent-ink); }
  .ecosystem-heading button[aria-expanded='true'] :global(svg) { transform: rotate(90deg); }
  @media (max-width: 620px) {
    .scan-heading { gap: .65rem; }
    .image-details-title { padding-inline: .75rem; }
    .image-menu-panel :is(a, button) { min-height: 44px; }
    .scan-meta { gap: .35rem .75rem; padding: .65rem .75rem; }
    .scan-meta > div { gap: .15rem .35rem; }
    .scan-meta .digest { flex-basis: 100%; }
    .scan-meta > div > span:first-child, .scan-meta strong { font-size: var(--text-detail); }
    .metadata-link { justify-self: start; margin-inline-start: 0; }
    .report-title { padding-inline: .75rem; }
    .report-views.tabs { padding-inline: .55rem; gap: .2rem; }
    .report-views button { flex: 1 1 45%; }
    .report-toolbar { padding-inline: .75rem; }
    .ecosystem-filters { padding-inline: .75rem; }
    .ecosystem-filters button { min-height: 40px; }
    .report-toolbar .search { flex: 1 1 100%; }
    .report-toolbar .search input { flex: 1; max-width: none; }
    .column-menu { display: none; }
    .finding-severities { padding-inline: .75rem; }
    .findings-table { min-width: 0; }
    .findings-table thead th, .findings-table thead th:first-child { min-width: 0; }
    .findings-table thead th:nth-child(2) { width: 6rem; }
    .findings-table thead th:nth-child(n+3), .finding-row td:nth-child(n+3) { display: none; }
    .findings-table td { overflow-wrap: anywhere; }
    .mobile-finding-summary { display: grid; gap: .16rem; margin-top: .45rem; }
    .mobile-finding-summary small { margin: 0; }
  }
</style>
