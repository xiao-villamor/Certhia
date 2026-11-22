<script lang="ts">
  import { auth } from '#lib/auth.svelte.js';
  import { productName, productSlug } from '#lib/product.js';
  import { onMount, tick } from 'svelte';
  import { ArrowDown, ArrowRight, GripVertical, ScanLine, Search, SlidersHorizontal } from '@lucide/svelte';
  import { active, api, apiPage, imageName, message, shortDigest, time, type Scan } from '#lib/api.js';
  import { findingsByImage, type Advisory, type ImageFinding } from '#lib/library.js';
  import IssueLink from '#lib/IssueLink.svelte';
  import Status from '#lib/Status.svelte';
  import RiskChart from '#lib/RiskChart.svelte';
  import PackageChart from '#lib/PackageChart.svelte';
  import ScanVolumeChart from '#lib/ScanVolumeChart.svelte';

  const levels = ['critical', 'high', 'medium', 'low', 'unknown'] as const;
  type Severity = (typeof levels)[number];
  interface Dashboard {
    scans: number;
    completed: number;
    registries: number;
    active: number;
    failed: number;
    severity: Record<Severity, number>;
    historicalSeverity: Record<Severity, number>;
    openWithFix: number;
    incompleteLatest: number;
  }

  const panels = [
    { id: 'overview', label: 'Workspace overview', visible: true },
    { id: 'triage', label: 'Needs triage', visible: true },
    { id: 'severity', label: 'Findings by severity', visible: true },
    { id: 'activity', label: 'Scan activity', visible: true },
    { id: 'volume', label: 'Scan volume', visible: true },
    { id: 'packages', label: 'Most affected package versions', visible: true },
    { id: 'risk', label: 'Severity-weighted risk', visible: false }
  ] as const;
  type Panel = (typeof panels)[number]['id'];
  interface DeskPreferences {
    panels: Panel[];
    order: Panel[];
    density: 'comfortable' | 'compact';
  }
  const defaultPreferences: DeskPreferences = {
    panels: panels.filter(panel => panel.visible).map(panel => panel.id),
    order: panels.map(panel => panel.id),
    density: 'comfortable'
  };
  const preferencesKey = `${productSlug}.scan-desk`;
  let preferences = $state<DeskPreferences>(defaultPreferences);
  let settingsOpen = $state(false);
  let preferencesError = $state(false);
  let orderNotice = $state('');
  let customizeButton: HTMLButtonElement;
  let deskGrid: HTMLDivElement;
  let moveMenu = $state<Panel>();
  let dragging = $state<Panel>();
  let destination = $state<Panel>();
  let dragPosition = $state({ x: 0, y: 0 });
  let drag: { id: Panel; pointer: number; x: number; y: number; startX: number; startY: number } | undefined;
  let scrollFrame = 0;
  let suppressClick = false;
  const visiblePanels = $derived(preferences.order.filter(id => preferences.panels.includes(id)));
  const panelLabels = new Map(panels.map(panel => [panel.id, panel.label]));

  const panelLayout = $derived.by(() => {
    const layout: { id: Panel; span: number }[] = [];
    function isWide(id: Panel) {
      return id === 'overview' || id === 'activity';
    }
    for (let index = 0; index < visiblePanels.length; index += 1) {
      const id = visiblePanels[index];
      const next = visiblePanels[index + 1];
      if (isWide(id) || !next || isWide(next)) {
        layout.push({ id, span: 12 });
      } else {
        const firstSpan = id === 'triage' ? 8 : next === 'triage' ? 4 : 6;
        layout.push({ id, span: firstSpan }, { id: next, span: 12 - firstSpan });
        index += 1;
      }
    }
    return layout;
  });

  function readPreferences(): DeskPreferences {
    try {
      const saved = JSON.parse(localStorage.getItem(preferencesKey) ?? 'null') as (Partial<DeskPreferences> & { first?: string }) | null;
      if (saved) {
        const legacyOrder: Panel[] = saved.first === 'activity'
          ? ['overview', 'activity', ...defaultPreferences.order.filter(id => id !== 'overview' && id !== 'activity')]
          : defaultPreferences.order;
        const savedOrder = Array.isArray(saved.order) ? saved.order.filter(id => panelLabels.has(id)) : legacyOrder;
        const selected = saved.panels;
        return {
          order: [...new Set([...savedOrder, ...defaultPreferences.order])],
          panels: Array.isArray(selected)
            ? defaultPreferences.order.filter(id => id === 'activity' || (id === 'overview' && !Array.isArray(saved.order)) || selected.includes(id))
            : defaultPreferences.panels,
          density: saved.density === 'compact' ? 'compact' : defaultPreferences.density
        };
      }
    } catch {
      // The desk can still render with defaults when browser storage is unavailable.
    }
    return defaultPreferences;
  }

  function updatePreferences(next: DeskPreferences) {
    const historicalTotal = $derived(summary && levels.reduce((total, level) => total + summary!.historicalSeverity[level], 0));
  const showTriage = next.panels.includes('triage') && !preferences.panels.includes('triage');
    preferences = next;
    if (showTriage) void refreshTriage();
    try {
      localStorage.setItem(preferencesKey, JSON.stringify(next));
      preferencesError = false;
    } catch {
      preferencesError = true;
    }
  }

  async function togglePanel(id: Panel, visible: boolean) {
    const next = visible ? [...preferences.panels, id] : preferences.panels.filter(panel => panel !== id);
    updatePreferences({ ...preferences, panels: next });
    await tick();
    if (visible) document.getElementById('move-panel-' + id)?.focus();
    else {
      const options = document.querySelector<HTMLDetailsElement>('.edit-options');
      if (options) options.open = true;
      document.getElementById('desk-visibility-' + id)?.focus();
    }
  }

  async function movePanel(id: Panel, target: number, restoreFocus = false) {
    const position = visiblePanels.indexOf(id);
    if (position < 0 || target < 0 || target >= visiblePanels.length || position === target) return;
    const reordered = visiblePanels.filter(panel => panel !== id);
    reordered.splice(target, 0, id);
    let index = 0;
    const order = preferences.order.map(panel => preferences.panels.includes(panel) ? reordered[index++] : panel);
    updatePreferences({ ...preferences, order });
    orderNotice = `${panelLabels.get(id)} moved to position ${target + 1} of ${visiblePanels.length}.`;
    if (restoreFocus) {
      moveMenu = undefined;
      await tick();
      document.getElementById('move-panel-' + id)?.focus();
    }
  }

  function updateDestination() {
    if (!drag) return;
    const { x, y, id } = drag;
    const element = document.elementFromPoint(x, y)?.closest<HTMLElement>('[data-panel]');
    const target = element?.dataset.panel as Panel | undefined;
    destination = element?.parentElement === deskGrid && target !== id ? target : undefined;
  }

  function scrollDuringDrag() {
    if (!drag || !dragging) return;
    const zone = Math.min(150, window.innerHeight / 4);
    const speed = drag.y < zone ? -Math.ceil((zone - drag.y) / 7)
      : drag.y > window.innerHeight - zone ? Math.ceil((drag.y - window.innerHeight + zone) / 7) : 0;
    if (speed) {
      window.scrollBy(0, speed);
      updateDestination();
    }
    scrollFrame = requestAnimationFrame(scrollDuringDrag);
  }

  function pointerDown(event: PointerEvent, id: Panel) {
    if (!event.isPrimary || event.button !== 0 || drag) return;
    suppressClick = false;
    const { pointerId, clientX, clientY } = event;
    drag = { id, pointer: pointerId, x: clientX, y: clientY, startX: clientX, startY: clientY };
    event.currentTarget instanceof HTMLElement && event.currentTarget.setPointerCapture(pointerId);
  }

  function pointerMove(event: PointerEvent) {
    if (!drag || drag.pointer !== event.pointerId) return;
    drag.x = event.clientX;
    drag.y = event.clientY;
    if (!dragging && Math.hypot(drag.x - drag.startX, drag.y - drag.startY) >= 6) {
      dragging = drag.id;
      moveMenu = undefined;
      scrollFrame = requestAnimationFrame(scrollDuringDrag);
    }
    if (dragging) {
      dragPosition = { x: Math.min(drag.x + 12, window.innerWidth - 156), y: Math.max(0, drag.y - 44) };
      updateDestination();
    }
  }

  function finishDrag(event?: PointerEvent, commit = false) {
    if (!drag || (event && drag.pointer !== event.pointerId)) return;
    const id = drag.id;
    const target = destination;
    suppressClick = Boolean(dragging);
    drag = undefined;
    dragging = undefined;
    destination = undefined;
    cancelAnimationFrame(scrollFrame);
    if (commit && target) void movePanel(id, visiblePanels.indexOf(target));
  }

  function closeSettings() {
    finishDrag();
    settingsOpen = false;
    moveMenu = undefined;
    customizeButton.focus();
  }

  function panelKeys(event: KeyboardEvent, id: Panel) {
    const position = visiblePanels.indexOf(id);
    const target = event.key === 'ArrowUp' || event.key === 'ArrowLeft' ? position - 1
      : event.key === 'ArrowDown' || event.key === 'ArrowRight' ? position + 1
        : event.key === 'Home' ? 0 : event.key === 'End' ? visiblePanels.length - 1 : undefined;
    if (target === undefined) return;
    event.preventDefault();
    void movePanel(id, target, true);
  }

  const number = new Intl.NumberFormat();
  let summary = $state<Dashboard>();
  let summaryError = $state('');
  let triage = $state<ImageFinding[]>();
  let triageError = $state('');
  let triageRequest: AbortController | undefined;
  let recent = $state<Scan[]>();
  const hasDemo = $derived(recent?.some(scan => scan.reference.startsWith('demo-fixtures.invalid/')));
  let recentError = $state('');
  let recentCursor = $state<string | null>(null);
  let overviewRequest: AbortController | undefined;

  let filtered = $state<Scan[]>([]);
  let filteredCursor = $state<string | null>(null);
  let filterLoading = $state(false);
  let filterError = $state('');
  let extra = $state<Scan[]>([]);
  let extraCursor = $state<string | null>(null);
  let firstPage = $state<Scan[]>();
  let paging = $state(false);
  let pageError = $state('');
  let query = $state('');
  let status = $state('');
  let activity: HTMLElement;
  let filterRequest: AbortController | undefined;
  let pageRequest: AbortController | undefined;

  const hasFilters = $derived(Boolean(query.trim() || status));
  const scans = $derived.by(() => {
    const first = firstPage ?? (hasFilters ? filtered : recent ?? []);
    const seen = new Set(first.map(scan => scan.id));
    return [...first, ...extra.filter(scan => !seen.has(scan.id))];
  });
  const next = $derived(firstPage ? extraCursor : hasFilters ? filteredCursor : recentCursor);
  const loading = $derived(hasFilters ? filterLoading : !recent && !recentError);
  const activityError = $derived(hasFilters ? filterError : recentError);
  const findingTotal = $derived(levels.reduce((total, level) => total + (summary?.severity[level] ?? 0), 0));
  const historicalTotal = $derived(summary && levels.reduce((total, level) => total + summary!.historicalSeverity[level], 0));
  const showTriage = $derived(preferences.panels.includes('triage'));

  function count(value: number | undefined) {
    return value === undefined ? '—' : number.format(value);
  }

  async function refreshOverview() {
    if (overviewRequest) return;
    const controller = new AbortController();
    overviewRequest = controller;
    const { signal } = controller;
    await Promise.all([
      api<Dashboard>('/dashboard', { signal }).then(result => {
        if (signal.aborted) return;
        summary = result;
        summaryError = '';
      }).catch(error => { if (!signal.aborted) summaryError = message(error); }),
      apiPage<Scan[]>('/scans', null, { signal }).then(result => {
        if (signal.aborted) return;
        recent = result.items;
        recentCursor = result.next;
        recentError = '';
      }).catch(error => { if (!signal.aborted) recentError = message(error); })
    ]);
    overviewRequest = undefined;
  }

  async function refreshTriage() {
    if (triageRequest) return;
    const controller = new AbortController();
    triageRequest = controller;
    const { signal } = controller;
    try {
      const params = '/vulnerabilities?status=open&latest=true&limit=50&severity=';
      const critical = findingsByImage((await apiPage<Advisory[]>(params + 'critical', null, { signal })).items);
      const high = critical.length >= 4 ? [] : findingsByImage((await apiPage<Advisory[]>(params + 'high', null, { signal })).items);
      if (!signal.aborted) {
        triage = [...critical, ...high].slice(0, 4);
        triageError = '';
      }
    } catch (error) {
      if (!signal.aborted) triageError = message(error);
    } finally {
      triageRequest = undefined;
    }
  }

  function scanPath(search: string, selectedStatus: string) {
    const params = new URLSearchParams();
    if (search) params.set('q', search);
    if (selectedStatus) params.set('status', selectedStatus);
    return params.size ? '/scans?' + params : '/scans';
  }

  async function refreshFilters(path: string, signal: AbortSignal) {
    try {
      const result = await apiPage<Scan[]>(path, null, { signal });
      if (signal.aborted) return;
      filtered = result.items;
      filteredCursor = result.next;
      filterError = '';
    } catch (error) {
      if (!signal.aborted) filterError = message(error);
    } finally {
      if (!signal.aborted) filterLoading = false;
    }
  }

  $effect(() => {
    const path = scanPath(query.trim(), status);
    pageRequest?.abort();
    extra = [];
    extraCursor = null;
    firstPage = undefined;
    paging = false;
    pageError = '';
    if (path === '/scans') return;

    const controller = new AbortController();
    filterRequest = controller;
    filtered = [];
    filteredCursor = null;
    filterLoading = true;
    filterError = '';
    const timer = setTimeout(() => void refreshFilters(path, controller.signal), 180);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  });

  async function loadMore() {
    if (!next || paging) return;
    const controller = new AbortController();
    pageRequest = controller;
    const first = hasFilters ? filtered : recent;
    paging = true;
    pageError = '';
    try {
      const result = await apiPage<Scan[]>(scanPath(query.trim(), status), next, { signal: controller.signal });
      if (controller.signal.aborted) return;
      extra = [...extra, ...result.items];
      extraCursor = result.next;
      firstPage ??= first;
    } catch (error) {
      if (!controller.signal.aborted) pageError = message(error);
    } finally {
      if (!controller.signal.aborted) paging = false;
    }
  }

  function showScanStatus(filter: string) {
    query = '';
    status = filter;
    activity.focus();
  }

  onMount(() => {
    preferences = readPreferences();
    void refreshOverview();
    if (showTriage) void refreshTriage();
    let ticks = 0;
    const timer = setInterval(() => {
      ticks += 1;
      if (document.hidden) return;
      const hasActive = recent?.some(active) || scans.some(active);
      if (!hasActive && !summary?.active && ticks % 5 !== 0) return;
      void refreshOverview();
      if (showTriage && ticks % 5 === 0) void refreshTriage();
      if (hasFilters && !firstPage && !paging && !filterLoading && filterRequest) {
        filterLoading = true;
        void refreshFilters(scanPath(query.trim(), status), filterRequest.signal);
      }
    }, 3000);
    return () => {
      clearInterval(timer);
      finishDrag();
      overviewRequest?.abort();
      triageRequest?.abort();
      pageRequest?.abort();
    };
  });
</script>

<svelte:head><title>Scan desk · {productName}</title></svelte:head>

<div class="page-heading">
  <div><h1>Scan desk</h1><p>Triage findings by image version and monitor scan jobs.</p></div>
  <div class="filters desk-actions">
    {#if auth.operator}<a class="button secondary" href="/scans/bulk">Queue a batch</a>{/if}
    {#if auth.operator}<a class="button secondary" href="/scans/new?mode=import">Import report</a>{/if}
    <button class="button secondary" type="button" bind:this={customizeButton} aria-expanded={settingsOpen} aria-controls="desk-preferences" onclick={() => settingsOpen ? closeSettings() : settingsOpen = true}>
      <SlidersHorizontal size={16} aria-hidden="true" /> {settingsOpen ? 'Editing layout' : 'Customize'}
    </button>
  </div>
</div>

<svelte:window onkeydown={event => {
  if (event.key !== 'Escape') return;
  if (drag) finishDrag();
  else if (moveMenu) moveMenu = undefined;
}} />

{#if settingsOpen}
  <section class="panel desk-edit" id="desk-preferences" aria-labelledby="desk-preferences-title">
    <div class="edit-bar">
      <div><h2 id="desk-preferences-title">Customize Scan desk</h2><p>Drag a panel by its handle to move it.</p></div>
      <div class="filters">
        <button class="button secondary" type="button" onclick={() => { finishDrag(); moveMenu = undefined; updatePreferences(defaultPreferences); orderNotice = 'Default layout restored.'; }}>Reset view</button>
        <button class="button primary" type="button" onclick={closeSettings}>Done</button>
      </div>
    </div>
    <details class="edit-options">
      <summary>Hidden panels and density</summary>
      <div class="edit-options-body">
        {#each preferences.order as id (id)}
          {#if !preferences.panels.includes(id)}
            <button id={'desk-visibility-' + id} class="button secondary" type="button" onclick={() => togglePanel(id, true)}>Show {panelLabels.get(id)}</button>
          {/if}
        {/each}
        <label class="field"><span>Scan table density</span><select value={preferences.density}
          onchange={event => updatePreferences({ ...preferences, density: event.currentTarget.value === 'compact' ? 'compact' : 'comfortable' })}>
          <option value="comfortable">Comfortable</option><option value="compact">Compact</option>
        </select></label>
      </div>
    </details>
    {#if preferencesError}<p class="preferences-error" role="status">Browser storage is unavailable. Changes apply until you leave this page.</p>{/if}
  </section>
{/if}
<p class="order-notice" role="status">{orderNotice}</p>

{#if summaryError}
  <div class="notice error" role="alert">
    Workspace totals could not be refreshed. {summaryError}
    <button class="text-button" onclick={refreshOverview}>Retry</button>
  </div>
{/if}

{#snippet workspaceOverview()}
<section class="panel exposure-overview" aria-label="Workspace overview">
  <div class="exposure-caption">
    <h2>Workspace overview</h2>
    {#if hasDemo}<span class="badge neutral">Includes demo reports</span>{/if}
  </div>
  <div class="overview-metrics">
    <button class="metric" type="button" aria-controls="scan-activity" onclick={() => showScanStatus('active')}>
      <span>Active scans <ArrowDown size={14} aria-hidden="true" /></span>
      <strong>{count(summary?.active)}</strong>
      <small>Queued or running</small>
    </button>
    <button class="metric" type="button" aria-controls="scan-activity" onclick={() => showScanStatus('failed')}>
      <span>Failed scans <ArrowDown size={14} aria-hidden="true" /></span>
      <strong class:critical-text={!!summary?.failed}>{count(summary?.failed)}</strong>
      <small>Recorded scans</small>
    </button>
    <a class="metric" href="/library?status=open&severity=critical">
      <span>Open critical findings <ArrowRight size={14} aria-hidden="true" /></span>
      <strong class:critical-text={!!summary?.severity.critical}>{count(summary?.severity.critical)}</strong>
      <small>Latest completed scans</small>
    </a>
    <a class="metric" href="/library?status=open&severity=high">
      <span>Open high findings <ArrowRight size={14} aria-hidden="true" /></span>
      <strong class:high-text={!!summary?.severity.high}>{count(summary?.severity.high)}</strong>
      <small>Latest completed scans</small>
    </a>
  </div>
  {#if summary?.incompleteLatest}
    <p class="panel-footer field-help">{count(summary.incompleteLatest)} latest reports have incomplete vulnerability observations.</p>
  {/if}
</section>

{/snippet}

{#snippet triagePanel()}
  <section class="panel triage-panel" aria-labelledby="triage-title">
    <div class="panel-title">
      <div><h2 id="triage-title">Needs triage</h2><p>Up to four open critical or high findings from the latest completed scan per image reference and platform.</p></div>
      <div class="filters">
        <a class="button secondary" href="/library?status=open&fixable=true">Open findings with a reported fix{summary ? ' · ' + count(summary.openWithFix) : ''}</a>
        <a class="button primary" href="/library?status=open">Open triage queue <ArrowRight aria-hidden="true" size={15} /></a>
      </div>
    </div>
    {#if triageError}
      <div class="compact-empty" role="alert">{triageError} <button class="text-button" onclick={refreshTriage}>Retry</button></div>
    {:else if !triage}
      <div class="compact-empty" role="status">Loading findings…</div>
    {:else if !triage.length}
      <div class="empty"><h3>No open critical or high findings</h3><p>New findings at these severities will appear here.</p></div>
    {:else}
      <ul class="triage-list">
        {#each triage as {key, finding, image, packages} (key)}
          {@const fixCount = packages.filter(pkg => pkg.fixed).length}
          <li>
            <div class="triage-version">
              <a class="triage-image table-link mono" title={image.reference} aria-label={`Open scan report for ${image.reference}`}
                href={'/scans/' + image.scanId + '?' + new URLSearchParams({finding: finding.id, from: 'triage', advisoryFilters: 'status=open'})}>{imageName(image.reference)}</a>
              <small>{#if image.reference.includes('/')}{image.reference.split('/')[0]} · {/if}{image.platform}
                <span class="mono triage-digest" title={image.digest}>{shortDigest(image.digest)}</span>
              </small>
            </div>
            <div class="triage-advisory">
              <span class={'severity ' + finding.severity.toLowerCase()}>{finding.severity.toLowerCase()}</span>
              <a class="table-link mono" href={'/library/' + encodeURIComponent(finding.id) + '?status=open'}>{finding.id}</a>
              <small>{packages.length === 1 ? packages[0].package : `${packages.length} package matches`}</small>
            </div>
            <div class="triage-remediation">
              {#if !fixCount}<span>No fix reported</span>
              {:else if packages.length === 1}<span>Reported fix <strong class="mono">{packages[0].fixed}</strong></span>
              {:else}<span>Fix reported for <strong>{fixCount}/{packages.length}</strong> packages</span>{/if}
              {#if image.issue}<small><IssueLink issue={image.issue} /></small>{/if}
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
{/snippet}

{#snippet severityPanel()}
  <section class="panel" aria-labelledby="exposure-title">
    <div class="panel-title">
      <div><h2 id="exposure-title">Open findings by severity</h2><p>{summary ? count(findingTotal) + ' advisories across the latest completed scans' : 'Latest completed scan per image reference and platform'}</p></div>
    </div>
    {#if summary && findingTotal > 0}
      <div class="severity-composition" aria-hidden="true">
        {#each levels as level (level)}
          {#if summary.severity[level]}<span class={'severity-marker ' + level} style:flex-grow={summary.severity[level]}></span>{/if}
        {/each}
      </div>
    {/if}
    <dl class="severity-breakdown">
      {#each levels as level (level)}
        <div>
          <dt><a class="table-link" href={'/library?status=open&severity=' + level}>
            <span class={'severity-marker ' + level} aria-hidden="true"></span>{level}</a></dt>
          <dd>{count(summary?.severity[level])}</dd>
        </div>
      {/each}
    </dl>
    {#if summary}
      <p class="panel-footer field-help">Historical total across scanned digests · {count(historicalTotal)} package–advisory records
        <a class="table-link" href="/library?scope=history">Browse history</a>
      </p>
    {/if}
  </section>
{/snippet}

{#snippet scanActivity()}
<!-- svelte-ignore a11y_no_noninteractive_tabindex (Programmatic focus after following the failed scans shortcut.) -->
<section class="panel recent-scans" class:compact={preferences.density === 'compact'} id="scan-activity" aria-labelledby="scans-title" bind:this={activity} tabindex="-1">
  <div class="panel-title">
    <div><h2 id="scans-title">Scan activity</h2>
      {#if summary}<p>{count(summary.completed)} completed of {count(summary.scans)} recorded &middot; {#if auth.operator}<a href="/registries" class="table-link">{count(summary.registries)} registries</a>{:else}{count(summary.registries)} registries{/if}</p>
      {:else}<p>Scan jobs and imported reports</p>{/if}
    </div>
    <div class="filters scan-filters">
      <label class="search"><Search size={17} aria-hidden="true" /><input aria-label="Filter images" placeholder="Filter images" bind:value={query} /></label>
      <select aria-label="Filter scan status" bind:value={status}>
        <option value="">All statuses</option>
        <option value="active">Active</option>
        <option value="completed">Completed</option>
        <option value="running">Running</option>
        <option value="queued">Queued</option>
        <option value="failed">Failed</option>
        <option value="cancelled">Cancelled</option>
      </select>
    </div>
  </div>

  {#if activityError && !scans.length}
    <div class="compact-empty" role="alert">{activityError}
      <button class="text-button" onclick={() => hasFilters && filterRequest
        ? refreshFilters(scanPath(query.trim(), status), filterRequest.signal) : refreshOverview()}>Retry</button>
    </div>
  {:else if loading && !scans.length}
    <div class="empty" role="status">Loading scans…</div>
  {:else if !scans.length}
    <div class="empty">
      {#if hasFilters}
        <h3>No scans match your filters</h3>
        <button class="button secondary" onclick={() => { query = ''; status = ''; }}>Clear filters</button>
      {:else}
        <h3>No scans yet</h3>
        <p>Scan a container image or import a Trivy report.</p>
        {#if auth.operator}<a href="/scans/new" class="button primary"><ScanLine size={16} aria-hidden="true" /> Start scan</a>{/if}
      {/if}
    </div>
  {:else}
    {#if activityError}<p class="compact-empty" role="alert">{activityError}</p>{/if}
    <!-- svelte-ignore a11y_no_noninteractive_tabindex (The table can be scrolled with the keyboard.) -->
    <div class="table-wrap" role="region" aria-labelledby="scans-title" tabindex="0">
      <table>
        <thead>
          <tr>
            <th scope="col">Image</th>
            <th scope="col">Status</th>
            <th scope="col" class="finding-count">Critical</th>
            <th scope="col" class="finding-count">High</th>
            <th scope="col">Platform</th>
            <th scope="col">Created</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each scans as scan (scan.id)}
            <tr>
              <td class="scan-image"><a class="table-link mono" title={scan.reference} href={'/scans/' + scan.id}>{imageName(scan.reference)}</a>
                {#if scan.reference.includes('/')}<small>{scan.reference.split('/')[0]}</small>{/if}</td>
              <td><Status status={scan.status} />{#if scan.error && scan.status === 'failed'}<small class="failure-reason">{scan.error}</small>{/if}</td>
              <td class="finding-count" class:critical-text={Boolean(scan.counts?.critical)}>{scan.counts?.critical ?? '—'}</td>
              <td class="finding-count">{scan.counts?.high ?? '—'}</td>
              <td class="scan-platform mono">{scan.platform}</td>
              <td class="scan-date"><time datetime={scan.createdAt}>{time(scan.createdAt)}</time></td>
              <td>{#if scan.status === 'completed'}
                <a class="table-link compare-link" href={'/compare?' + new URLSearchParams({ target: scan.id })}
                  aria-label={`Compare ${scan.reference} on ${scan.platform}`}>Compare</a>
              {/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if next || pageError}
      <div class="panel-footer">
        {#if pageError}<p role="alert">{pageError}</p>{/if}
        {#if next}<button class="button secondary" disabled={paging} onclick={loadMore}>{paging ? 'Loading…' : 'Load more scans'}</button>{/if}
      </div>
    {/if}
  {/if}
</section>
{/snippet}

<div class="desk-grid" bind:this={deskGrid}>
  {#each panelLayout as { id, span } (id)}
    <div class="desk-panel" class:paired={span < 12} class:editing={settingsOpen} class:dragging={dragging === id} class:destination={destination === id}
      data-panel={id} style:--panel-span={span}>
      {#if settingsOpen}
        {@const position = visiblePanels.indexOf(id)}
        <div class="panel-edit">
          <button id={'move-panel-' + id} class="panel-handle" type="button" aria-label={'Move ' + panelLabels.get(id)}
            aria-expanded={moveMenu === id} aria-controls={'move-options-' + id}
            onpointerdown={event => pointerDown(event, id)} onpointermove={pointerMove}
            onpointerup={event => finishDrag(event, true)} onpointercancel={event => finishDrag(event)} onlostpointercapture={event => finishDrag(event)}
            onkeydown={event => panelKeys(event, id)}
            onclick={() => {
              if (suppressClick) { suppressClick = false; return; }
              moveMenu = moveMenu === id ? undefined : id;
            }}><GripVertical size={19} aria-hidden="true" /> Move</button>
          {#if id !== 'activity'}
            <button class="panel-hide" type="button" aria-label={'Hide ' + panelLabels.get(id)}
              onclick={() => { moveMenu = undefined; void togglePanel(id, false); }}>Hide</button>
          {/if}
        </div>
        <div class="move-options" id={'move-options-' + id} hidden={moveMenu !== id}>
          <button class="button secondary" type="button" disabled={position === 0} onclick={() => movePanel(id, 0, true)}>Move to top</button>
          <button class="button secondary" type="button" disabled={position === 0} onclick={() => movePanel(id, position - 1, true)}>Move up</button>
          <button class="button secondary" type="button" disabled={position === visiblePanels.length - 1} onclick={() => movePanel(id, position + 1, true)}>Move down</button>
        </div>
      {/if}
      {#if id === 'overview'}{@render workspaceOverview()}
      {:else if id === 'triage'}{@render triagePanel()}
      {:else if id === 'severity'}{@render severityPanel()}
      {:else if id === 'activity'}{@render scanActivity()}
      {:else if id === 'volume'}<ScanVolumeChart scans={recent} error={recentError} hasOlder={Boolean(recentCursor)} />
      {:else if id === 'packages'}<PackageChart />
      {:else}<RiskChart scans={recent} {recentError} {recentCursor} />{/if}
    </div>
  {/each}
</div>

{#if dragging}
  <div class="drag-label" aria-hidden="true" style:left={dragPosition.x + 'px'} style:top={dragPosition.y + 'px'}>
    <GripVertical size={16} /> {panelLabels.get(dragging)}
  </div>
{/if}

<style>
  .desk-edit { position: sticky; top: 0; z-index: 3; margin-bottom: 1rem; }
  .edit-bar { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: .65rem; padding: .75rem 1rem; }
  .edit-bar p { margin-top: .15rem; color: var(--muted); font-size: var(--text-detail); }
  .edit-options { border-top: 1px solid var(--line); padding: .25rem 1rem; }
  .edit-options summary { width: fit-content; padding: .45rem 0; color: var(--accent-ink); cursor: pointer; font-size: var(--text-label); font-weight: 750; }
  .edit-options-body { display: flex; flex-wrap: wrap; align-items: end; gap: .65rem; padding: .4rem 0 .65rem; }
  .preferences-error { padding: 0 1rem .65rem; color: var(--muted); font-size: var(--text-detail); }
  .order-notice { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
  .panel-edit { display: flex; align-items: center; justify-content: space-between; gap: .5rem; padding: .15rem .55rem; background: var(--inset); border: 1px solid var(--line); border-bottom: 0; border-radius: var(--radius) var(--radius) 0 0; }
  .panel-handle, .panel-hide { display: inline-flex; align-items: center; gap: .3rem; min-height: 44px; padding: .3rem .5rem; border: 0; border-radius: 5px; background: transparent; color: var(--accent-ink); font-size: var(--text-label); font-weight: 800; }
  .panel-handle { cursor: grab; touch-action: none; user-select: none; }
  .panel-handle:active, .dragging .panel-handle { cursor: grabbing; }
  .panel-handle:hover, .panel-hide:hover { background: var(--accent-soft); }
  .move-options { display: flex; flex-wrap: wrap; gap: .4rem; padding: .55rem; background: var(--surface); border-inline: 1px solid var(--line); border-top: 1px solid var(--line); }
  .move-options[hidden] { display: none; }
  .desk-panel.editing > :global(.panel) { border-start-start-radius: 0; border-start-end-radius: 0; }
  .desk-panel.dragging { opacity: .55; }
  .desk-panel.destination { outline: 2px dashed var(--accent); outline-offset: 2px; border-radius: var(--radius); }
  .drag-label { position: fixed; z-index: 5; display: flex; align-items: center; gap: .35rem; width: max-content; max-width: 9rem; padding: .5rem .6rem; border: 1px solid var(--accent); border-radius: var(--radius); background: var(--surface); color: var(--accent-ink); font-size: var(--text-detail); font-weight: 800; pointer-events: none; }
  .drag-label :global(svg) { flex: none; }
  .exposure-caption { display: flex; align-items: center; gap: .65rem; flex-wrap: wrap; padding: .75rem 1.15rem; border-bottom: 1px solid var(--line); }
  .exposure-caption h2 { font-size: .9rem; }
  .overview-metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); }
  .metric {
    display: grid;
    gap: .3rem;
    padding: .75rem 1.15rem;
    border: 0;
    border-inline-end: 1px solid var(--line);
    background: var(--surface);
    color: var(--ink);
    text-align: start;
    text-decoration: none;
  }
  .metric:last-child { border-inline-end: 0; }
  .metric:focus-visible { outline-offset: -3px; }
  :is(a, button).metric:hover { background: var(--accent-soft); }
  .metric span { display: flex; align-items: center; gap: .5rem; color: var(--muted); font-size: .8rem; font-weight: 750; }
  .metric span :global(svg) { flex: none; color: var(--accent-ink); }
  .metric strong { font: 650 1.55rem/1.1 var(--mono); overflow-wrap: anywhere; }
  .metric small { color: var(--muted); font-size: var(--text-detail); }
  .high-text { color: var(--high); }
  .failure-reason { max-width: 14rem; }
  .desk-grid { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 1rem; }
  .desk-panel { display: flex; flex-direction: column; min-width: 0; grid-column: span var(--panel-span); }
  .desk-panel > :global(.panel) { flex: 1; display: flex; flex-direction: column; margin-bottom: 0; }
  @media (min-width: 1051px) {
    .paired > :global(.panel) > :global(.panel-title) { min-height: 5.1rem; }
  }
  .severity-breakdown { flex: 1; display: grid; align-content: stretch; }
  .triage-panel .triage-list { flex: 1; display: grid; align-content: stretch; }
  .triage-list { list-style: none; margin: 0; padding: 0 1.15rem; }
  .triage-list li { display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(0, 1fr) minmax(0, .65fr); gap: .4rem .9rem; align-items: baseline; padding: .6rem 0; }
  .triage-list li + li { border-top: 1px solid var(--line); }
  .triage-advisory { display: flex; flex-wrap: wrap; gap: .2rem .42rem; align-items: center; }
  .triage-advisory small { flex-basis: 100%; }
  .triage-version, .triage-advisory, .triage-remediation { overflow-wrap: anywhere; }
  .triage-image { font-size: .83rem; }
  .triage-digest { display: block; }
  .triage-remediation { font-size: .8rem; color: var(--muted); }
  .triage-remediation strong { color: var(--ink); }
  .triage-list small { display: block; margin-top: .15rem; color: var(--muted); font-size: var(--text-detail); }
  .severity-composition { display: flex; gap: 2px; height: .65rem; margin: 1rem 1.15rem .25rem; overflow: hidden; border-radius: 3px; }
  .severity-composition span { flex-basis: 0; }
  .severity-breakdown { margin: 0; padding: .35rem 1.15rem .7rem; }
  .severity-breakdown > div { display: flex; align-items: center; justify-content: space-between; gap: .65rem; padding: .32rem 0; }
  .severity-breakdown > div + div { border-top: 1px solid var(--line); }
  .severity-breakdown a { display: inline-flex; align-items: center; gap: .55rem; min-height: 24px; text-transform: capitalize; font-size: .84rem; }
  .severity-breakdown dd { margin: 0; text-align: end; font: 600 .84rem var(--mono); }
  .severity-marker { display: inline-block; background: currentColor; }
  .severity-breakdown .severity-marker { flex: none; width: .55rem; height: .55rem; border-radius: 2px; }
  .severity-marker.unknown { color: var(--control-line); }
  .recent-scans th, .recent-scans td { padding: .7rem .85rem; }
  .recent-scans.compact th, .recent-scans.compact td { padding-block: .36rem; }
  .recent-scans .table-wrap { max-block-size: 30rem; overflow: auto; }
  .recent-scans .table-wrap:focus-visible { outline-offset: -3px; }
  .recent-scans table { border-collapse: separate; border-spacing: 0; }
  .recent-scans th { position: sticky; top: 0; }
  .recent-scans .empty { padding-block: 1.65rem; }
  .recent-scans:focus { outline: 2px solid var(--focus); outline-offset: 3px; }
  .scan-image { min-width: 9rem; }
  .finding-count { text-align: end; font-variant-numeric: tabular-nums; }
  .scan-platform, .scan-date { color: var(--muted); white-space: nowrap; }
  .compare-link { display: inline-flex; align-items: center; min-height: 24px; }
  @media (max-width: 560px) {
    .overview-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .metric:nth-child(even) { border-inline-end: 0; }
    .metric:nth-child(n + 3) { border-top: 1px solid var(--line); }
  }
  @media (max-width: 1050px) {
    .desk-panel { grid-column: 1 / -1; }
  }
  @media (max-width: 620px) {
    .triage-list li { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }
    .triage-version { grid-column: 1 / -1; }
  }
  @media (max-width: 480px) {
    .desk-actions { gap: .4rem; }
    .desk-actions .button { padding-inline: .55rem; }
    .metric { padding: .7rem; }
    .scan-filters, .scan-filters .search { width: 100%; }
    .scan-filters .search input { width: 100%; max-width: none; }
  }
</style>
