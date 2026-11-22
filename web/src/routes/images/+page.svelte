<script lang="ts">
  import { auth } from '#lib/auth.svelte.js';
  import { productName } from '#lib/product.js';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { onDestroy } from 'svelte';
  import { Box, ChevronDown, ScanLine, Search, Trash2 } from '@lucide/svelte';
  import { active, api, apiPage, imageName, message, post, shortDigest, time, type Scan } from '#lib/api.js';
  import Status from '#lib/Status.svelte';

  const severities = ['critical', 'high', 'medium', 'low'] as const;
  const severityLabels = ['Critical', 'High', 'Medium', 'Low'];
  const sorts = ['critical', 'recent', 'name'];
  const statuses = ['all', 'attention', 'failed'];

  let groups = $state<Record<string, Scan[]>>({});
  // Several repositories and history panels can stay open at once.
  let expanded = $state<string[]>([]);
  let history = $state<string[]>([]);
  const toggle = (list: string[], key: string) => list.includes(key) ? list.filter(item => item !== key) : [...list, key];
  const query = $derived(page.url.searchParams.get('q') ?? '');
  const registry = $derived(page.url.searchParams.get('registry') ?? '');
  const sort = $derived(sorts.find(value => value === page.url.searchParams.get('sort')) ?? 'critical');
  const status = $derived(statuses.find(value => value === page.url.searchParams.get('status')) ?? 'all');
  const filtered = $derived(!!(query || registry || status !== 'all'));
  let input = $state('');
  let timer: ReturnType<typeof setTimeout>;
  let issue = $state('');
  let feedback = $state('');
  let loading = $state(true);
  let busy = $state(false);
  let retry = $state(0);
  let visible = $state(100);

  const repositories = $derived.by(() => Object.entries(groups).map(([name, rows]) => {
    const scans = [...rows].sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt) || b.id.localeCompare(a.id));
    const versions = new Map<string, Scan[]>();
    for (const scan of scans) {
      const key = JSON.stringify([scan.reference, scan.platform]);
      const version = versions.get(key);
      if (version) version.push(scan);
      else versions.set(key, [scan]);
    }
    const attempt = scans[0];
    const report = scans.find(scan => scan.status === 'completed');
    const slash = name.indexOf('/');
    const first = name.slice(0, slash);
    const explicitHost = slash >= 0 && (first.includes('.') || first.includes(':') || first === 'localhost');
    return {
      name, scans, versions: [...versions.entries()], attempt, report,
      host: explicitHost ? first : '',
      path: explicitHost ? name.slice(slash + 1) : name,
      tags: new Set(scans.map(scan => scan.reference)).size,
      platforms: [...new Set(scans.map(scan => scan.platform))].sort()
    };
  }));
  const registries = $derived([...new Set(repositories.map(repo => repo.host).filter(Boolean))].sort());
  const results = $derived.by(() => repositories.filter(repo => {
    if (registry && repo.host !== registry) return false;
    if (status === 'failed' && repo.attempt.status !== 'failed') return false;
    if (status === 'attention' && repo.attempt.status !== 'failed' && !repo.report?.counts?.critical) return false;
    const term = query.trim().toLowerCase();
    return !term || repo.scans.some(scan => scan.reference.toLowerCase().includes(term));
  }).sort((a, b) => {
    const byName = a.path.localeCompare(b.path) || a.host.localeCompare(b.host);
    if (sort === 'name') return byName;
    const recent = Date.parse(b.attempt.finishedAt ?? b.attempt.createdAt) - Date.parse(a.attempt.finishedAt ?? a.attempt.createdAt);
    if (sort === 'recent') return recent || byName;
    for (const severity of severities) {
      const difference = (b.report?.counts?.[severity] ?? -1) - (a.report?.counts?.[severity] ?? -1);
      if (difference) return difference;
    }
    return recent || byName;
  }));
  const versionCount = $derived(results.reduce((total, repo) => total + repo.versions.length, 0));

  $effect(() => { input = query; });
  $effect(() => { query; registry; status; sort; visible = 100; });
  onDestroy(() => clearTimeout(timer));

  function updateParams(values: Record<string, string>, replaceState = false) {
    const url = new URL(page.url.href);
    for (const [key, value] of Object.entries(values)) {
      if (value) url.searchParams.set(key, value);
      else url.searchParams.delete(key);
    }
    if (url.href !== page.url.href) void goto(url, { reset: false, replace: replaceState });
  }

  function search(value: string) {
    input = value;
    clearTimeout(timer);
    timer = setTimeout(() => updateParams({ q: value.trim() }, true), 170);
  }

  function clearFilters() {
    clearTimeout(timer);
    input = '';
    updateParams({ q: '', registry: '', status: '' });
  }

  async function load(signal: AbortSignal) {
    issue = '';
    try {
      const combined: Record<string, Scan[]> = Object.create(null);
      let cursor: string | null = null;
      do {
        const result: { items: Record<string, Scan[]>; next: string | null } =
          await apiPage('/images?limit=250', cursor, { signal });
        for (const [name, rows] of Object.entries(result.items)) (combined[name] ??= []).push(...rows);
        cursor = result.next;
      } while (cursor && !signal.aborted);
      if (!signal.aborted) groups = combined;
    } catch (error) {
      if (!signal.aborted) issue = message(error);
    } finally {
      if (!signal.aborted) loading = false;
    }
  }

  $effect(() => {
    retry;
    const controller = new AbortController();
    loading = true;
    expanded = [];
    history = [];
    void load(controller.signal);
    return () => controller.abort();
  });

  function tag(reference: string, repository: string) {
    if (reference.startsWith('sha256:')) return shortDigest(reference);
    const suffix = reference.slice(repository.length);
    if (suffix.startsWith('@')) return shortDigest(suffix.slice(1));
    if (suffix.startsWith(':')) return suffix.slice(1);
    return imageName(reference);
  }

  async function deleteScan(repository: string, scan: Scan) {
    if (!auth.admin || active(scan) || busy) return;
    const description = scan.reference + ' (' + scan.platform + ') from ' + time(scan.createdAt);
    if (!confirm('Delete the scan record for ' + description + '?')) return;
    busy = true;
    issue = '';
    feedback = '';
    try {
      const result = await api<{ removed: number }>('/images/delete', post({ ids: [scan.id] }));
      if (result.removed === 1) {
        const updated = { ...groups };
        const remaining = updated[repository].filter(row => row.id !== scan.id);
        if (remaining.length) updated[repository] = remaining;
        else delete updated[repository];
        groups = updated;
        feedback = 'Deleted the scan for ' + description + '.';
      } else {
        issue = 'The scan could not be deleted. Refresh the catalog to see its current status.';
      }
    } catch (error) { issue = message(error); }
    finally { busy = false; }
  }
</script>

<svelte:head><title>Image catalog · {productName}</title></svelte:head>

<div class="page-heading">
  <div><h1>Image catalog</h1><p>Scan results and report history by tag and platform.</p></div>
</div>
{#if issue}<div class="notice error" role="alert">{issue} <button class="text-button" onclick={() => {retry += 1;}}>Refresh catalog</button></div>{/if}
{#if feedback}<div class="notice success" role="status">{feedback}</div>{/if}

{#snippet severitySummary(report: Scan | undefined)}
  {#if report?.counts}
    <div class="severity-counts">
      {#each severities as severity, index (severity)}
        <span class="badge severity {report.counts[severity] ? severity : 'neutral'}" title={severityLabels[index]}>
          <span>{severityLabels[index]}</span><strong>{report.counts[severity]}</strong>
        </span>
      {/each}
    </div>
  {:else}
    <span class="field-help">No completed report</span>
  {/if}
{/snippet}

{#snippet scanTime(scan: Scan)}
  <time class="scan-time" datetime={scan.finishedAt ?? scan.createdAt}>{time(scan.finishedAt ?? scan.createdAt)}</time>
{/snippet}

<section class="panel" aria-label="Scanned images">
  <div class="panel-title catalog-toolbar">
    <div class="catalog-controls">
      <label class="search image-search"><Search size={17} aria-hidden="true" /><input type="search" aria-label="Search image catalog" placeholder="Search repositories, tags, or digests" value={input} oninput={(event) => search(event.currentTarget.value)} /></label>
      <label class="field"><span>Registry</span><select value={registry} onchange={(event) => updateParams({ registry: event.currentTarget.value })}>
        <option value="">All registries</option>
        {#if registry && !registries.includes(registry)}<option value={registry}>{registry}</option>{/if}
        {#each registries as host (host)}<option value={host}>{host}</option>{/each}
      </select></label>
      <label class="field"><span>Status</span><select value={status} onchange={(event) => updateParams({ status: event.currentTarget.value === 'all' ? '' : event.currentTarget.value })}>
        <option value="all">All statuses</option><option value="attention">Needs attention</option><option value="failed">Failed</option>
      </select></label>
      <label class="field sort-control"><span>Sort by</span><select value={sort} onchange={(event) => updateParams({ sort: event.currentTarget.value === 'critical' ? '' : event.currentTarget.value })}>
        <option value="critical">Most critical first</option><option value="recent">Recently scanned</option><option value="name">Name</option>
      </select></label>
    </div>
    {#if !loading && !issue}
      <div class="result-line">
        <span class="field-help" role="status">{results.length} {results.length === 1 ? 'repository' : 'repositories'} · {versionCount} {versionCount === 1 ? 'image version' : 'image versions'}</span>
        {#if filtered}<button type="button" class="text-button" onclick={clearFilters}>Clear filters</button>{/if}
      </div>
    {/if}
  </div>
  {#if loading}
    <div class="empty" role="status">Loading images…</div>
  {:else if !results.length && !issue}
    <div class="empty">
      <span class="empty-icon"><Box size={26} aria-hidden="true" /></span>
      <h3>{filtered ? 'No matching images' : 'No scanned images'}</h3>
      {#if auth.operator && !filtered}<a class="button primary" href="/scans/new"><ScanLine size={17} aria-hidden="true" /> Start scan</a>{/if}
    </div>
  {:else if results.length}
    <div class="catalog-grid catalog-labels" aria-hidden="true">
      <span>Repository</span><span>Tags and platforms</span><span>Findings</span><span>Last scanned</span>
    </div>
    <ul class="repository-list">
      {#each results.slice(0, visible) as repo (repo.name)}
        {@const open = expanded.includes(repo.name)}
        {@const versionsId = 'image-versions-' + repo.attempt.id}
        <li>
          <div class="catalog-grid repository-row" class:expanded={open}>
            <button type="button" class="repository-toggle" aria-expanded={open} aria-controls={versionsId}
              onclick={() => { expanded = toggle(expanded, repo.name); }}>
              <ChevronDown size={16} aria-hidden="true" />
              <span><strong class="mono">{repo.path}</strong>{#if repo.host}<small>{repo.host}</small>{/if}</span>
            </button>
            <div class="version-summary"><strong>{repo.tags > 1 ? repo.tags + ' tags' : tag(repo.attempt.reference, repo.name)}</strong>
              <small class="mono">{repo.platforms.join(' · ')}</small>
            </div>
            <div class="finding-summary">
              {@render severitySummary(repo.report)}
              {#if repo.report && repo.attempt.status !== 'completed'}<small>Last completed report</small>{/if}
            </div>
            <div class="attempt-summary">
              {@render scanTime(repo.attempt)}
              {#if repo.attempt.status !== 'completed'}<a class="table-link" href={'/scans/' + repo.attempt.id} aria-label={'Open ' + repo.attempt.status + ' scan for ' + repo.attempt.reference}><Status status={repo.attempt.status} /></a>{/if}
            </div>
          </div>
          <div id={versionsId} hidden={!open} class="versions">
            {#if open}
              {#each repo.versions as [key, scans] (key)}
                {@const attempt = scans[0]}
                {@const report = scans.find(scan => scan.status === 'completed')}
                {@const previous = report && repo.scans.slice(repo.scans.indexOf(report) + 1).find(scan => scan.status === 'completed' && scan.platform === report.platform)}
                {@const historyId = 'image-history-' + attempt.id}
                {@const historyOpen = history.includes(key)}
                <div class="catalog-grid version-row">
                  <div class="version-name">
                    <a class="table-link mono" href={'/scans/' + (report?.id ?? attempt.id)}
                      title={report ? 'Open report' : 'Open scan'}>{tag(attempt.reference, repo.name)}</a>
                  </div>
                  <small class="mono version-platform">{attempt.platform}</small>
                  <div class="finding-summary">
                    {@render severitySummary(report)}
                    {#if report && attempt.status !== 'completed'}<small>Last completed report</small>{/if}
                  </div>
                  <div class="version-actions">
                    {#if attempt.status !== 'completed'}<a class="table-link" href={'/scans/' + attempt.id} aria-label={'Open ' + attempt.status + ' scan'}><Status status={attempt.status} /></a>{/if}
                    <button type="button" class="text-button history-button" aria-expanded={historyOpen} aria-controls={historyId}
                      onclick={() => { history = toggle(history, key); }}>
                      History <span class="mono">{scans.length}</span><ChevronDown size={15} aria-hidden="true" />
                    </button>
                    {#if report && previous}
                      <a class="table-link" href={'/compare?' + new URLSearchParams({baseline: previous.id, target: report.id})}>Compare previous</a>
                    {/if}
                  </div>
                </div>
                <div id={historyId} hidden={!historyOpen} class="history-panel">
                  {#if historyOpen}
                    <h3>Scan history <span class="mono">{tag(attempt.reference, repo.name)} · {attempt.platform}</span></h3>
                    <div class="table-wrap">
                      <table>
                        <thead><tr><th scope="col">Scan</th><th scope="col">Status</th><th scope="col" class="count">Critical</th><th scope="col" class="count">High</th>{#if auth.admin}<th scope="col" class="count">Actions</th>{/if}</tr></thead>
                        <tbody>
                          {#each scans as scan (scan.id)}
                            <tr>
                              <td><a class="table-link" href={'/scans/' + scan.id}><time datetime={scan.createdAt}>{time(scan.createdAt)}</time></a></td>
                              <td><Status status={scan.status} />{#if scan.error && scan.status === 'failed'}<small>{scan.error}</small>{/if}</td>
                              <td class="count" class:critical-text={!!scan.counts?.critical}>{scan.counts?.critical ?? '—'}</td>
                              <td class="count">{scan.counts?.high ?? '—'}</td>
                              {#if auth.admin}
                                <td class="scan-action">{#if !active(scan)}
                                  <button type="button" class="text-button delete-scan" disabled={busy}
                                    aria-label={'Delete scan for ' + scan.reference + ' on ' + scan.platform + ' from ' + time(scan.createdAt)}
                                    onclick={() => deleteScan(repo.name, scan)}><Trash2 size={15} aria-hidden="true" /> Delete scan</button>
                                {/if}</td>
                              {/if}
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                    </div>
                  {/if}
                </div>
              {/each}
            {/if}
          </div>
        </li>
      {/each}
    </ul>
    {#if results.length > visible}
      <div class="panel-footer"><button type="button" class="button secondary" onclick={() => { visible += 100; }}>Show more repositories</button></div>
    {/if}
  {/if}
</section>

<style>
  .catalog-toolbar { display: grid; grid-template-columns: minmax(0, 1fr); gap: .65rem; }
  .catalog-controls { display: grid; align-items: end; gap: .65rem; grid-template-columns: minmax(13rem, 1fr) repeat(3, minmax(0, max-content)); }
  .catalog-controls select { width: 100%; max-width: 18rem; }
  .image-search :global(input) { width: 100%; max-width: none; }
  .result-line { display: flex; align-items: center; flex-wrap: wrap; gap: .3rem .8rem; }
  .catalog-grid { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(0, .75fr) minmax(14rem, 1.35fr) minmax(0, .85fr); align-items: center; gap: .65rem 1rem; padding: .7rem 1.15rem; }
  .catalog-labels { background: var(--inset); color: var(--muted); font-size: var(--text-label); font-weight: 750; line-height: 1.3; }
  .repository-list { margin: 0; padding: 0; list-style: none; }
  .repository-list > li { border-top: 1px solid var(--line); }
  .repository-row:hover, .repository-row.expanded, .versions { background: var(--canvas); }
  .repository-toggle { color: var(--ink); cursor: pointer; border: 0; background: none; padding: .2rem 0; text-align: left; display: flex; align-items: center; gap: .55rem; }
  .repository-toggle :global(svg) { flex: none; color: var(--muted); transform: rotate(-90deg); }
  .repository-toggle[aria-expanded="true"] :global(svg) { transform: none; }
  .repository-toggle strong { font-size: .88rem; }
  .repository-toggle:hover strong { color: var(--accent-ink); }
  .repository-row strong, .version-row strong { overflow-wrap: anywhere; }
  .repository-row small, .version-row small { display: block; margin-top: .18rem; color: var(--muted); font-size: .75rem; overflow-wrap: anywhere; }
  .version-summary strong { font-size: .82rem; }
  .severity-counts { display: flex; flex-wrap: wrap; gap: .26rem; }
  .severity-counts .severity { gap: .25rem; padding-inline: .42rem; text-transform: none; }
  .severity-counts strong { font-family: var(--mono); }
  .attempt-summary { display: flex; flex-wrap: wrap; align-items: center; gap: .25rem .5rem; }
  .scan-time { color: var(--muted); font-size: .8rem; }
  .versions { padding-bottom: .4rem; }
  .version-row { padding-block: .55rem; border-top: 1px dashed var(--line); font-size: .82rem; }
  .version-name { padding-inline-start: 1.55rem; }
  .version-name a { font-size: .82rem; }
  .version-platform { margin: 0; }
  .version-row small { margin-top: 0; }
  .finding-summary { display: grid; gap: .22rem; justify-items: start; }
  .finding-summary small { margin-top: 0; }
  .version-actions { display: flex; flex-wrap: wrap; align-items: center; gap: .3rem .9rem; font-size: .79rem; line-height: 1.2; }
  .version-actions .table-link { line-height: 1.2; }
  .history-button, .delete-scan { display: inline-flex; align-items: center; gap: .28rem; }
  .history-button { min-height: 32px; text-decoration: none; }
  .history-button:hover { text-decoration: underline; }
  .history-button span { color: var(--muted); }
  .history-button[aria-expanded="true"] :global(svg) { transform: rotate(180deg); }
  .history-panel { margin: .1rem 1.15rem .65rem 2.7rem; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); }
  .history-panel h3 { font-size: .84rem; padding: .65rem .85rem; }
  .history-panel h3 span { color: var(--muted); margin-inline-start: .35rem; }
  .history-panel :is(td, th) { padding: .55rem .75rem; }
  .count { text-align: end; font-variant-numeric: tabular-nums; }
  .scan-action { width: 1%; text-align: end; }
  .delete-scan { min-height: 32px; white-space: nowrap; color: var(--muted); }
  .delete-scan:hover { color: var(--critical); }
  @media (max-width: 1060px) {
    .catalog-controls { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .image-search { grid-column: 1 / -1; }
    .catalog-controls select { max-width: none; }
    .catalog-grid { grid-template-columns: minmax(0, 1.2fr) minmax(0, .75fr) minmax(10rem, 1.1fr) minmax(0, .7fr); }
  }
  @media (max-width: 680px) {
    .catalog-controls { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .sort-control { grid-column: 1 / -1; }
    .catalog-labels { display: none; }
    .catalog-grid { grid-template-columns: minmax(0, 1fr); gap: .35rem; padding: .75rem 1rem; }
    .repository-row > :not(:first-child) { margin-inline-start: 1.55rem; }
    .version-summary { display: flex; flex-wrap: wrap; align-items: baseline; gap: .2rem .6rem; }
    .version-summary small { margin-top: 0; }
    .version-row > :not(:first-child) { margin-inline-start: 1.55rem; }
    .history-panel { margin-inline: 1rem; }
    .history-panel :is(td, th) { padding-inline: .4rem; white-space: normal; }
  }
</style>
