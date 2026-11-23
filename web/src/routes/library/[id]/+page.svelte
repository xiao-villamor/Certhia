<script lang="ts">
  import { productName } from '#lib/product.js';
  import { page } from '$app/state';
  import { ArrowLeft, ArrowUpRight, ChevronDown } from '@lucide/svelte';
  import { apiPage, imageName, message, shortDigest, time } from '#lib/api.js';
  import { ecosystemGroup } from '#lib/ecosystems.js';
  import AdvisoryDetails from '#lib/AdvisoryDetails.svelte';
  import FindingTracker from '#lib/FindingTracker.svelte';
  import IssueLink from '#lib/IssueLink.svelte';
  import { findingsByImage, trackingTarget, type Advisory } from '#lib/library.js';
  import { trackingStatus, type TrackingTarget } from '#lib/tracking.js';

  const fromHistory = $derived(page.url.searchParams.get('scope') === 'history');
  const indexPath = $derived('/library' + page.url.search);
  const historyPath = $derived.by(() => {
    const params = new URLSearchParams(page.url.search);
    params.set('scope', 'history');
    return '?' + params;
  });
  let item = $state<Advisory>();
  const versions = $derived(item ? findingsByImage([item]) : []);
  let tracking = $state<TrackingTarget>();
  let loading = $state(true);
  let error = $state('');
  let notice = $state('');
  let next = $state<string | null>(null);
  let busy = $state(false);
  let controller: AbortController;
  let retry = $state(0);

  async function load(advisory: string, history: boolean, signal: AbortSignal, cursor?: string) {
    busy = true;
    error = '';
    try {
      const params = new URLSearchParams({advisory});
      params.set('latest', String(!history));
      const result = await apiPage<Advisory[]>('/vulnerabilities?' + params, cursor, {signal});
      if (signal.aborted) return;
      const entry = result.items[0];
      item = cursor && item && entry ? {...item, affected: [...item.affected, ...entry.affected]} : entry;
      next = result.next;
    } catch (issue) {
      if (!signal.aborted) error = message(issue);
    } finally {
      if (!signal.aborted) { loading = false; busy = false; }
    }
  }

  $effect(() => {
    const advisory = page.params.id;
    const history = fromHistory;
    retry;
    if (!advisory) return;
    item = undefined;
    next = null;
    notice = '';
    tracking = undefined;
    loading = true;
    controller = new AbortController();
    const {signal} = controller;
    void load(advisory, history, signal);
    return () => controller.abort();
  });

  function trackingSaved() {
    const target = tracking;
    tracking = undefined;
    if (!target) return;
    notice = 'Tracking saved.';
    void load(target.finding, fromHistory, controller.signal);
  }

  function reportPath(scanId: string, finding: string) {
    return '/scans/' + scanId + '?' + new URLSearchParams({
      finding, advisoryFilters: page.url.searchParams.toString()
    });
  }
</script>

<svelte:head><title>{page.params.id} · {productName}</title></svelte:head>
<FindingTracker target={tracking} dismiss={() => {tracking = undefined;}} onSaved={trackingSaved} />

<div class="page-heading">
  <div>
    <a class="crumb back-link" href={indexPath}><ArrowLeft size={15} aria-hidden="true" /> Vulnerabilities</a>
    <div class="advisory-title"><h1>{page.params.id}</h1>
      {#if item}<span class={'severity ' + item.finding.severity.toLowerCase()}>{item.finding.severity.toLowerCase()}</span>{/if}
    </div>
    {#if item?.finding.title}<p>{item.finding.title}</p>{/if}
  </div>
</div>

{#if error}<div class="notice error" role="alert">{error} <button class="text-button" onclick={() => {retry += 1;}}>Retry</button></div>{/if}
{#if notice}<div class="notice success" role="status">{notice}</div>{/if}
{#if loading}<div class="panel empty" role="status">Loading affected images…</div>
{:else if !item && !error}
  <div class="panel empty">
    <h2>{fromHistory ? 'No affected reports' : 'No affected reports in the latest scanned tags'}</h2>
    <a class="button secondary" href={fromHistory ? indexPath : historyPath}>
      {fromHistory ? 'Back to vulnerabilities' : 'Check scan history'}
    </a>
  </div>
{:else if item}
  <section class="panel" aria-labelledby="affected-reports">
    <div class="panel-title">
      <div><h2 id="affected-reports">Affected image versions</h2><p>{fromHistory ? 'Includes older digests' : 'Latest completed scan per image reference and platform'}</p></div>
    </div>
    <!-- svelte-ignore a11y_no_noninteractive_tabindex (The table scrolls on narrow screens.) -->
    <div class="table-wrap" role="region" aria-labelledby="affected-reports" tabindex="0">
      <table class="affected-table">
        <thead><tr><th scope="col">Image and platform</th><th scope="col">Package</th><th scope="col">Installed</th><th scope="col">Reported fix</th><th scope="col">Tracking</th><th scope="col">Linked issue</th></tr></thead>
        {#each versions as row (row.key)}
          {@const {image, finding, packages} = row}
          <tbody>
            {#each packages as detail, i}
              <tr>
                {#if i === 0}
                  <td rowspan={packages.length}>
                    <a class="table-link mono report-link" href={reportPath(image.scanId, finding.id)} title={image.reference}>
                      {imageName(image.reference)} <ArrowUpRight size={13} aria-hidden="true" />
                    </a>
                    <small>{image.reference.includes('/') ? image.reference.split('/')[0] + ' · ' : ''}{image.platform}</small>
                    <small title={image.digest}>{shortDigest(image.digest)}{#if image.finishedAt} · <time datetime={image.finishedAt}>{time(image.finishedAt)}</time>{/if}</small>
                  </td>
                {/if}
                <td>{detail.package}<small>{ecosystemGroup(detail.ecosystem)}</small></td>
                <td class="mono">{detail.installed || '—'}</td>
                <td>{#if detail.fixed}<span class="mono">{detail.fixed}</span>{:else}<span class="field-help">None reported</span>{/if}</td>
                {#if i === 0}
                  <td rowspan={packages.length}><button type="button" class="status-chip" data-status={image.status ?? 'open'} aria-haspopup="dialog"
                    aria-label={'Review ' + finding.id + ' on ' + image.reference + ' (' + image.platform + ')'}
                    onclick={() => { notice = ''; tracking = trackingTarget(row); }}>{trackingStatus(image.status)} <ChevronDown size={13} aria-hidden="true" /></button></td>
                  <td rowspan={packages.length}>{#if image.issue}<IssueLink issue={image.issue} />{:else}<span class="field-help">—</span>{/if}</td>
                {/if}
              </tr>
            {/each}
          </tbody>
        {/each}
      </table>
    </div>
    {#if next}
      <div class="panel-footer"><button class="button secondary" disabled={busy} onclick={() => {
        if (page.params.id && next && !busy) void load(page.params.id, fromHistory, controller.signal, next);
      }}>{busy ? 'Loading…' : 'Load more reports'}</button></div>
    {/if}
  </section>
{/if}

<section class="panel advisory-panel" aria-labelledby="advisory-overview">
  <div class="panel-title"><div><h2 id="advisory-overview">Advisory</h2><p>Scores and references recorded by the scanner</p></div></div>
  <div class="advisory-body"><AdvisoryDetails id={page.params.id ?? ''} compact /></div>
</section>

<style>
  .advisory-body { padding: 1rem 1.15rem 1.15rem; }
  .back-link, .report-link { display: inline-flex; align-items: center; gap: .4rem; }
  .advisory-title { display: flex; align-items: center; gap: .8rem; flex-wrap: wrap; }
  .affected-table th:first-child { min-width: 13rem; }
  .affected-table th { min-width: 6.25rem; }
  .affected-table tbody + tbody { border-top: 1px solid var(--line); }
</style>
