<script lang="ts">
  import { auth } from '#lib/auth.svelte.js';
  import AdvisoryDetails from '#lib/AdvisoryDetails.svelte';
  import ConfigDialog from '#lib/ConfigDialog.svelte';
  import IssueLink from '#lib/IssueLink.svelte';
  import { allPages, api, classifications, message, post, shortDigest } from '#lib/api.js';
  import { detectionKey, findingDetectors } from '#lib/finding-evidence.js';
  import { classificationsPath, issueTrackersPath, trackerName, type FindingTracking, type IssueTracker, type TrackerIssue, type TrackingTarget } from '#lib/tracking.js';

  let { target, scanners, evidencePending = false, evidenceUnavailable = false, dismiss, onSaved }: {
    target?: TrackingTarget;
    scanners?: string[];
    evidencePending?: boolean;
    evidenceUnavailable?: boolean;
    dismiss: () => void;
    onSaved: () => void;
  } = $props();
  let status = $state('open');
  let note = $state('');
  const keepExisting = 'existing';
  let trackers = $state<IssueTracker[]>([]);
  let trackerId = $state('');
  let stored = $state<TrackerIssue>();
  let storedChoice = $state('');
  let key = $state('');
  let loaded = $state(false);
  let busy = $state(false);
  let error = $state('');
  let detected = $state<string[]>([]);
  let detectorLoading = $state(false);
  let detectorError = $state(false);
  let advisoryOpen = $state(false);
  const detectorNames = $derived(scanners ?? detected);
  const detectorStatus = $derived((scanners === undefined ? detectorLoading : evidencePending)
    ? 'Loading…' : detectorNames.join(', ') || ((scanners === undefined ? detectorError : evidenceUnavailable) ? 'Unavailable' : 'Not recorded'));

  $effect(() => {
    const entry = target;
    loaded = false; error = ''; advisoryOpen = false;
    if (!entry) return;
    const controller = new AbortController();
    const options = {signal:controller.signal};
    void Promise.all([
      api<FindingTracking[]>(classificationsPath(entry.scanId, entry.finding), options),
      auth.operator ? allPages<IssueTracker>(issueTrackersPath, options) : Promise.resolve([])
    ]).then(([items, configured]) => {
      if (controller.signal.aborted) return;
      const saved = items.find(item => item.finding === entry.finding);
      status = saved?.status ?? 'open';
      note = saved?.note ?? '';
      trackers = configured;
      stored = saved?.issue ?? undefined;
      storedChoice = stored
        ? configured.find(tracker => tracker.id === stored?.trackerId)?.id ?? keepExisting : '';
      trackerId = storedChoice;
      key = stored?.key ?? '';
      loaded = true;
    }).catch(issue => {
      if (!controller.signal.aborted) error = message(issue);
    });
    return () => controller.abort();
  });

  $effect(() => {
    const entry = target;
    detected = [];
    detectorError = false;
    detectorLoading = false;
    if (scanners !== undefined || !entry?.details.length) return;
    const request = new AbortController();
    detectorLoading = true;
    void findingDetectors(entry.scanId, request.signal).then(found => {
      if (!request.signal.aborted) detected = [...new Set(entry.details.flatMap(detail => found.get(detectionKey(detail)) ?? []))].sort();
    }).catch(() => {
      if (!request.signal.aborted) detectorError = true;
    }).finally(() => {
      if (!request.signal.aborted) detectorLoading = false;
    });
    return () => request.abort();
  });

  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (!auth.operator || !target || !loaded || busy) return;
    const entry = target;
    busy = true; error = '';
    const issueId = key.trim();
    const unchanged = trackerId === keepExisting
      || (stored && trackerId === storedChoice && issueId === stored.key);
    const payload = {
      finding:entry.finding, status, note,
      ...(unchanged ? {} : {issue:trackerId ? {trackerId, key:issueId} : null})
    };
    try {
      await api(classificationsPath(entry.scanId), {...post(payload), method:'PUT'});
      if (target === entry) onSaved();
    } catch (issue) {
      if (target === entry) error = message(issue);
    }
    finally { busy = false; }
  }
</script>

<ConfigDialog id="finding-tracker" title={target?.finding ?? 'Vulnerability details'}
  description={target ? target.reference + ' · ' + target.platform : undefined} open={!!target} {busy} {dismiss} onsubmit={save}>
  {#if loaded}
    <fieldset class="tracking-status" disabled={busy || !auth.operator}>
      <legend>Tracking status</legend>
      <div class="status-options">
        {#each classifications as [value,label] (value)}
          <label><input type="radio" {value} bind:group={status} />{label}</label>
        {/each}
      </div>
    </fieldset>
    {#if target}<p class="field-help">Status and issue link apply to this image version and platform.{#if target.digest}{' '}<span class="mono break" title={target.digest}>{shortDigest(target.digest)}</span>{/if}</p>{/if}
  {:else if !error}
    <p class="field-help" role="status">Loading tracking details…</p>
  {/if}
  {#if target?.details.length}
    {@const finding = target.details[0]}
    <section class="finding-context" aria-label="Vulnerability evidence">
      <div class="context-heading">
        <span class={'severity ' + finding.severity.toLowerCase()}>{finding.severity.toLowerCase()}</span>
        {#if finding.title}<p>{finding.title}</p>{/if}
      </div>
      {#if target.details.length === 1}
        <dl>
          <div><dt>Package</dt><dd>{finding.package}</dd></div>
          <div><dt>Installed</dt><dd>{finding.installed || 'Unknown'}</dd></div>
          <div><dt>Reported fix</dt><dd>{finding.fixed || 'None reported'}</dd></div>
          <div><dt>Detected by</dt><dd>{detectorStatus}</dd></div>
        </dl>
      {:else}
        <div class="table-wrap"><table class="package-evidence">
          <thead><tr><th scope="col">Package</th><th scope="col">Installed</th><th scope="col">Reported fix</th></tr></thead>
          <tbody>{#each target.details as detail}
            <tr><td>{detail.package}<small>{detail.ecosystem}</small></td><td>{detail.installed || 'Unknown'}</td><td>{detail.fixed || 'None reported'}</td></tr>
          {/each}</tbody>
        </table></div>
        <dl><div><dt>Detected by</dt><dd>{detectorStatus}</dd></div></dl>
      {/if}
    </section>
  {/if}
  {#if loaded}
    <label class="field"><span>Note {#if auth.operator}<small>Optional</small>{/if}</span>
      <textarea rows="3" maxlength="4000" bind:value={note} disabled={busy} readonly={!auth.operator}></textarea>
      {#if status === 'false_positive'}<small>An explanatory note is included in this scan’s OpenVEX export.</small>{/if}
    </label>
    {#if auth.operator && (trackers.length || stored)}
    <label class="field"><span>Issue tracker</span>
      <select bind:value={trackerId} disabled={busy}>
        <option value="">No linked issue</option>
        {#if storedChoice === keepExisting}<option value={keepExisting}>Keep existing link</option>{/if}
        {#each trackers as tracker (tracker.id)}
          <option value={tracker.id}>{tracker.name} · {trackerName(tracker.provider)}</option>
        {/each}
      </select>
    </label>
    {#if trackerId && trackerId !== keepExisting}
      <label class="field"><span>Issue ID</span>
        <input class="mono" required maxlength="101" placeholder="SEC-123 or 42" bind:value={key} disabled={busy} />
      </label>
    {/if}
    {#if stored && trackerId === storedChoice && (trackerId === keepExisting || key === stored.key)}
      <p class="field-help">Current issue <IssueLink issue={stored} /></p>
    {/if}
    {:else if stored}
      <p class="field-help">Current issue <IssueLink issue={stored} /></p>
    {:else if auth.admin}
      <p class="field-help"><a href="/settings?section=issue-trackers">Set up an issue tracker</a> to link this vulnerability to an issue.</p>
    {/if}
  {/if}
  {#if target}
    <details class="form-disclosure" bind:open={advisoryOpen}>
      <summary>Advisory details</summary>
      <div class="disclosure-body">
        {#if advisoryOpen}<AdvisoryDetails id={target.finding} compact />{/if}
        <a class="advisory-link" href={'/library/' + encodeURIComponent(target.finding)}>View all affected images</a>
      </div>
    </details>
  {/if}
  {#if error}<div class="notice error" role="alert">{error}</div>{/if}
  {#snippet actions()}
    <button type="button" class="button secondary" disabled={busy} onclick={dismiss}>{auth.operator ? 'Cancel' : 'Close'}</button>
    {#if auth.operator}<button type="submit" class="button primary" disabled={busy || !loaded}>{busy ? 'Saving…' : 'Save tracking'}</button>{/if}
  {/snippet}
</ConfigDialog>


<style>
  .finding-context { display: grid; gap: .8rem; padding: .85rem; border: 1px solid var(--line); border-radius: var(--radius); background: var(--canvas); }
  .context-heading { display: flex; align-items: flex-start; gap: .55rem; }
  .context-heading p { font-size: .85rem; font-weight: 750; overflow-wrap: anywhere; }
  .finding-context dl { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .65rem 1rem; margin: 0; }
  .finding-context dt { color: var(--muted); font-size: var(--text-detail); }
  .finding-context dd { margin: .16rem 0 0; font-size: var(--text-label); font-weight: 750; overflow-wrap: anywhere; }
  .package-evidence :is(th, td) { padding: .4rem .55rem; }
  .advisory-link { justify-self: start; color: var(--accent-ink); font-size: .82rem; font-weight: 800; text-underline-offset: 3px; }
  .tracking-status { min-width: 0; margin: 0; padding: 0; border: 0; }
  .tracking-status legend { margin-bottom: .5rem; padding: 0; font-size: var(--text-label); font-weight: 750; }
  .status-options { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 9rem), 1fr)); gap: .4rem; }
  .status-options label { display: flex; align-items: center; gap: .45rem; min-height: 44px; padding: .4rem .5rem; border: 1px solid var(--control-line); border-radius: 6px; font-size: var(--text-label); cursor: pointer; }
  .status-options label:has(input:checked) { border-color: var(--accent); background: var(--accent-soft); }
  .status-options input { flex: none; min-height: auto; margin: 0; accent-color: var(--accent); }
  @media (max-width: 480px) {
    .status-options { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }
</style>
