<script lang="ts">
  import { auth } from '#lib/auth.svelte.js';
  import AdvisoryDetails from '#lib/AdvisoryDetails.svelte';
  import ConfigDialog from '#lib/ConfigDialog.svelte';
  import IssueLink from '#lib/IssueLink.svelte';
  import { allPages, api, classifications, message, post, scannerName, shortDigest, type Finding, type ScanDetail } from '#lib/api.js';
  import { detectionKey, findingDescription } from '#lib/finding-evidence.js';
  import { classificationsPath, findingReportPath, issueTrackersPath, trackerName, type ExceptionScope, type FindingException, type FindingTracking, type IssueScope, type IssueTracker, type TrackerIssue, type TrackingTarget } from '#lib/tracking.js';

  let { target, findingSources, evidencePending = false, evidenceUnavailable = false, dismiss, onSaved }: {
    target?: TrackingTarget;
    findingSources?: Map<string, string[]>;
    evidencePending?: boolean;
    evidenceUnavailable?: boolean;
    dismiss: () => void;
    onSaved: () => void;
  } = $props();
  let status = $state('open');
  let note = $state('');
  let savedException = $state<FindingException>();
  let exceptionMode = $state<'keep' | 'set' | 'revoke'>('keep');
  let exceptionScope = $state<ExceptionScope>('reference');
  let exceptionReason = $state('');
  let exceptionExpiry = $state('');
  let reasonInput = $state<HTMLTextAreaElement>();
  let expiryInput = $state<HTMLInputElement>();
  let invalidException = $state<'reason' | 'expiry'>();
  const exceptionToday = $derived(target ? new Date().toISOString().slice(0, 10) : '');
  const keepExisting = 'existing';
  let trackers = $state<IssueTracker[]>([]);
  let trackerId = $state('');
  let scope = $state<IssueScope>('advisory');
  let stored = $state<TrackerIssue>();
  let storedChoice = $state('');
  let key = $state('');
  let loaded = $state(false);
  let busy = $state(false);
  let error = $state('');
  let handoff = $state('');
  let copied = $state(false);
  const setupPath = $derived(target ? '/settings?' + new URLSearchParams({
    section: 'issue-trackers', next: findingReportPath(target.scanId, target.finding, true)
  }) : '/settings?section=issue-trackers');

  async function draftIssue(entry: TrackingTarget) {
    const link = new URL(findingReportPath(entry.scanId, entry.finding), window.location.origin);
    handoff = [
      entry.finding + (scope === 'advisory' ? ' · affected packages and images' : ' detected in ' + entry.reference),
      ...(scope === 'advisory' ? ['All affected images: ' + new URL('/library/' + encodeURIComponent(entry.finding), window.location.origin).href] : []),
      '',
      'Image: ' + entry.reference,
      'Platform: ' + entry.platform,
      ...(entry.digest?.startsWith('sha256:') ? ['Manifest digest: ' + entry.digest] : []),
      'Scan report: ' + link.href,
      '',
      ...details.map(detail => '- ' + detail.package + ' (' + detail.ecosystem + ') ' + detail.installed
        + (detail.fixed ? ' · Reported fix ' + detail.fixed : '')),
      '',
      'Presence reflects the findings reported in this scan.'
    ].join('\n');
    try {
      await navigator.clipboard.writeText(handoff);
      if (target === entry) copied = true;
    } catch {
      if (target === entry) copied = false;
    }
  }
  let refreshedDetails = $state<Finding[]>();
  let detectorLoading = $state(false);
  let detectorError = $state(false);
  let advisoryOpen = $state(false);
  const details = $derived(refreshedDetails ?? target?.details ?? []);
  const evidence = $derived(details.map(detail => ({
    detail,
    names: [...new Set((detail.detectedBy?.length ? detail.detectedBy.map(scannerName)
      : findingSources?.get(detectionKey(detail))) ?? [])].sort()
  })));
  const detectorNames = $derived([...new Set(evidence.flatMap(row => row.names))].sort());
  const aliases = $derived([...new Set(details.flatMap(detail => detail.aliases ?? []))]);
  const description = $derived(findingDescription(evidence[0]?.detail.title ?? ''));
  const detectorStatus = $derived((findingSources ? evidencePending : detectorLoading)
    ? 'Loading…' : (findingSources ? evidenceUnavailable : detectorError) ? 'Unavailable' : 'Not recorded');
  const showPackageDetectors = $derived(evidence.length > 1
    && evidence.some(row => row.names.join(', ') !== evidence[0].names.join(', ')));

  $effect(() => {
    const entry = target;
    loaded = false; error = ''; advisoryOpen = false; handoff = ''; copied = false;
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
      savedException = saved?.exception;
      exceptionMode = 'keep';
      invalidException = undefined;
      exceptionScope = saved?.exception?.scope ?? 'reference';
      exceptionReason = saved?.exception?.reason ?? '';
      exceptionExpiry = saved?.exception?.expiresAt.slice(0, 10) ?? '';
      trackers = configured;
      stored = saved?.issue ?? undefined;
      storedChoice = stored
        ? configured.find(tracker => tracker.id === stored?.trackerId)?.id ?? keepExisting : '';
      trackerId = storedChoice;
      scope = stored ? (stored.scope ?? 'image') : 'advisory';
      key = stored?.key ?? '';
      loaded = true;
    }).catch(issue => {
      if (!controller.signal.aborted) error = message(issue);
    });
    return () => controller.abort();
  });

  $effect(() => {
    const entry = target;
    refreshedDetails = undefined;
    detectorError = false;
    detectorLoading = false;
    if (findingSources || !entry) return;
    const request = new AbortController();
    detectorLoading = true;
    void api<ScanDetail>('/scans/' + entry.scanId, {signal:request.signal}).then(scan => {
      if (request.signal.aborted) return;
      const all = scan.report?.findings.filter(finding => finding.id === entry.finding);
      if (all?.length) refreshedDetails = all;
      detectorError = scan.report?.evidenceAvailable === false;
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
    if (exceptionMode === 'set') {
      if (!exceptionReason.trim()) {
        invalidException = 'reason';
        reasonInput?.focus();
        return;
      }
      if (!exceptionExpiry || exceptionExpiry < new Date().toISOString().slice(0, 10)) {
        invalidException = 'expiry';
        expiryInput?.focus();
        return;
      }
    }
    const entry = target;
    busy = true; error = '';
    const issueId = key.trim();
    const unchanged = trackerId === keepExisting
      || (stored && trackerId === storedChoice && issueId === stored.key && scope === (stored.scope ?? 'image'));
    const payload = {
      finding:entry.finding, status, note,
      ...(exceptionMode === 'set' ? {exceptionEdit:{
        action:'set', scope:exceptionScope, reason:exceptionReason,
        expiresAt:exceptionExpiry + 'T23:59:59.999Z'
      }} : exceptionMode === 'revoke' ? {exceptionEdit:{action:'revoke', scope:exceptionScope}} : {}),
      ...(unchanged || (!trackerId && !stored) ? {} : {issueScope:scope, issue:trackerId ? {trackerId, key:issueId} : null})
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

{#snippet issueDraft()}
  {#if target}
    <button type="button" class="button secondary" onclick={() => target && draftIssue(target)}>Copy issue draft</button>
    {#if copied}<p class="field-help" role="status">Issue draft copied.</p>
    {:else if handoff}<label class="field"><span>Issue draft</span><textarea readonly rows="6" value={handoff}></textarea></label>{/if}
  {/if}
{/snippet}

<ConfigDialog id="finding-tracker" title={target?.finding ?? 'Vulnerability details'}
  description={target ? target.reference + ' · ' + target.platform : undefined} open={!!target} {busy} {dismiss} onsubmit={save}>
  {#if evidence.length}
    {@const first = evidence[0].detail}
    <section class="finding-summary" aria-label="Vulnerability evidence">
      <div class="context-heading">
        <span class={'severity ' + first.severity.toLowerCase()}>{first.severity.toLowerCase()}</span>
        {#if description.summary}<p>{description.summary}</p>{/if}
      </div>
      {#if aliases.length}<p class="field-help mono">{aliases.join(' · ')}</p>{/if}
      <div class="detectors" aria-label="Detected by">
        <span class="field-help">Detected by</span>
        {#each detectorNames as name (name)}<span class="detector">{name}</span>
        {:else}<span class="field-help" role="status">{detectorStatus}</span>{/each}
      </div>
    </section>
  {/if}

  {#if loaded}
    <div class="tracking-grid">
      <label class="field"><span>Manual tracking status</span>
        <select bind:value={status} disabled={busy || !auth.operator}>
          {#each classifications as [value, label]}<option {value}>{label}</option>{/each}
        </select>
        <small>This image version and platform{#if target?.digest}{' · '}<span class="mono" title={target.digest}>{shortDigest(target.digest)}</span>{/if}</small>
        {#if savedException && status === 'open'}<small><strong>Effective status · Excepted</strong> · Hidden from the open triage queue until expiry or removal.</small>{/if}
      </label>
      {#if stored}
        <div class="linked-issue">
          <span class="field-help">{stored.scope === 'advisory' ? 'Shared ticket' : 'Image ticket'}</span>
          <IssueLink issue={stored} />
          {#if stored.scope === 'advisory' && target}
            <a class="table-link" href={'/library/' + encodeURIComponent(target.finding)}>View affected images</a>
          {/if}
        </div>
      {/if}
    </div>
    {#if savedException || auth.operator}
      <details class="form-disclosure" open={!!savedException || exceptionMode !== 'keep'}>
        <summary>{savedException ? 'Active exception' : 'Exception'}</summary>
        <div class="disclosure-body">
          {#if savedException && exceptionMode !== 'set'}
            <p>{savedException.reason}</p>
            <p class="field-help">
              {savedException.scope === 'repository' ? 'All references in this repository' : 'This image reference'}
              · {target?.platform} · Expires {savedException.expiresAt.slice(0, 10)} UTC
            </p>
          {/if}
          {#if auth.operator}
            {#if exceptionMode === 'set'}
              <label class="field"><span>Exception scope</span>
                <select bind:value={exceptionScope} disabled={busy || !!savedException}>
                  <option value="reference">This tag or digest reference on {target?.platform}</option>
                  <option value="repository">All references in this repository on {target?.platform}</option>
                </select>
                <small>Applies to this advisory. A tag or repository exception applies to future versions in that scope.</small>
              </label>
              <label class="field"><span>Reason</span>
                <textarea bind:this={reasonInput} bind:value={exceptionReason} rows="2" required maxlength="4000" disabled={busy}
                  aria-invalid={invalidException === 'reason' || undefined} aria-describedby={invalidException === 'reason' ? 'finding-exception-reason' : undefined}
                  oninput={() => invalidException = undefined} oninvalid={() => invalidException = 'reason'}></textarea>
                {#if invalidException === 'reason'}<small id="finding-exception-reason" role="alert">Enter a reason for the exception.</small>{/if}
              </label>
              <label class="field"><span>Expiry date (UTC)</span>
                <input type="date" bind:this={expiryInput} bind:value={exceptionExpiry} min={exceptionToday} required disabled={busy}
                  aria-invalid={invalidException === 'expiry' || undefined} aria-describedby="finding-exception-expiry"
                  oninput={() => invalidException = undefined} oninvalid={() => invalidException = 'expiry'} />
                <small id="finding-exception-expiry" role={invalidException === 'expiry' ? 'alert' : undefined}>{invalidException === 'expiry'
                  ? 'Choose today or a future date in UTC.' : 'Expires at the end of the selected day.'}</small>
              </label>
              <button type="button" class="button secondary" onclick={() => exceptionMode = 'keep'} disabled={busy}>Cancel change</button>
            {:else if exceptionMode === 'revoke'}
              <p class="field-help" role="status">The exception will be removed when you save tracking.</p>
              <button type="button" class="button secondary" onclick={() => exceptionMode = 'keep'} disabled={busy}>Keep exception</button>
            {:else}
              <div class="exception-actions">
                <button type="button" class="button secondary" onclick={() => exceptionMode = 'set'} disabled={busy}>
                  {savedException ? 'Edit exception' : 'Add exception'}
                </button>
                {#if savedException}
                  <button type="button" class="button secondary" onclick={() => exceptionMode = 'revoke'} disabled={busy}>Remove exception</button>
                {/if}
              </div>
            {/if}
          {/if}
        </div>
      </details>
    {/if}
    {#if auth.operator && (trackers.length || stored)}
      <details class="form-disclosure" open={!stored && trackers.length > 0}>
        <summary>{stored ? 'Manage issue link' : 'Link a ticket'}</summary>
        <div class="disclosure-body">
          <div class="tracking-grid">
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
          </div>
          {#if (trackerId && trackerId !== keepExisting) || (!trackerId && stored)}
            <label class="field"><span>{trackerId ? 'Ticket scope' : 'Link to remove'}</span>
              <select bind:value={scope} disabled={busy}>
                <option value="advisory">All images for this CVE</option>
                <option value="image">This image version and platform</option>
              </select>
              {#if trackerId && scope === 'advisory'}<small>Reuse one ticket across affected packages and images. Image-specific links take priority.</small>{/if}
            </label>
          {/if}
          {@render issueDraft()}
        </div>
      </details>
    {:else if !stored && auth.admin}
      <p class="field-help"><a href={setupPath}>Set up an issue tracker</a> to link a ticket.</p>
    {:else if !stored && auth.operator}
      <p class="field-help">Ask a workspace administrator to configure an issue tracker.</p>
    {/if}
    {#if auth.operator && !trackers.length && !stored}
      <details class="form-disclosure">
        <summary>Issue draft</summary>
        <div class="disclosure-body">{@render issueDraft()}</div>
      </details>
    {/if}
  {:else if !error}
    <p class="field-help" role="status">Loading tracking details…</p>
  {/if}
  {#if evidence.length}
    <details class="form-disclosure">
      <summary>Affected packages ({evidence.length})</summary>
      <div class="table-wrap"><table class="package-evidence">
        <thead><tr><th scope="col">Package</th><th scope="col">Installed</th><th scope="col">Reported fix</th>
          {#if showPackageDetectors}<th scope="col">Detected by</th>{/if}
        </tr></thead>
        <tbody>{#each evidence as {detail, names}}
          <tr><td>{detail.package}<small>{detail.ecosystem}</small></td><td>{detail.installed || 'Unknown'}</td>
            <td>{detail.fixed || 'None reported'}</td>{#if showPackageDetectors}<td>{names.join(', ') || detectorStatus}</td>{/if}
          </tr>
        {/each}</tbody>
      </table></div>
    </details>
  {/if}
  {#if loaded}
    <label class="field tracking-note"><span>Note {#if auth.operator}<small>Optional</small>{/if}</span>
      <textarea rows="2" maxlength="4000" bind:value={note} disabled={busy} readonly={!auth.operator}></textarea>
      {#if status === 'false_positive'}<small>The OpenVEX export includes this note.</small>{/if}
    </label>
  {/if}
  {#if description.full}
    <section class="scanner-description" aria-labelledby="scanner-description-title">
      <h3 id="scanner-description-title">Scanner description</h3>
      <p>{description.full}</p>
    </section>
  {/if}
  {#if target}
    <details class="form-disclosure" bind:open={advisoryOpen}>
      <summary>Advisory details</summary>
      <div class="disclosure-body">
        {#if advisoryOpen}<AdvisoryDetails id={target.finding} compact />{/if}
        {#if stored?.scope !== 'advisory'}
          <a class="advisory-link" href={'/library/' + encodeURIComponent(target.finding)}>View all affected images</a>
        {/if}
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
  .exception-actions { display: flex; flex-wrap: wrap; gap: .5rem; }
  :global(#finding-tracker) { width: min(43rem, calc(100% - 2rem)); }
  .finding-summary { display: grid; gap: .55rem; padding-bottom: .85rem; border-bottom: 1px solid var(--line); }
  .context-heading, .detectors { display: flex; align-items: baseline; flex-wrap: wrap; gap: .4rem .55rem; }
  .context-heading p { font-size: var(--text-label); font-weight: 750; overflow-wrap: anywhere; }
  .detector { padding: .15rem .45rem; border: 1px solid var(--line); border-radius: 6px; font-size: var(--text-detail); font-weight: 650; }
  .tracking-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .85rem; align-items: start; }
  .linked-issue { display: grid; justify-items: start; gap: .3rem; }
  .tracking-note textarea { min-height: 3.6rem; }
  .scanner-description { display: grid; gap: .35rem; }
  .scanner-description p { white-space: pre-wrap; overflow-wrap: anywhere; font-size: var(--text-label); color: var(--muted); }
  .package-evidence :is(th, td) { padding: .4rem .55rem; }
  .advisory-link { justify-self: start; color: var(--accent-ink); font-size: .82rem; font-weight: 800; text-underline-offset: 3px; }
  @media (max-width: 480px) {
    .tracking-grid { grid-template-columns: 1fr; }
  }
</style>
