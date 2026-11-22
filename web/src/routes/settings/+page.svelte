<script lang="ts">
  import { auth, returnPath } from '#lib/auth.svelte.js';
  import UserSettings from '#lib/UserSettings.svelte';
  import { productName } from '#lib/product.js';
  import { page } from '$app/state';
  import { onMount } from 'svelte';
  import IssueTrackerSettings from '#lib/IssueTrackerSettings.svelte';
  import FindingDisplaySettings from '#lib/FindingDisplaySettings.svelte';
  import ImageWatches from '#lib/ImageWatches.svelte';
  import ReportBrandingSettings from '#lib/ReportBrandingSettings.svelte';
  import { api, message, post, scannerProviders, type ScannerAvailability } from '#lib/api.js';

  interface Preferences {
    scanDays: number;
    auditDays: number;
    batchDays: number;
    channel: string;
    notifyFailures: boolean;
    notifyScanSuccesses: boolean;
    cleanupS3Artifacts: boolean;
    notificationConfigured: boolean;
  }

  const sections = [
    { id: 'scanner-providers', label: 'Scanner providers', href: '/settings' },
    { id: 'issue-trackers', label: 'Issue trackers', href: '/settings?section=issue-trackers' },
    { id: 'retention-notifications', label: 'Retention & alerts', href: '/settings?section=retention-notifications' },
    { id: 'image-watches', label: 'Image watches', href: '/settings?section=image-watches' },
    { id: 'findings-display', label: 'Findings display', href: '/settings?section=findings-display' },
    { id: 'reports', label: 'Reports', href: '/settings?section=reports' },
    { id: 'users', label: 'Users', href: '/settings?section=users' }
  ] as const;
  const trackerReturn = $derived(returnPath(new URL(page.url.href)));
  const requestedSection = $derived(page.url.searchParams.get('section') ?? page.url.hash.slice(1));
  const section = $derived(
    !auth.admin ? 'image-watches' : requestedSection === 'notifications-title' || requestedSection === 'retention-title'
      ? 'retention-notifications'
      : sections.find(item => item.id === requestedSection)?.id ?? 'scanner-providers'
  );
  const retentionFields = [
    { key: 'scanDays', label: 'Completed scans' },
    { key: 'auditDays', label: 'Audit entries' },
    { key: 'batchDays', label: 'Batch and schedule history' }
  ] as const;
  const notificationChannels = [
    ['webhook', 'JSON webhook'], ['slack', 'Slack'], ['teams', 'Microsoft Teams'],
    ['gotify', 'Gotify'], ['apprise', 'Apprise']
  ] as const;

  let savedPreferences = $state<Preferences>();
  let draft = $state<Preferences>();
  let notificationUrl = $state('');
  let removeNotification = $state(false);
  let preferencesLoading = $state(true);
  let preferencesBusy = $state<'save' | 'test'>();
  let preferencesIssue = $state('');
  let preferencesNotice = $state('');
  let testIssue = $state('');
  let testNotice = $state('');

  let scannerAccess = $state<ScannerAvailability>();
  let selected = $state<string[]>([]);
  let scannerLoading = $state(true);
  let scannerBusy = $state(false);
  let scannerIssue = $state('');
  let scannerNotice = $state('');

  const defaultScanners = $derived(scannerAccess?.defaults ?? ['trivy']);
  const scannerDirty = $derived(
    !!scannerAccess && (selected.length !== defaultScanners.length || selected.some(id => !defaultScanners.includes(id)))
  );
  const unavailableSelected = $derived(selected.some(id => !scannerAccess?.registry.includes(id)));
  const previewDefaults = $derived(scannerDirty && !unavailableSelected);
  const effectiveDefaults = $derived.by(() => {
    if (!scannerAccess) return [];
    const defaults = previewDefaults ? selected : defaultScanners;
    return [
      { label: 'Registry scans', available: scannerAccess.registry },
      { label: 'Local scans', available: scannerAccess.local }
    ].map(({ label, available }) => {
      const supported = defaults.filter(id => available.includes(id));
      const names = (supported.length ? supported : ['trivy']).map(id =>
        scannerProviders.find(provider => provider.id === id)?.name ?? id
      );
      return { label, names: names.join(', ') };
    });
  });
  const destinationDirty = $derived(
    !!notificationUrl.trim() || removeNotification || draft?.channel !== savedPreferences?.channel
  );
  const preferencesDirty = $derived(
    !!savedPreferences && (destinationDirty || JSON.stringify(draft) !== JSON.stringify(savedPreferences))
  );

  onMount(() => {
    if (!auth.admin) return;
    void loadPreferences();
    void loadScanners();
  });

  async function loadPreferences() {
    preferencesLoading = true;
    preferencesIssue = '';
    try {
      savedPreferences = await api<Preferences>('/settings');
      draft = { ...savedPreferences };
    } catch (error) {
      preferencesIssue = message(error);
    } finally {
      preferencesLoading = false;
    }
  }

  async function loadScanners() {
    scannerLoading = true;
    scannerIssue = '';
    try {
      scannerAccess = await api<ScannerAvailability>('/scanners/available');
      selected = [...defaultScanners];
    } catch (error) {
      scannerIssue = message(error);
    } finally {
      scannerLoading = false;
    }
  }

  function discardScanners() {
    selected = [...defaultScanners];
    scannerNotice = 'Changes discarded.';
    scannerIssue = '';
  }

  async function saveScanners(event: SubmitEvent) {
    event.preventDefault();
    if (!scannerAccess || !scannerDirty || scannerBusy || unavailableSelected) return;

    scannerBusy = true;
    scannerIssue = '';
    scannerNotice = '';
    const scanners = [...selected];
    try {
      await api('/settings/scanners', { ...post({ scanners }), method: 'PUT' });
      scannerAccess.defaults = scanners.length ? scanners : null;
      selected = [...defaultScanners];
      scannerNotice = 'Scanner defaults saved.';
    } catch (error) {
      scannerIssue = message(error);
    } finally {
      scannerBusy = false;
    }
  }

  function discardPreferences() {
    if (!savedPreferences) return;
    draft = { ...savedPreferences };
    notificationUrl = '';
    removeNotification = false;
    preferencesNotice = 'Changes discarded.';
    preferencesIssue = '';
    testIssue = '';
    testNotice = '';
  }

  async function savePreferences(event: SubmitEvent) {
    event.preventDefault();
    if (!draft || !preferencesDirty || preferencesBusy) return;

    preferencesBusy = 'save';
    preferencesIssue = '';
    preferencesNotice = '';
    testIssue = '';
    testNotice = '';

    const { notificationConfigured, ...values } = draft;
    const url = removeNotification ? '' : notificationUrl.trim();
    try {
      await api('/settings', {
        ...post({ ...values, notificationUrl: url, removeNotification }),
        method: 'PUT'
      });
      savedPreferences = { ...values, notificationConfigured: !removeNotification && (!!url || notificationConfigured) };
      draft = { ...savedPreferences };
      notificationUrl = '';
      removeNotification = false;
      preferencesNotice = 'Preferences saved.';
    } catch (error) {
      preferencesIssue = message(error);
    } finally {
      preferencesBusy = undefined;
    }
  }

  async function testNotification() {
    if (!savedPreferences?.notificationConfigured || destinationDirty || preferencesBusy) return;

    preferencesBusy = 'test';
    testIssue = '';
    testNotice = '';
    try {
      await api('/settings/notifications/test', post({}));
      testNotice = 'Test notification delivered.';
    } catch (error) {
      testIssue = message(error);
    } finally {
      preferencesBusy = undefined;
    }
  }
</script>

<svelte:head><title>Workspace preferences · {productName}</title></svelte:head>

{#snippet saveBar(changed: boolean, busy: boolean, status: string, action: string, discard: () => void, blocked = false)}
  <footer class="settings-footer">
    <p class:unsaved={changed} role="status">{changed ? 'Unsaved changes' : status}</p>
    <div class="filters">
      {#if changed}<button type="button" class="button secondary" disabled={busy} onclick={discard}>Discard changes</button>{/if}
      <button type="submit" class="button primary" disabled={busy || !changed || blocked}>{action}</button>
    </div>
  </footer>
{/snippet}

<div class="settings-workspace">
  {#if auth.admin}<div class="page-heading">
    <div><h1>Workspace preferences</h1><p>Configure scanner defaults, issue trackers, retention, and alerts.</p></div>
  </div>

  <nav class="tabs settings-nav" aria-label="Settings sections">
    {#each sections as item (item.id)}
      {@const changed = item.id === 'scanner-providers' ? scannerDirty : item.id === 'retention-notifications' && preferencesDirty}
      <a href={item.href} class:tab-active={section === item.id}
        aria-current={section === item.id ? 'location' : undefined}
        aria-label={changed ? item.label + ' (unsaved changes)' : undefined}>
        {item.label}
        {#if changed}<span class="draft-dot" aria-hidden="true" title="Unsaved changes"></span>{/if}
      </a>
    {/each}
  </nav>{/if}

  {#if section === 'scanner-providers'}
    <div class="scanner-layout">
      <section class="panel" id="scanner-providers" aria-labelledby="scanner-title">
        <div class="panel-title">
          <div><h2 id="scanner-title">Scanner providers</h2><p>These defaults apply to scheduled scans, webhooks, and scans without an explicit selection.</p></div>
        </div>
        {#if scannerLoading}
          <p class="compact-empty" role="status">Loading scanner providers…</p>
        {:else if !scannerAccess}
          <div class="settings-message">
            <p class="notice error" role="alert">{scannerIssue}</p>
            <button class="button secondary" onclick={loadScanners}>Retry</button>
          </div>
        {:else}
          <form onsubmit={saveScanners}>
            <fieldset class="scanner-list" disabled={scannerBusy} aria-label="Default scanner providers">
              <div class="scanner-columns" aria-hidden="true">
                <span>Provider</span><span>Supported scan sources</span><span>Default</span>
              </div>
              {#each scannerProviders as provider (provider.id)}
                {@const available = scannerAccess.registry.includes(provider.id)}
                <label class="scanner-row">
                  <span class="scanner-label"><strong>{provider.name}</strong><small>{provider.purpose}</small></span>
                  <span class="scanner-coverage" class:unavailable={!available} id={'scanner-coverage-' + provider.id}>
                    {available ? (scannerAccess.local.includes(provider.id) ? 'Registry and local' : 'Registry only') : 'Not installed'}
                  </span>
                  <input type="checkbox" value={provider.id} bind:group={selected} aria-label={'Use ' + provider.name + ' by default'}
                    aria-describedby={'scanner-coverage-' + provider.id} disabled={!available && !selected.includes(provider.id)} />
                </label>
              {/each}
            </fieldset>
            <div class="settings-message">
              {#if unavailableSelected}
                <p class="notice warning">Remove unavailable providers from the selection before saving.</p>
              {/if}
              {#if scannerIssue}<p class="notice error" role="alert">{scannerIssue}</p>{/if}
              <p class="field-help">
                Trivy runs when no default provider is selected.
                {#if scannerAccess.registry.some(engine => !scannerAccess?.local.includes(engine))}
                  Local scans use Trivy if none of the selected providers can run locally.
                {/if}
                {#if scannerAccess.registry.length < scannerProviders.length}
                  The standard Docker image includes the additional providers.
                {/if}
              </p>
            </div>
            {@render saveBar(scannerDirty, scannerBusy, scannerNotice, scannerBusy ? 'Saving…' : 'Save scanner defaults', discardScanners, unavailableSelected)}
          </form>
        {/if}
      </section>
      {#if scannerAccess}
        <aside class="panel" aria-labelledby="effective-defaults-title">
          <div class="panel-title"><div><h2 id="effective-defaults-title">Effective defaults</h2>
            <p>{previewDefaults ? 'Preview after saving' : 'Used when a scan has no explicit selection'}</p></div>
          </div>
          <dl class="effective-defaults">
            {#each effectiveDefaults as { label, names } (label)}
              <div><dt>{label}</dt><dd>{names}</dd></div>
            {/each}
          </dl>
        </aside>
      {/if}
    </div>
  {:else if section === 'issue-trackers'}
    {#if trackerReturn.startsWith('/scans/')}<p><a class="table-link" href={trackerReturn}>Return to finding</a></p>{/if}
    <IssueTrackerSettings />
  {:else if section === 'retention-notifications'}
    <section class="panel" id="retention-notifications" aria-labelledby="retention-notifications-title">
      <div class="panel-title">
        <div><h2 id="retention-notifications-title">Retention &amp; alerts</h2><p>Set when workspace records expire and which scan events send a notification.</p></div>
      </div>
      {#if preferencesLoading}
        <p class="compact-empty" role="status">Loading preferences…</p>
      {:else if !draft || !savedPreferences}
        <div class="settings-message">
          <p class="notice error" role="alert">{preferencesIssue}</p>
          <button class="button secondary" onclick={loadPreferences}>Retry</button>
        </div>
      {:else}
        <form onsubmit={savePreferences}>
          <fieldset class="maintenance-fields" disabled={!!preferencesBusy} aria-label="Retention and alert preferences">
            <section class="preference-group" aria-labelledby="retention-title">
              <div><h3 id="retention-title">Data retention</h3><p class="field-help">Choose between 1 and 365 days for each record type.</p></div>
              <div class="retention-rows">
                {#each retentionFields as field (field.key)}
                  <label class="retention-row">
                    <span>{field.label}</span>
                    <span class="duration-control">
                      <input type="number" required min="1" max="365" bind:value={draft[field.key]}
                        aria-label={'Days to keep ' + field.label.toLowerCase()} />
                      <span aria-hidden="true">days</span>
                    </span>
                  </label>
                {/each}
              </div>
              <label class="inline-check"><input type="checkbox" bind:checked={draft.cleanupS3Artifacts} /> Remove stored S3 artifacts when their scans expire</label>
            </section>

            <section class="preference-group" aria-labelledby="notifications-title">
              <div class="notifications-heading">
                <h3 id="notifications-title">Notifications</h3>
                <span class="badge" class:completed={savedPreferences.notificationConfigured} class:neutral={!savedPreferences.notificationConfigured}>
                  {savedPreferences.notificationConfigured ? 'Destination saved' : 'No destination saved'}
                </span>
              </div>
              <label class="field"><span>Delivery channel</span><select bind:value={draft.channel}>
                {#each notificationChannels as [id, label] (id)}<option value={id}>{label}</option>{/each}
              </select></label>
              <label class="field"><span>HTTPS webhook URL</span>
                <input type="url" autocomplete="off" spellcheck="false" bind:value={notificationUrl}
                  disabled={removeNotification} placeholder="https://…" />
                {#if savedPreferences.notificationConfigured}<small>Enter a URL to replace the stored destination.</small>{/if}
              </label>
              <fieldset class="notification-events">
                <legend>Notify on</legend>
                <label class="inline-check"><input type="checkbox" bind:checked={draft.notifyScanSuccesses} /> Successful scans</label>
                <label class="inline-check"><input type="checkbox" bind:checked={draft.notifyFailures} /> Failed scans</label>
              </fieldset>
              {#if savedPreferences.notificationConfigured}
                <label class="inline-check"><input type="checkbox" bind:checked={removeNotification} /> Remove saved webhook</label>
                <div class="notification-test">
                  <button type="button" class="button secondary" onclick={testNotification} disabled={destinationDirty || !!preferencesBusy}>
                    {preferencesBusy === 'test' ? 'Sending…' : 'Send test notification'}
                  </button>
                  {#if destinationDirty}<p class="field-help">Save destination changes before testing.</p>{/if}
                  {#if testIssue}<p class="notice error" role="alert">{testIssue}</p>{/if}
                  {#if testNotice}<p class="field-help" role="status">{testNotice}</p>{/if}
                </div>
              {/if}
            </section>
          </fieldset>

          {#if preferencesIssue}<div class="settings-message"><p class="notice error" role="alert">{preferencesIssue}</p></div>{/if}
          {@render saveBar(preferencesDirty, !!preferencesBusy, preferencesNotice, preferencesBusy === 'save' ? 'Saving…' : 'Save preferences', discardPreferences)}
        </form>
      {/if}
    </section>
  {:else if section === 'image-watches'}
    <ImageWatches destination={savedPreferences?.notificationConfigured} />
  {:else if section === 'findings-display'}
    <FindingDisplaySettings />
  {:else if section === 'users'}
    <UserSettings />
  {:else if section === 'reports'}
    <ReportBrandingSettings />
  {/if}
</div>

<style>
  .settings-workspace { max-inline-size: 92rem; container-type: inline-size; }
  .settings-nav { margin-bottom: 1.25rem; }
  .settings-nav a { min-height: 44px; padding-inline: .85rem; font-size: .875rem; }
  .settings-nav a:focus-visible { outline-offset: -3px; }
  .draft-dot { width: .42rem; height: .42rem; flex: none; border-radius: 50%; background: var(--high); }
  .settings-workspace :global(#notifications-title),
  .settings-workspace :global(#retention-title) { scroll-margin-top: 1rem; }
  .settings-workspace :global(.settings-empty) { display: grid; gap: .55rem; justify-items: start; padding: 1.3rem 1.15rem; }
  .settings-workspace :global(.settings-empty > p) { max-inline-size: 64ch; color: var(--muted); font-size: .88rem; }
  .settings-workspace :global(.settings-empty > .notice) { width: 100%; max-inline-size: none; margin: 0; color: var(--critical); }

  .scanner-layout { display: grid; grid-template-columns: minmax(0, 1fr) minmax(14rem, .36fr); align-items: start; gap: 1rem; }
  .scanner-layout > .panel { margin-bottom: 0; }
  .scanner-list, .maintenance-fields, .notification-events { margin: 0; padding: 0; min-inline-size: 0; border: 0; }
  .scanner-columns, .scanner-row {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(9rem, .55fr) 4.1rem;
    align-items: center;
    gap: .9rem;
    padding: .75rem 1.15rem;
  }
  .scanner-columns { background: var(--inset); color: var(--muted); font-size: .76rem; font-weight: 750; }
  .scanner-columns > :last-child { text-align: center; }
  .scanner-row { min-height: 54px; border-bottom: 1px solid var(--line); cursor: pointer; }
  .scanner-row:not(:has(input:disabled)):hover { background: var(--canvas); }
  .scanner-row:has(input:disabled) { cursor: default; }
  .scanner-label { display: grid; gap: .2rem; min-width: 0; }
  .scanner-label strong { font-size: .95rem; }
  .scanner-label small, .scanner-coverage { font-size: .82rem; color: var(--muted); }
  .scanner-coverage.unavailable { color: var(--muted); font-style: italic; }
  .scanner-row input { justify-self: center; }
  .effective-defaults { display: grid; gap: 0; margin: 0; padding: .15rem 1.15rem; }
  .effective-defaults > div { display: grid; gap: .25rem; padding-block: .85rem; }
  .effective-defaults > div + div { border-top: 1px solid var(--line); }
  .effective-defaults dt { color: var(--muted); font-size: .79rem; font-weight: 700; }
  .effective-defaults dd { margin: 0; font-weight: 800; font-size: .92rem; overflow-wrap: anywhere; }

  .settings-message { padding: .85rem 1.15rem; }
  .settings-message .field-help { max-inline-size: 78ch; }
  .settings-message .notice { margin: 0 0 .7rem; }
  .settings-footer {
    display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: .65rem;
    padding: .8rem 1.15rem; border-top: 1px solid var(--line); background: var(--canvas);
  }
  .settings-footer p { color: var(--successful); font-size: .82rem; font-weight: 700; }
  .settings-footer p.unsaved { color: var(--high); }
  .settings-footer .filters { margin-inline-start: auto; justify-content: flex-end; }

  .maintenance-fields { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.12fr); }
  .preference-group { display: grid; align-content: start; gap: .95rem; min-width: 0; padding: 1.15rem; }
  .preference-group + .preference-group { border-inline-start: 1px solid var(--line); }
  .preference-group h3 + p { margin-top: .2rem; }
  .retention-row {
    display: flex; align-items: center; justify-content: space-between; gap: .75rem;
    min-height: 50px; padding-block: .45rem; border-bottom: 1px solid var(--line);
    font-size: .84rem; font-weight: 700;
  }
  .duration-control { display: flex; align-items: center; gap: .38rem; flex: none; color: var(--muted); font-weight: 600; }
  .duration-control input { inline-size: 4.65rem; font-variant-numeric: tabular-nums; }
  .notifications-heading { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: .5rem; }
  .notifications-heading .badge { text-transform: none; }
  .notification-events legend { margin-bottom: .2rem; padding: 0; font-size: .84rem; font-weight: 750; }
  .notification-events label { margin-inline-end: .85rem; }
  .notification-test { display: grid; gap: .45rem; justify-items: start; padding-top: .8rem; border-top: 1px solid var(--line); }
  .notification-test .notice { margin: 0; }

  @container (max-width: 49rem) {
    .scanner-layout { grid-template-columns: 1fr; }
    .effective-defaults { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .75rem; }
    .effective-defaults > div + div { border-top: 0; }
    .maintenance-fields { grid-template-columns: 1fr; }
    .preference-group + .preference-group { border-inline-start: 0; border-top: 1px solid var(--line); }
  }
  @container (max-width: 35rem) {
    .scanner-columns { display: none; }
    .scanner-row { grid-template-columns: minmax(0, 1fr) auto; gap: .2rem .8rem; padding: .7rem 1rem; }
    .scanner-coverage { grid-row: 2; }
    .scanner-row input { grid-column: 2; grid-row: 1 / span 2; }
    .settings-nav a { padding-inline: .6rem; }
  }
</style>
