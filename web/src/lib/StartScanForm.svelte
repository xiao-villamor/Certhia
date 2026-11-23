<script lang="ts">
  import { goto } from '$app/navigation';
  import ConfigDialog from '#lib/ConfigDialog.svelte';
  import { onMount, onDestroy, tick } from 'svelte';
  import { uniqueSwarmImages, type SwarmImage } from '#lib/swarm-discovery.js';
  import { archiveReference } from '#lib/archive-reference.js';
  import { trivyImportDetails } from '#lib/trivy-import.js';
  import RegistryCatalogPicker from '#lib/RegistryCatalogPicker.svelte';
  import { api, message, platforms, post, scannerName, scannerProviders, type Registry, type ScannerAvailability, type ScanRetryOptions, allRegistries } from '#lib/api.js';

  let { initialMode = 'registry', initialReference = '', initialRegistry = '', retryOptions, dismiss }:
    { initialMode?: string; initialReference?: string; initialRegistry?: string; retryOptions?: ScanRetryOptions; dismiss?: () => void } = $props();
  const uid = $props.id();
  let selectedMode = $state<string>();
  const mode = $derived(selectedMode ?? initialMode);
  const importing = $derived(mode === 'import');
  const archive = $derived(mode === 'archive');
  const discovery = $derived(['docker','swarm','kubernetes'].includes(mode));
  const showRegistry = $derived(mode === 'registry' || (discovery && mode !== 'docker'));
  const sources = [
    { id: 'registry', label: 'Registry image', hint: 'Scan a public or private image by tag or digest.' },
    { id: 'docker', label: 'Local Docker', hint: 'Choose an image from the connected Docker daemon.', find: 'Find local images' },
    { id: 'swarm', label: 'Docker Swarm', hint: 'Choose an image from a service on the connected Swarm manager.', find: 'Find service images' },
    { id: 'kubernetes', label: 'Kubernetes', hint: 'Choose an image declared by a pod in the connected cluster.', find: 'Find pod images' },
    { id: 'archive', label: 'Image archive', hint: 'Upload a Docker image archive for scanning.' },
    { id: 'import', label: 'Trivy JSON', hint: 'Add an existing Trivy report to your scan history.' }
  ];
  const source = $derived(sources.find(item => item.id === mode) ?? sources[0]);
  let registries = $state<Registry[]>([]);
  let reference = $state('');
  let referenceInput = $state<HTMLInputElement>();
  let manualRegistryReference = $state(false);
  type ImageUsage = {
    namespace: string;
    pod: string;
    workloadKind: string;
    workloadName: string;
    container: string;
    containerType: 'app' | 'init' | 'ephemeral';
  };
  type DiscoveredImage = SwarmImage & {
    label: string;
    running?: boolean | null;
    usages?: ImageUsage[];
  };
  let discovered = $state<DiscoveredImage[]>([]);
  const selectedImage = $derived(discovered.find(item => item.reference === reference));
  let lookup = $state<'idle' | 'loading' | 'ready' | 'failed'>('idle');
  let lookupError = $state('');
  let pickedImage = '';
  let namespace = $state('');
  let namespaces = $state<string[]>([]);
  let namespaceListUnavailable = $state(false);
  let query = $state('');
  let scanAll = $state(false);
  let queuedSwarmDigests = $state<string[]>([]);
  const swarmTargets = $derived.by(() => uniqueSwarmImages(discovered, registry?.host));
  const remainingSwarmTargets = $derived.by(() => {
    const queued = new Set(queuedSwarmDigests);
    return [...swarmTargets].filter(([digest]) => !queued.has(digest));
  });
  const bulkSelected = $derived(scanAll && (mode === 'docker' || mode === 'swarm'));
  let discoveryRequest: AbortController | undefined;
  let tagsRequest: AbortController | undefined;
  let archiveRequest: AbortController | undefined;
  let hubImage = $state('');
  let hubTags = $state<string[]>([]);
  let hubTagsLoading = $state(false);
  let hubTagsError = $state('');
  let archiveSuggestion = $state('');

  function resetLookup() {
    discoveryRequest?.abort();
    tagsRequest?.abort();
    hubImage = '';
    hubTags = [];
    hubTagsError = '';
    hubTagsLoading = false;
    discovered = [];
    lookup = 'idle';
    lookupError = '';
    scanAll = false;
    queuedSwarmDigests = [];
  }

  function clearPickedImage() {
    if (pickedImage && reference === pickedImage) reference = '';
    pickedImage = '';
  }

  function changeRegistry(next: string) {
    registryId = next;
    if (mode !== 'registry') return;
    clearPickedImage();
    manualRegistryReference = !!reference.trim();
    resetLookup();
    error = '';
  }

  function pickRegistryReference(image: string) {
    reference = image;
    pickedImage = image;
    error = '';
  }

  async function enterRegistryReference(suggestion: string) {
    pickRegistryReference(reference || suggestion);
    manualRegistryReference = true;
    await tick();
    referenceInput?.focus();
  }

  async function browseRegistry() {
    pickRegistryReference('');
    manualRegistryReference = false;
    await tick();
    manualRegistryButton?.focus();
  }

  let manualRegistryButton = $state<HTMLButtonElement>();

  $effect(() => {
    initialMode;
    selectedMode = undefined;
    reference = initialReference;
    registryId = initialRegistry;
    manualRegistryReference = !!initialReference.trim();
    platform = retryOptions?.platform ?? 'linux/amd64';
    scanners = retryOptions?.scanners ?? [];
    priority = retryOptions?.priority ?? 0;
  });

  $effect(() => {
    mode;
    resetLookup();
    archiveRequest?.abort();
    archiveSuggestion = '';
    pickedImage = '';
    file = undefined;
    readingReport = false;
    importReference = '';
    importPlatform = '';
    error = '';
  });

  $effect(() => {
    if (mode !== 'kubernetes') return;
    const controller = new AbortController();
    namespaces = [];
    namespaceListUnavailable = false;
    void api<string[]>('/discover/kubernetes/namespaces', {signal:controller.signal})
      .then(result => { if (!controller.signal.aborted) namespaces = result; })
      .catch(() => { if (!controller.signal.aborted) namespaceListUnavailable = true; });
    return () => controller.abort();
  });

  async function discover() {
    if (mode === 'kubernetes') clearPickedImage();
    resetLookup();
    const controller = new AbortController();
    discoveryRequest = controller;
    lookup = 'loading';
    error = '';
    try {
      const results = await api<typeof discovered>('/discover/' + (mode === 'registry' ? 'dockerhub?q=' + encodeURIComponent(query) : mode
        + (mode === 'kubernetes' && namespace.trim() ? '?namespace=' + encodeURIComponent(namespace.trim()) : '')), {signal:controller.signal});
      if (controller.signal.aborted) return;
      discovered = results;
      lookup = 'ready';
    } catch (issue) {
      if (controller.signal.aborted) return;
      lookupError = message(issue);
      lookup = 'failed';
    }
  }
  async function pickImage(value: string) {
    pickedImage = value;
    if (value) reference = value;
    if (mode !== 'registry') return;
    tagsRequest?.abort();
    hubImage = value;
    hubTags = [];
    hubTagsError = '';
    hubTagsLoading = !!value;
    if (!value) return;
    const controller = new AbortController();
    tagsRequest = controller;
    try {
      const data = await api<{tags:string[]}>('/discover/dockerhub/tags?' + new URLSearchParams({image:value}), {signal:controller.signal});
      if (!controller.signal.aborted) hubTags = data.tags;
    } catch (issue) {
      if (!controller.signal.aborted) hubTagsError = message(issue);
    } finally {
      if (!controller.signal.aborted) hubTagsLoading = false;
    }
  }

  async function readArchive(upload: File | undefined) {
    archiveRequest?.abort();
    if (archiveSuggestion && reference === archiveSuggestion) reference = '';
    archiveSuggestion = '';
    file = upload;
    if (!upload) return;
    const controller = new AbortController();
    archiveRequest = controller;
    try {
      const suggested = await archiveReference(upload, controller.signal);
      if (!controller.signal.aborted && suggested) {
        archiveSuggestion = suggested;
        if (!reference.trim()) reference = suggested;
      }
    } catch { /* Reference entry remains available if the archive does not contain a readable tag. */ }
  }
  let platform = $state('linux/amd64');
  let registryId = $state('');
  let engines = $state<ScannerAvailability>({registry:['trivy'],local:['trivy'],defaults:null});
  let scanners = $state<string[]>([]);
  let priority = $state(0);
  const enginesForImage = $derived(mode === 'docker' || archive ? engines.local : engines.registry);
  const chosenEngines = $derived(scanners.filter(scanner => enginesForImage.includes(scanner)));
  const workspaceEngines = $derived((engines.defaults ?? []).filter(scanner => enginesForImage.includes(scanner)));
  const effectiveEngines = $derived(chosenEngines.length ? chosenEngines : workspaceEngines.length ? workspaceEngines : ['trivy']);
  let file = $state<File>();
  let readingReport = $state(false);
  let importReference = $state('');
  let importPlatform = $state('');

  async function readReport(upload: File | undefined) {
    file = upload;
    error = '';
    importReference = initialReference;
    importPlatform = '';
    if (!upload) { readingReport = false; return; }
    readingReport = true;
    try {
      if (upload.size > 20 * 1024 * 1024) throw new Error('The report exceeds the 20 MB limit.');
      const details = trivyImportDetails(JSON.parse(await upload.text()));
      if (file !== upload) return;
      importReference = details.reference || initialReference;
      importPlatform = details.platform;
    } catch {
      if (file !== upload) return;
      error = upload.size > 20 * 1024 * 1024 ? 'The report exceeds the 20 MB limit.' : 'Choose a valid Trivy JSON report.';
    } finally {
      if (file === upload) readingReport = false;
    }
  }
  let busy = $state(false);
  let error = $state('');
  let registryError = $state('');
  let loadingRegistries = $state(true);
  const registry = $derived(registries.find((entry) => entry.id === registryId));
  const savedRegistryFlow = $derived(mode === 'registry' && !!registryId);
  const registryTargetPending = $derived(savedRegistryFlow && (!registry || !manualRegistryReference && !reference));

  function changeSource(next: string) {
    clearPickedImage();
    if (dismiss || retryOptions) selectedMode = next;
    else void goto(next === 'registry' ? '/scans/new' : '/scans/new?mode=' + next);
  }

  onDestroy(() => {
    discoveryRequest?.abort();
    tagsRequest?.abort();
    archiveRequest?.abort();
  });

  onMount(() => {
    void api<ScannerAvailability>('/scanners/available').then(result => {engines = result;}).catch(() => {});
    void allRegistries().then(items => { registries = items; }).catch(issue => { registryError = message(issue); })
      .finally(() => { loadingRegistries = false; });
  });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy || readingReport || registryTargetPending) return;
    busy = true;
    error = '';
    try {
      let result: { id: string };
      if (archive) {
        if (!file) throw new Error('Choose a Docker image archive.');
        if (file.size > 2 * 1024 * 1024 * 1024) throw new Error('The archive exceeds 2 GiB.');
        result = await api('/scans/archive?' + new URLSearchParams({ reference, platform, priority:String(priority), scanners:scanners.filter(scanner => enginesForImage.includes(scanner)).join(',') }), {
          method: 'POST', headers: { 'content-type': 'application/x-tar' }, body: file
        });
      } else if (importing) {
        if (!file) throw new Error('Choose a Trivy JSON report.');
        if (file.size > 20 * 1024 * 1024) throw new Error('The report exceeds the 20 MB limit.');
        const query = new URLSearchParams({ reference: importReference, platform: importPlatform });
        result = await api('/scans/import?' + query, { method: 'POST', headers: { 'content-type': 'application/json' }, body: file });
      } else if (mode === 'docker' && scanAll) {
        await api('/scans/bulk', post({ scans:
          discovered.map(item => ({ source: 'docker', reference: item.reference, platform, priority,
            scanners:scanners.filter(scanner => enginesForImage.includes(scanner)) })) }));
        dismiss?.();
        await goto('/scans/bulk');
        return;
      } else if (mode === 'swarm' && scanAll) {
        const targets = remainingSwarmTargets.map(([digest, item]) => ({
          digest,
          scan: {
            source: 'swarm', reference: item.reference, platform, priority,
            registryId: item.registryHost === registry?.host ? registryId : null,
            scanners: scanners.filter(scanner => enginesForImage.includes(scanner))
          }
        }));
        if (!targets.length) throw new Error('There are no remaining Swarm image digests to scan.');
        // Each request is atomic and the bulk endpoint accepts up to 50 scans.
        for (let offset = 0; offset < targets.length; offset += 50) {
          const batch = targets.slice(offset, offset + 50);
          await api('/scans/bulk', post({ scans: batch.map(target => target.scan) }));
          queuedSwarmDigests = [...queuedSwarmDigests, ...batch.map(target => target.digest)];
        }
        dismiss?.();
        await goto('/scans/bulk');
        return;
      } else {
        result = await api('/scans', post({ reference, platform, registryId: mode === 'docker' ? null : registryId || null,
          source: discovery ? mode : 'registry', priority, scanners: scanners.filter(scanner => enginesForImage.includes(scanner)) }));
      }
      dismiss?.();
      await goto('/scans/' + result.id);
    } catch (issue) {
      const queued = mode === 'swarm' && scanAll ? queuedSwarmDigests.length : 0;
      error = queued
        ? `${queued} Swarm image scans queued. ${remainingSwarmTargets.length ? 'Submit again to queue the remaining images. ' : ''}${message(issue)}`
        : message(issue);
    } finally {
      busy = false;
    }
  }
</script>

{#snippet imageChoices()}
  {#if lookup === 'failed'}
    <p class="notice error" role="alert">{lookupError}</p>
  {:else if lookup === 'ready' && !discovered.length}
    <p class="field-help" role="status">{mode === 'kubernetes' && namespace.trim()
      ? 'No pod images found in ' + namespace.trim() + '. Try another namespace or enter an image reference.'
      : 'No images found. You can enter an image reference manually.'}</p>
  {:else if discovered.length}
    <label class="field"><span>{mode === 'kubernetes' ? 'Pod images' : mode === 'swarm' ? 'Service images' : 'Discovered images'} ({discovered.length})</span>
      <select value={mode === 'registry' ? hubImage : discovered.some(item => item.reference === reference) ? reference : ''}
        onchange={(event) => void pickImage(event.currentTarget.value)}>
        <option value="">Choose an image</option>
        {#each discovered as item}
          <option value={item.reference}>{item.label}{item.running ? ' (running)' : ''} · {item.reference}</option>
        {/each}
      </select>
    </label>
    {#if mode === 'registry' && hubImage}
      {#if hubTagsLoading}<p class="field-help" role="status">Loading Docker Hub tags…</p>
      {:else if hubTagsError}<p class="field-help" role="status">{hubTagsError} Enter a tag in Image reference.</p>
      {:else if hubTags.length}
        {@const repository = hubImage.split(':')[0]}
        <label class="field"><span>Docker Hub tag</span>
          <select value={reference.startsWith(repository + ':') ? reference.slice(repository.length + 1) : ''}
            onchange={(event) => {
              if (event.currentTarget.value) { reference = repository + ':' + event.currentTarget.value; pickedImage = reference; }
            }}>
            <option value="">Choose a tag</option>
            {#each hubTags as tag}<option value={tag}>{tag}</option>{/each}
          </select>
        </label>
      {:else}<p class="field-help">No tags returned. You can enter an image reference.</p>{/if}
    {/if}
    {#if mode === 'kubernetes' && selectedImage?.usages?.length}
      <details class="form-disclosure">
        <summary>Pods and workloads using this image</summary>
        <ul>
          {#each selectedImage.usages as usage}
            <li>{usage.namespace}/{usage.pod} · {usage.container}{usage.containerType === 'app' ? '' : ` (${usage.containerType})`}
              {#if usage.workloadKind !== 'Pod'} · {usage.workloadKind}/{usage.workloadName}{/if}
            </li>
          {/each}
        </ul>
      </details>
    {/if}
    {#if mode === 'docker'}
      {#if discovered.every(item => item.running == null)}
        <p class="field-help">Running container status is unavailable.</p>
      {/if}
      <label class="inline-check"><input type="checkbox" bind:checked={scanAll} disabled={busy} /> Scan all discovered Docker images</label>
    {:else if mode === 'swarm'}
      {#if swarmTargets.size}
        <label class="inline-check"><input type="checkbox" bind:checked={scanAll} disabled={busy} />
          Scan all Swarm service image digests ({remainingSwarmTargets.length})
        </label>
      {/if}
      {#if discovered.some(item => !item.digest)}
        <p class="field-help">Services with tag-only image references can be scanned individually.</p>
      {/if}
    {/if}
  {/if}
{/snippet}

{#snippet referenceField()}
  <label class="field">
    <span>Image reference</span>
    <input class="mono" required={!bulkSelected} disabled={bulkSelected || busy} maxlength="1024"
      placeholder={registry ? 'team/image:version' : 'registry.example.com/team/image:version'}
      bind:this={referenceInput} bind:value={reference} oninput={() => { pickedImage = ''; }} />
    {#if savedRegistryFlow && registry}<small>Enter a repository with its tag or digest. References without a hostname use {registry.host}.</small>{/if}
  </label>
{/snippet}

{#snippet fields()}
    <fieldset class="field source-field">
      <legend>Image source</legend>
      <div class="source-options">
        {#each sources as option (option.id)}
          <label class="source-option">
            <input type="radio" name={uid + '-source'} value={option.id} checked={source.id === option.id}
              disabled={busy} onchange={() => changeSource(option.id)} />
            <span>{option.label}</span>
          </label>
        {/each}
      </div>
      <small>{source.hint}</small>
    </fieldset>
    {#if error}<div class="notice error" role="alert">{error}</div>{/if}
    {#if importing}
      <label class="field">
        <span>Trivy JSON report</span>
        <input type="file" required accept=".json,application/json" disabled={busy}
          onchange={event => void readReport(event.currentTarget.files?.[0])} />
      </label>
      {#if readingReport}<p class="field-help" role="status">Reading report details…</p>{/if}
      {#if file && !readingReport}<p class="field-help">Confirm the image reference and platform. Fill in any details the report did not provide.</p>{/if}
      <label class="field">
        <span>Image reference</span>
        <input class="mono" required maxlength="1024" placeholder="alpine:3.23" bind:value={importReference} disabled={readingReport || busy} />
      </label>
      <label class="field">
        <span id={uid + '-import-platform-label'}>Platform</span>
        <select aria-labelledby={uid + '-import-platform-label'} required bind:value={importPlatform} disabled={readingReport || busy}>
          <option value="">Choose a platform</option>
          {#each platforms as value}<option>{value}</option>{/each}
        </select>
      </label>
    {:else}
    {#if discovery}
      {#if mode === 'kubernetes'}
        <label class="field"><span id={uid + '-namespace-label'}>Namespace</span>
          <input list={uid + '-namespaces'} placeholder="All namespaces" aria-labelledby={uid + '-namespace-label'}
            aria-describedby={namespaceListUnavailable ? uid + '-namespace-help' : undefined} value={namespace} oninput={(event) => {
            clearPickedImage();
            resetLookup();
            namespace = event.currentTarget.value;
          }} />
          {#if namespaceListUnavailable}<small id={uid + '-namespace-help'}>Namespace suggestions are unavailable. You can type a namespace you have access to.</small>{/if}
        </label>
        <datalist id={uid + '-namespaces'}>{#each namespaces as name}<option value={name}></option>{/each}</datalist>
      {/if}
      <div class="inline-input">
        <button type="button" class="button secondary" onclick={discover} disabled={busy || lookup === 'loading'}>{lookup === 'loading' ? 'Finding images…' : source.find}</button>
      </div>
      {@render imageChoices()}
    {/if}
    <div class="form-grid" class:single-field={!showRegistry}>
      {#if showRegistry}
        <label class="field"><span>Registry connection</span>
          <select value={registryId} disabled={loadingRegistries || busy} onchange={(event) => changeRegistry(event.currentTarget.value)}>
            <option value="">Public or anonymous registry</option>
            {#if registryId && !registry}
              <option value={registryId} disabled>{loadingRegistries ? 'Loading registry connection…' : 'Registry connection unavailable'}</option>
            {/if}
            {#each registries as item (item.id)}<option value={item.id}>{item.name} · {item.host}</option>{/each}
          </select>
        </label>
      {/if}
      <label class="field">
        <span>Platform</span>
        <select bind:value={platform}>{#each platforms as value}<option>{value}</option>{/each}</select>
      </label>
    </div>
    {#if showRegistry}
      {#if registryError}<div class="notice error" role="alert">{registryError}</div>{/if}
      {#if !loadingRegistries && !registries.length && !registryError}
        <p class="field-help"><a href="/registries">Add a registry connection</a> for images that require authentication.</p>
      {/if}
    {/if}
    {#if savedRegistryFlow}
      {#if registry && manualRegistryReference}
        {@render referenceField()}
        <div><button type="button" class="button secondary" disabled={busy} onclick={browseRegistry}>Browse repositories</button></div>
      {:else if registry}
        {#key registry.id}
          <RegistryCatalogPicker {registry} {busy} bind:manualButton={manualRegistryButton}
            select={pickRegistryReference} enterReference={enterRegistryReference} />
        {/key}
      {:else if !loadingRegistries && !registryError}
        <p class="field-help">Choose an available registry connection.</p>
      {/if}
    {:else if mode === 'registry'}
      {@render referenceField()}
      <details class="form-disclosure">
        <summary>Search Docker Hub</summary>
        <div class="disclosure-body">
          <div class="inline-input">
            <input aria-label="Docker Hub search" placeholder="Find images on Docker Hub" bind:value={query} />
            <button type="button" class="button secondary" onclick={discover} disabled={lookup === 'loading' || query.trim().length < 2}>{lookup === 'loading' ? 'Searching…' : 'Search Docker Hub'}</button>
          </div>
          {@render imageChoices()}
        </div>
      </details>
    {:else}
      {@render referenceField()}
    {/if}
    {#if archive}
      <label class="field">
        <span>Docker image archive</span>
        <input type="file" required accept=".tar,.tar.gz,.tgz" onchange={(event) => void readArchive(event.currentTarget.files?.[0])} />
        {#if archiveSuggestion && reference === archiveSuggestion}<small>Image reference suggested from the archive.</small>{/if}
      </label>
    {/if}
      <details class="form-disclosure" open={!!retryOptions}>
        <summary>Scan options</summary>
        <div class="disclosure-body">
      {#if enginesForImage.length > 1}
        <fieldset class="field"><legend>Scanners</legend><p class="field-help">Leave unchecked to use the <a href="/settings" target="_blank" rel="noopener">workspace defaults (new tab)</a>.</p>
        <div class="filters">{#each scannerProviders.filter(provider => enginesForImage.includes(provider.id)) as provider (provider.id)}
          <label class="inline-check"><input type="checkbox" value={provider.id} bind:group={scanners} />{provider.name}</label>
        {/each}</div>
        </fieldset>
      {/if}
      {#if scanners.length > chosenEngines.length}<p class="field-help">Some previously selected engines are unavailable for this source.</p>{/if}
      <label class="field"><span>Queue priority</span><input type="number" min="-10" max="10" bind:value={priority} /></label>
        </div>
      </details>
      <p class="field-help">{chosenEngines.length ? 'Selected scanners' : 'Effective workspace defaults'} · {effectiveEngines.map(scannerName).join(', ')}</p>
    {/if}
{/snippet}

{#snippet actions()}
  {#if dismiss}
    <button type="button" class="button secondary" disabled={busy} onclick={dismiss}>Cancel</button>
  {:else}
    <a class="button secondary" href="/">Cancel</a>
  {/if}
  <button type="submit" class="button primary" disabled={busy || readingReport || registryTargetPending || (mode === 'swarm' && scanAll && !remainingSwarmTargets.length)}>{busy ? 'Submitting…' : importing ? 'Import report' : bulkSelected ? 'Start scans' : 'Start scan'}</button>
{/snippet}

{#if dismiss}
  <ConfigDialog id="start-scan" title="Start scan" open {busy} {dismiss} onsubmit={submit} {actions}>
    {@render fields()}
  </ConfigDialog>
{:else}
  <section class="panel scan-setup" aria-labelledby={uid + '-title'}>
    <div class="panel-title"><h2 id={uid + '-title'}>{importing ? 'Report details' : 'Source and scan options'}</h2></div>
    <form class="form-panel wide" onsubmit={submit}>
      {@render fields()}
      <div class="actions">{@render actions()}</div>
    </form>
  </section>
{/if}

<style>
  .scan-setup { width: min(100%, 62rem); }
  .form-grid.single-field { grid-template-columns: minmax(0, 1fr); }
  fieldset.source-field { border: 0; padding: 0; min-width: 0; }
  .source-field legend { padding: 0; margin-bottom: .45rem; }
  .source-options { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: .35rem; }
  .source-option { position: relative; }
  .source-option input { position: absolute; width: 1px; height: 1px; min-height: 0; opacity: 0; }
  .source-option span {
    display: grid; align-content: center; min-height: 2.6rem; padding: .35rem .55rem;
    border: 1px solid var(--control-line); border-radius: var(--radius);
    font-size: .81rem; text-align: center; cursor: pointer;
  }
  .source-option:hover span { background: var(--inset); }
  .source-option input:checked + span {
    color: var(--accent-ink); background: var(--accent-soft); border-color: var(--accent-ink);
  }
  .source-option input:focus-visible + span { outline: 2px solid var(--focus); outline-offset: 2px; }
  @media (max-width: 480px) {
    .source-options { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }
</style>
