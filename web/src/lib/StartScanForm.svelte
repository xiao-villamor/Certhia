<script lang="ts">
  import { goto } from '$app/navigation';
  import ConfigDialog from '#lib/ConfigDialog.svelte';
  import { onMount, onDestroy } from 'svelte';
  import RegistryCatalogPicker from '#lib/RegistryCatalogPicker.svelte';
  import { api, message, platforms, post, scannerProviders, type Registry, type ScannerAvailability, allRegistries } from '#lib/api.js';

  let { initialMode = 'registry', initialReference = '', initialRegistry = '', dismiss }:
    { initialMode?: string; initialReference?: string; initialRegistry?: string; dismiss?: () => void } = $props();
  const uid = $props.id();
  let selectedMode = $state<string>();
  const mode = $derived(selectedMode ?? initialMode);
  const importing = $derived(mode === 'import');
  const archive = $derived(mode === 'archive');
  const discovery = $derived(['docker','swarm','kubernetes'].includes(mode));
  const showRegistry = $derived(mode === 'registry' || (discovery && mode !== 'docker'));
  const sources = [
    { id: 'registry', label: 'Registry image', hint: 'Scan a public or private image by tag or digest.' },
    { id: 'docker', label: 'Local Docker', hint: 'Choose images available on the connected Docker daemon.' },
    { id: 'swarm', label: 'Docker Swarm', hint: 'Find images running as Swarm services.' },
    { id: 'kubernetes', label: 'Kubernetes', hint: 'Find images from pods in the connected cluster.' },
    { id: 'archive', label: 'Image archive', hint: 'Upload a Docker image archive for scanning.' },
    { id: 'import', label: 'Trivy JSON', hint: 'Add an existing Trivy report to your scan history.' }
  ];
  const source = $derived(sources.find(item => item.id === mode) ?? sources[0]);
  let registries = $state<Registry[]>([]);
  let reference = $state('');
  let discovered = $state<{reference: string; label: string;}[]>([]);
  let discovering = $state(false);
  let namespace = $state('');
  let namespaces = $state<string[]>([]);
  let query = $state('');
  let scanAll = $state(false);
  let discoveryRequest: AbortController | undefined;

  $effect(() => {
    initialMode;
    selectedMode = undefined;
    reference = initialReference;
    registryId = initialRegistry;
  });

  $effect(() => {
    mode;
    discovered = [];
    discoveryRequest?.abort();
    discovering = false;
    scanAll = false;
    file = undefined;
    error = '';
  });

  $effect(() => {
    if (mode !== 'kubernetes') return;
    const controller = new AbortController();
    void api<string[]>('/discover/kubernetes/namespaces', {signal:controller.signal})
      .then(result => {namespaces = result;}).catch(() => {});
    return () => controller.abort();
  });

  async function discover() {
    const controller = new AbortController();
    discoveryRequest?.abort();
    discoveryRequest = controller;
    discovering = true;
    error = '';
    try {
      discovered = await api('/discover/' + (mode === 'registry' ? 'dockerhub?q=' + encodeURIComponent(query) : mode
        + (mode === 'kubernetes' && namespace ? '?namespace=' + encodeURIComponent(namespace) : '')), {signal:controller.signal});
      if (!discovered.length) error = 'No images were found.';
    } catch (issue) { if (!controller.signal.aborted) error = message(issue); }
    finally { if (!controller.signal.aborted) discovering = false; }
  }
  let platform = $state('linux/amd64');
  let registryId = $state('');
  let engines = $state<ScannerAvailability>({registry:['trivy'],local:['trivy'],defaults:null});
  let scanners = $state<string[]>([]);
  let priority = $state(0);
  const enginesForImage = $derived(mode === 'docker' || archive ? engines.local : engines.registry);
  let file = $state<File>();
  let busy = $state(false);
  let error = $state('');
  let registryError = $state('');
  const registry = $derived(registries.find((entry) => entry.id === registryId));

  function changeSource(next: string) {
    if (dismiss) selectedMode = next;
    else void goto(next === 'registry' ? '/scans/new' : '/scans/new?mode=' + next);
  }

  onDestroy(() => discoveryRequest?.abort());

  onMount(() => {
    void api<ScannerAvailability>('/scanners/available').then(result => {engines = result;}).catch(() => {});
    void allRegistries().then(items => { registries = items; }).catch(issue => { registryError = message(issue); });
  });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
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
        const query = new URLSearchParams({ reference, platform });
        result = await api('/scans/import?' + query, { method: 'POST', headers: { 'content-type': 'application/json' }, body: file });
      } else if (mode === 'docker' && scanAll) {
        await api('/scans/bulk', post({ scans:
          discovered.map(item => ({ source: 'docker', reference: item.reference, platform, priority,
            scanners:scanners.filter(scanner => enginesForImage.includes(scanner)) })) }));
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
      error = message(issue);
    } finally {
      busy = false;
    }
  }
</script>

{#snippet fields()}
    <fieldset class="field source-field">
      <legend>Image source</legend>
      <div class="source-options">
        {#each sources as option (option.id)}
          <label class="source-option">
            <input type="radio" name={uid + '-source'} value={option.id} checked={source.id === option.id}
              onchange={() => changeSource(option.id)} />
            <span>{option.label}</span>
          </label>
        {/each}
      </div>
      <small>{source.hint}</small>
    </fieldset>
    {#if error}<div class="notice error" role="alert">{error}</div>{/if}
    <label class="field">
      <span>Image reference {#if registry}<small>{registry.host}</small>{/if}</span>
      <input class="mono" required={!(mode === 'docker' && scanAll)} maxlength="1024" placeholder={registry ? 'team/image:version' : 'registry.example.com/team/image:version'} bind:value={reference} />
    </label>
    <div class="form-grid" class:single-field={!showRegistry}>
      <label class="field">
        <span>Platform</span>
        <select bind:value={platform}>{#each platforms as value}<option>{value}</option>{/each}</select>
      </label>
      {#if showRegistry}
        <label class="field"><span>Registry connection</span>
          <select bind:value={registryId} onchange={() => {discoveryRequest?.abort(); discovering = false; discovered = [];}}>
            <option value="">Public or anonymous registry</option>
            {#each registries as item (item.id)}<option value={item.id}>{item.name} · {item.host}</option>{/each}
          </select>
        </label>
      {/if}
    </div>
    {#if showRegistry}
      {#if registryError}<div class="notice error" role="alert">{registryError}</div>{/if}
      {#if !registries.length && !registryError}
        <p class="field-help"><a href="/registries">Add a registry connection</a> for images that require authentication.</p>
      {/if}
    {/if}
    {#if mode === 'registry' && registry}
      {#key registry.id}<RegistryCatalogPicker {registry} select={(image) => {reference = image;}} />{/key}
    {:else if mode === 'registry'}
      <details class="form-disclosure">
        <summary>Search Docker Hub</summary>
        <div class="disclosure-body">
          <div class="inline-input">
            <input aria-label="Docker Hub search" placeholder="Find images on Docker Hub" bind:value={query} />
            <button type="button" class="button secondary" onclick={discover} disabled={discovering || query.trim().length < 2}>Search Docker Hub</button>
          </div>
        </div>
      </details>
    {/if}
    {#if discovery || mode === 'registry'}
      {#if discovery}
      <div class="inline-input">
        {#if mode === 'kubernetes'}<input aria-label="Namespace" list={uid + '-namespaces'} placeholder="All namespaces" bind:value={namespace} />
        <datalist id={uid + '-namespaces'}>{#each namespaces as name}<option value={name}></option>{/each}</datalist>{/if}
        <button type="button" class="button secondary" onclick={discover} disabled={discovering}>{discovering ? 'Discovering…' : 'Discover images'}</button>
      </div>
      {/if}
      {#if discovered.length}
        <label class="field"><span>Discovered images</span>
          <select aria-label="Discovered images" onchange={(event) => {reference = event.currentTarget.value;}}>
            <option value="">Select image</option>
            {#each discovered as item}<option value={item.reference}>{item.label} · {item.reference}</option>{/each}
          </select>
        </label>
        {#if mode === 'docker'}<label class="inline-check"><input type="checkbox" bind:checked={scanAll} /> Scan all discovered Docker images</label>{/if}
      {/if}
    {/if}
    {#if importing || archive}
      <label class="field">
        <span>{importing ? 'Trivy JSON report' : 'Docker image archive'}</span>
        <input type="file" required accept={importing ? '.json,application/json' : '.tar,.tar.gz,.tgz'} onchange={(event) => { file = event.currentTarget.files?.[0]; }} />
      </label>
    {/if}
    {#if !importing}
      <details class="form-disclosure">
        <summary>Scan options</summary>
        <div class="disclosure-body">
      {#if enginesForImage.length > 1}
        <fieldset class="field"><legend>Scanners</legend><p class="field-help">Leave unchecked to use the <a href="/settings">workspace defaults</a>.</p>
        <div class="filters">{#each scannerProviders.filter(provider => enginesForImage.includes(provider.id)) as provider (provider.id)}
          <label class="inline-check"><input type="checkbox" value={provider.id} bind:group={scanners} />{provider.name}</label>
        {/each}</div>
        </fieldset>
      {/if}
      <label class="field"><span>Queue priority</span><input type="number" min="-10" max="10" bind:value={priority} /></label>
        </div>
      </details>
    {/if}
{/snippet}

{#snippet actions()}
  {#if dismiss}
    <button type="button" class="button secondary" disabled={busy} onclick={dismiss}>Cancel</button>
  {:else}
    <a class="button secondary" href="/">Cancel</a>
  {/if}
  <button type="submit" class="button primary" disabled={busy}>{busy ? 'Submitting…' : importing ? 'Import report' : 'Start scan'}</button>
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
