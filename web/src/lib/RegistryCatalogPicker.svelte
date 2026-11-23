<script lang="ts">
  import { auth } from '#lib/auth.svelte.js';
  import { api, message, post, type Registry } from '#lib/api.js';

  interface Catalog { nextCursor: string | null; images: string[]; refreshedAt: string | null; error: string | null; }
  let { registry, busy, select, enterReference, manualButton = $bindable() }:
    {registry: Registry; busy: boolean; select: (reference: string) => void; enterReference: (suggestion: string) => void; manualButton?: HTMLButtonElement} = $props();
  let catalog = $state<Catalog>();
  let filter = $state('');
  let repository = $state('');
  let tag = $state('');
  let tags = $state<string[]>([]);
  let loading = $state(true);
  let loadingTags = $state(false);
  let catalogIssue = $state('');
  let tagsIssue = $state('');
  let request: AbortController | undefined;
  const visible = $derived(catalog?.images ?? []);
  const selectedRepository = $derived(repository ? registry.host + '/' + repository : '');

  async function load(id: string, refresh = false, cursor?: string) {
    request?.abort();
    const controller = new AbortController();
    request = controller;
    loading = true;
    catalogIssue = '';
    const params = new URLSearchParams({search:filter.trim()});
    if (cursor) params.set('cursor',cursor);
    const path = '/registries/' + id + '/catalog?' + params;
    try {
      let data = await api<Catalog>(path, {signal:controller.signal, ...(refresh ? post({}) : {})});
      if (auth.admin && !refresh && !data.refreshedAt && !data.error) {
        data = await api<Catalog>(path, {signal:controller.signal, ...post({})});
      }
      if (!controller.signal.aborted) catalog = cursor && catalog ? {...data,images:[...catalog.images,...data.images]} : data;
    } catch (error) {
      if (!controller.signal.aborted) catalogIssue = message(error);
    } finally {
      if (!controller.signal.aborted) loading = false;
    }
  }

  $effect(() => {
    void load(registry.id);
    return () => request?.abort();
  });

  $effect(() => {
    const image = selectedRepository;
    const id = registry.id;
    tag = ''; tags = []; tagsIssue = ''; loadingTags = !!image;
    if (!image) return;
    const abort = new AbortController();
    void api<{tags:string[]}>('/registries/' + id + '/tags?' + new URLSearchParams({image}), {signal:abort.signal})
      .then(result => {if (!abort.signal.aborted) tags = [...new Set(result.tags)];})
      .catch(error => {if (!abort.signal.aborted) tagsIssue = message(error);})
      .finally(() => {if (!abort.signal.aborted) loadingTags = false;});
    return () => abort.abort();
  });
</script>

<div class="registry-picker">
  <div class="filters picker-header">
    <strong>Choose an image</strong>
    <div class="filters">
      {#if auth.admin}<button type="button" class="button secondary" onclick={() => load(registry.id, true)} disabled={loading || busy}>Refresh catalog</button>{/if}
      <button type="button" class="button secondary" disabled={busy} bind:this={manualButton} onclick={() => enterReference(selectedRepository)}>Enter image tag or digest</button>
    </div>
  </div>
  {#if loading && !catalog}
    <p class="field-help" role="status">Loading registry catalog…</p>
  {:else if catalog?.refreshedAt}
    {#if visible.length || filter}
      <label class="field"><span>Filter repositories</span>
        <input bind:value={filter} placeholder="Search by repository path" disabled={busy}
          onkeydown={(event) => { if (event.key === 'Enter') event.preventDefault(); }} />
      </label>
    {/if}
    <div class="form-grid">
      <label class="field"><span>Repository</span>
        <select value={repository} disabled={busy || (!visible.length && !repository)} onchange={(event) => {
          repository = event.currentTarget.value;
          select('');
        }}>
          <option value="">Choose a repository</option>
          {#if repository && !visible.includes(repository)}<option value={repository}>{repository}</option>{/if}
          {#each visible as image (image)}<option value={image}>{image}</option>{/each}
        </select>
        {#if !loading && !visible.length && !catalog.error && !catalogIssue}
          <small>{filter.trim() ? 'No repositories match this filter.' : 'No repositories are listed for this connection.'}</small>
        {/if}
      </label>
      <label class="field"><span>Tag</span>
        <select value={tag} disabled={busy || loadingTags || !tags.length} onchange={(event) => {
          tag = event.currentTarget.value;
          select(tag ? selectedRepository + ':' + tag : '');
        }}>
          <option value="">{!repository ? 'Choose a repository first' : loadingTags ? 'Loading tags…' : 'Choose a tag'}</option>
          {#each tags as value (value)}<option value={value}>{value}</option>{/each}
        </select>
        {#if repository && !loadingTags && !tags.length && !tagsIssue}<small>No tags were listed for this repository.</small>{/if}
      </label>
    </div>
    {#if catalog.nextCursor}<button type="button" class="button secondary" disabled={loading} onclick={() => load(registry.id, false, catalog?.nextCursor ?? undefined)}>Load more repositories</button>{/if}
  {:else if !catalogIssue && !catalog?.error}
    <p class="field-help">No repositories are listed for this connection.</p>
  {/if}
  {#if catalogIssue || catalog?.error || tagsIssue}
    <div class="notice warning" role="status">{catalogIssue || catalog?.error || tagsIssue}</div>
  {/if}
</div>

<style>
  .registry-picker { display: grid; gap: .7rem; padding: .9rem; background: var(--inset); border-radius: var(--radius); }
  .picker-header { justify-content: space-between; }
</style>
