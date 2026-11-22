<script lang="ts">
  import { auth } from '#lib/auth.svelte.js';
  import { productName } from '#lib/product.js';
  import { onMount } from 'svelte';
  import { Database, KeyRound, Pencil, Plus, RefreshCw, ScanLine, Trash2, Webhook } from '@lucide/svelte';
  import ConfigDialog from '#lib/ConfigDialog.svelte';
  import RegistryWebhook from '#lib/RegistryWebhook.svelte';
  import { api, message, post, registryPage, type Registry } from '#lib/api.js';

  let registries = $state<Registry[]>([]);
  let cursor = $state<string | null>(null);
  let paging = $state(false);
  let loading = $state(true);
  let opened = $state(false);
  let advanced = $state(false);
  let savedCredentials = $state(false);
  let webhookRegistry = $state<Registry>();
  const providers = [
    ['oci','Generic OCI',''],['dockerhub','Docker Hub','docker.io'],['ghcr','GitHub Container Registry','ghcr.io'],
    ['gitlab','GitLab','registry.gitlab.com'],['gar','Google Artifact Registry','us-docker.pkg.dev'],['ecr','Amazon ECR',''],
    ['acr','Azure Container Registry',''],['harbor','Harbor',''],['nexus','Sonatype Nexus',''],['artifactory','JFrog Artifactory',''],
    ['forgejo','Forgejo',''],['gitea','Gitea',''],['quay','Quay','quay.io'],
  ];
  const initial = { name:'', host:'', username:'', password:'', reference:'', provider:'oci', authHost:'', autoSync:false, clearCredentials:false, protocol:'https', skipTls:false, namespace:'' };
  let form = $state({...initial});
  let editing = $state('');
  let workload = $state(false);
  const cloudProvider = $derived(form.provider === 'ecr' || form.provider === 'acr');
  const workloadMarker = '_workload_identity';
  interface Catalog {nextCursor:string|null; images:string[]; refreshedAt:string|null; error:string|null;}
  let catalog = $state<Catalog>();
  let browser = $state<Registry>();
  let imageFilter = $state('');
  let selectedImage = $state('');
  let tags = $state<string[]>([]);
  let tag = $state('');
  let browseBusy = $state(false);
  let catalogIssue = $state('');
  let imageIssue = $state('');
  let repository = $state('');
  let exactReference = $state('');
  let manifestResult = $state('');
  let manifestBusy = $state(false);
  let tagRequest = 0;
  const visible = $derived(catalog?.images ?? []);
  function edit(registry?: Registry) {
    editing = registry?.id || '';
    form = registry ? {...initial, name:registry.name, host:registry.host, provider:registry.provider, authHost:registry.authHost || '', autoSync:registry.autoSync, protocol:registry.protocol, skipTls:registry.skipTls, namespace:registry.namespace || ''} : {...initial};
    advanced = !!(form.authHost || form.autoSync || form.skipTls || form.protocol !== 'https');
    savedCredentials = registry?.authenticated ?? false;
    workload = false;
    opened = true;
    issue = ''; feedback = '';
  }
  async function browse(registry: Registry, refreshCatalog = false, cursor?: string) {
    if (browser?.id !== registry.id) {
      browser = registry; catalog = undefined; tags = []; imageFilter = ''; selectedImage = ''; tag = '';
      repository = ''; exactReference = ''; manifestResult = ''; imageIssue = ''; tagRequest++;
    }
    browseBusy = true; catalogIssue = '';
    try {
      const params = new URLSearchParams({search:imageFilter.trim()});
      if (cursor) params.set('cursor',cursor);
      const data = await api<Catalog>('/registries/' + registry.id + '/catalog?' + params, refreshCatalog ? post({}) : undefined);
      if (browser?.id === registry.id) catalog = cursor && catalog ? {...data,images:[...catalog.images,...data.images]} : data;
    }
    catch (error) { catalogIssue = message(error); }
    finally { browseBusy = false; }
  }
  async function choose(image: string) {
    if (!browser) return;
    const request = ++tagRequest;
    selectedImage = image.trim(); tag = ''; tags = []; imageIssue = '';
    if (!selectedImage) return;
    try {
      const result = await api<{tags:string[]}>('/registries/' + browser.id + '/tags?' + new URLSearchParams({image:selectedImage}));
      if (request !== tagRequest) return;
      tags = result.tags;
      tag = tags.includes('latest') ? 'latest' : tags[0] || '';
    } catch (error) {
      if (request === tagRequest) imageIssue = message(error);
    }
  }

  async function testManifest() {
    if (!browser || manifestBusy) return;
    const registry = browser.id;
    manifestBusy = true;
    manifestResult = '';
    try {
      const result = await api<{reference:string}>('/registries/' + registry + '/test', post({reference:exactReference.trim()}));
      if (browser?.id === registry) manifestResult = 'Manifest access verified for ' + result.reference + '.';
    } catch (error) {
      if (browser?.id === registry) manifestResult = message(error);
    } finally {
      manifestBusy = false;
    }
  }

  let busy = $state<'test' | 'save' | string>('');
  let issue = $state('');
  let feedback = $state('');

  async function refresh(append = false) {
    paging = true;
    try {
      const page = await registryPage(append ? cursor ?? undefined : undefined);
      registries = append ? [...registries, ...page.items] : page.items;
      cursor = page.next;
    } catch (error) {
      issue = message(error);
    } finally {
      loading = false;
      paging = false;
    }
  }

  onMount(() => { void refresh(); });

  function setReference(value: string) {
    form.reference = value;
    const host = value.trim().replace(/^https?:\/\//, '').split('/')[0];
    if (!form.host && value.includes('/') && (host === 'localhost' || host.includes('.') || host.includes(':'))) {
      form.host = host;
    }
  }

  function setProvider(provider: string) {
    const previousHost = providers.find(item => item[0] === form.provider)?.[2];
    if (!editing && (!form.host || form.host === previousHost)) {
      form.host = providers.find(item => item[0] === provider)?.[2] ?? '';
    }
    if (provider === 'gar' && !form.username && !savedCredentials) form.username = '_json_key';
    if (provider !== 'gar' && form.username === '_json_key' && !form.password) form.username = '';
    if (form.provider !== provider) workload = false;
    form.provider = provider;
  }

  function dismiss() {
    opened = false;
    issue = ''; feedback = '';
    form = {...initial};
  }

  async function submit(step: 'test' | 'save') {
    if (busy) return;
    busy = step;
    issue = '';
    feedback = '';
    try {
      if (step === 'test') {
        const saved = editing && !form.username && !form.password && !form.clearCredentials;
        const endpoint = saved ? '/registries/' + editing + '/test' : '/registries/test';
        const reference = form.reference.trim().replace(/^http:\/\//, '');
        const result = await api<{ reference: string }>(endpoint, post({...form, reference,
          ...(form.clearCredentials ? {username:'', password:''} : {})}));
        feedback = 'Manifest access verified for ' + result.reference + '.';
      } else {
        const data = workload ? {...form, username:workloadMarker, password:workloadMarker,
          protocol:'https', skipTls:false, authHost:'', clearCredentials:false} : form;
        if (editing) await api('/registries/' + editing, {...post(data),method:'PUT'});
        else await api('/registries', post(data));
        feedback = form.name + ' was saved.';
        form = {...initial};
        opened = false;
        await refresh();
      }
    } catch (error) {
      issue = message(error);
    } finally {
      busy = '';
    }
  }

  async function remove(registry: Registry) {
    if (busy || !window.confirm('Remove the saved connection for ' + registry.name + '?')) return;
    busy = registry.id;
    issue = '';
    feedback = '';
    try {
      await api('/registries/' + registry.id, { method: 'DELETE' });
      if (browser?.id === registry.id) browser = undefined;
      await refresh();
      feedback = registry.name + ' was removed.';
    } catch (error) {
      issue = message(error);
    } finally {
      busy = '';
    }
  }
</script>

<svelte:head><title>Registry connections · {productName}</title></svelte:head>

<div class="page-heading">
  <div><h1>Registry connections</h1><p>Save pull credentials for private image scans.</p></div>
  {#if auth.admin}<button class="button primary" onclick={() => edit()} aria-haspopup="dialog" disabled={!!busy}><Plus size={18} /> Add registry</button>{/if}
</div>

{#if !opened && issue}<div class="notice error" role="alert">{issue}</div>{/if}
{#if !opened && feedback}<div class="notice success" role="status">{feedback}</div>{/if}

<ConfigDialog id="registry-editor" title={editing ? 'Edit registry' : 'Add registry'} open={opened} busy={!!busy} {dismiss}
  description="Use a registry account or token with pull access for private images."
  onsubmit={(event) => {event.preventDefault(); void submit('save');}}>
    <div class="form-grid">
      <label class="field"><span>Provider</span><select value={form.provider} onchange={(event) => setProvider(event.currentTarget.value)}>
        {#each providers as [value,label]}<option {value}>{label}</option>{/each}
      </select></label>
      <label class="field"><span>Connection name</span><input required bind:value={form.name} maxlength="100" placeholder="Private registry" /></label>
    </div>
    <label class="field"><span>Registry host</span><input class="mono" required readonly={!!editing} bind:value={form.host} placeholder="registry.example.com" maxlength="259" /></label>
    {#if ['dockerhub','ghcr','gitlab','gar','nexus','gitea','forgejo'].includes(form.provider)}
      <label class="field"><span>{form.provider === 'gar' ? 'Project/repository' : form.provider === 'nexus' ? 'Nexus repository' : 'Namespace or organization'} <small>Optional</small></span>
        <input bind:value={form.namespace} maxlength="170" placeholder={form.provider === 'gar' ? 'project-id/repository' : form.provider === 'nexus' ? 'docker-hosted' : 'example-team'} /></label>
    {/if}
    {#if form.provider === 'ghcr'}
      <p class="field-help">For private packages, use your GitHub username and a classic token with read:packages and access to the package. Authorize the token for organization SSO if required. Catalog access, tag listing, and exact image access are checked separately.</p>
    {:else if form.provider === 'forgejo'}
      <p class="field-help">Use the Forgejo instance host, your username, and an access token with read:package. Enter the package owner for catalog browsing.</p>
    {/if}
    {#if cloudProvider}
      <label class="inline-check"><input type="checkbox" bind:checked={workload} /> Use server workload identity</label>
      <p class="field-help">
        {#if form.provider === 'ecr'}Use an ECS task role or EKS Pod Identity with ECR authorization and repository pull permissions. Use the private ECR login host. A manually supplied AWS login password expires after 12 hours.
        {:else}Configure Azure Workload Identity for the Certhia server with ACR repository read permissions. Use the registry’s azurecr.io login host.{/if}
        {#if workload}Save the connection before testing it. Tokens renew automatically.{/if}
      </p>
    {/if}
    {#if !workload}
    <div class="form-grid">
      <label class="field"><span>Username</span><input disabled={form.clearCredentials} bind:value={form.username} autocomplete="username" maxlength="512" /></label>
      <label class="field"><span>{form.provider === 'gar' ? 'Service account JSON or access token' : 'Password or token'}</span>
      {#if form.provider === 'gar' && form.username.startsWith('_json_key')}<textarea disabled={form.clearCredentials} bind:value={form.password} maxlength="8192"></textarea>
      {:else}<input type="password" disabled={form.clearCredentials} bind:value={form.password} autocomplete="new-password" maxlength="8192" placeholder={savedCredentials ? 'Credentials saved' : ''} />{/if}</label>
    </div>
    {#if savedCredentials}<label class="inline-check"><input type="checkbox" bind:checked={form.clearCredentials} /> Remove saved credentials</label>{/if}
    {/if}
    <details class="form-disclosure" bind:open={advanced}>
      <summary>Connection options</summary>
      <div class="disclosure-body">
        {#if !workload}
        <div class="form-grid">
          <label class="field"><span>Connection protocol</span><select bind:value={form.protocol}><option value="https">HTTPS</option><option value="http">HTTP</option></select></label>
          <label class="field"><span>Separate token host <small>Optional</small></span><input bind:value={form.authHost} placeholder="auth.example.com" /></label>
        </div>
        {#if form.protocol === 'https'}<label class="inline-check"><input type="checkbox" bind:checked={form.skipTls} /> Skip TLS certificate verification</label>{/if}
        {/if}
        <label class="inline-check"><input type="checkbox" bind:checked={form.autoSync} /> Refresh the catalog automatically</label>
      </div>
    </details>
    <label class="field">
      <span>Image to test <small>Optional</small></span>
      <input class="mono" value={form.reference} oninput={(event) => setReference(event.currentTarget.value)} placeholder="registry.example.com/team/image:version" />
    </label>
    {#if issue}<div class="notice error" role="alert">{issue}</div>{/if}
    {#if feedback}<div class="notice success" role="status">{feedback}</div>{/if}
    {#snippet actions()}
      <button type="button" class="button secondary" disabled={!!busy} onclick={dismiss}>Cancel</button>
      <button type="button" class="button secondary" disabled={!!busy || workload || !form.reference.trim() || !form.host.trim()} onclick={() => submit('test')}><KeyRound size={16} /> {busy === 'test' ? 'Testing…' : 'Test image access'}</button>
      <button type="submit" value="save" class="button primary" disabled={!!busy || !form.name.trim()}>{busy === 'save' ? 'Saving…' : 'Save registry'}</button>
    {/snippet}
</ConfigDialog>

<RegistryWebhook registry={webhookRegistry} dismiss={() => {webhookRegistry = undefined;}} />

<section class="panel" aria-labelledby="registries-title">
  <div class="panel-title"><div><h2 id="registries-title">Saved connections</h2></div></div>
  {#if loading}
    <div class="empty" aria-live="polite">Loading registries…</div>
  {:else if !registries.length}
    <div class="empty">
      <span class="empty-icon"><Database size={26} strokeWidth={1.5} /></span>
      <h3>No saved registries</h3>
      <p>Add a connection to scan a private image by its tag or digest.</p>
      {#if auth.admin}<button class="button secondary" onclick={() => edit()} aria-haspopup="dialog" disabled={!!busy}><Plus size={16} aria-hidden="true" /> Add registry</button>{/if}
    </div>
  {:else}
    <div class="table-wrap">
      <table>
        <thead><tr><th>Connection</th><th>Provider</th><th>Access</th><th>Actions</th></tr></thead>
        <tbody>
          {#each registries as registry (registry.id)}
            <tr>
              <td><strong>{registry.name}</strong><small class="mono">{registry.host}</small></td>
              <td>{providers.find(item => item[0] === registry.provider)?.[1] || 'Generic OCI'}</td>
              <td><span class="badge neutral">{registry.authenticated ? 'Credentials saved' : 'Anonymous'}</span></td>
              <td><div class="filters">
                <a class="button secondary" href={'/scans/new?' + new URLSearchParams({registry:registry.id})}><ScanLine size={16} /> Scan image</a>
                <button class="button secondary" onclick={() => browse(registry)}>Browse</button>
                {#if auth.admin}<button class="button secondary" aria-haspopup="dialog" onclick={() => edit(registry)}><Pencil size={16} /> Edit</button>
                <button class="button secondary" aria-haspopup="dialog" onclick={() => {webhookRegistry = registry;}}><Webhook size={16} /> Webhook</button>
                <button class="icon-button" aria-label={'Remove ' + registry.name} title={'Remove ' + registry.name} disabled={!!busy} onclick={() => remove(registry)}><Trash2 size={17} /></button>{/if}
                </div></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if cursor}<button class="button secondary" disabled={paging} onclick={() => refresh(true)}>Load more connections</button>{/if}
  {/if}
</section>

{#if browser}
<section class="panel">
  <div class="panel-title"><div><h2>{browser.name} catalog</h2>
    {#if catalog?.refreshedAt}<p>Refreshed {new Date(catalog.refreshedAt).toLocaleString()}</p>{/if}
  </div>{#if auth.admin}<button class="button secondary" disabled={browseBusy} onclick={() => browser && browse(browser, true)}><RefreshCw size={17} /> {browseBusy ? 'Refreshing…' : 'Refresh catalog'}</button>{/if}</div>
  <div class="form-panel">
    {#if catalog?.error || catalogIssue}<div class="notice warning" role="status">{catalogIssue || catalog?.error}</div>{/if}
    {#if catalog?.refreshedAt}
      <label class="field"><span>Filter images</span><input bind:value={imageFilter} onchange={() => browser && browse(browser)} /></label>
      <label class="field"><span>Image</span><select value={selectedImage} onchange={(event) => choose(event.currentTarget.value)}><option value="">Select an image</option>
        {#each visible as image}<option value={image}>{image}</option>{/each}</select></label>
      {#if catalog.nextCursor}<button class="button secondary" disabled={browseBusy} onclick={() => browser && browse(browser, false, catalog?.nextCursor ?? undefined)}>Load more images</button>{/if}
    {:else}
      <p class="field-help">Refresh the catalog or enter a repository directly.</p>
    {/if}
    <div class="form-grid">
      <label class="field"><span>Repository for tag lookup</span><input class="mono" bind:value={repository} placeholder="owner/image" /></label>
      <label class="field"><span>Exact image reference</span><input class="mono" bind:value={exactReference} placeholder="owner/image:v1 or owner/image@sha256:…" /></label>
    </div>
    <div class="filters">
      <button class="button secondary" disabled={!repository.trim()} onclick={() => choose(repository)}>Look up tags</button>
      {#if auth.admin}<button class="button secondary" disabled={manifestBusy || !exactReference.trim()} onclick={testManifest}>Test manifest access</button>{/if}
    </div>
    {#if tags.length}<label class="field"><span>Tag for {selectedImage}</span><select bind:value={tag}>{#each tags as tag}<option>{tag}</option>{/each}</select></label>{/if}
    {#if imageIssue}<div class="notice warning" role="status">{imageIssue}</div>{/if}
    {#if manifestResult}<div class="notice" role="status">{manifestResult}</div>{/if}
    <div class="filters">
      <a class="button primary" href={'/scans/new?' + new URLSearchParams({registry:browser.id, image:exactReference.trim() || (selectedImage && tag ? selectedImage + ':' + tag : '')})}><ScanLine size={17} /> Scan image</a>
      {#if tags.length > 1}<a class="button secondary" href={'/scans/bulk?' + new URLSearchParams({registry:browser.id, images:tags.slice(0,50).map(tag => selectedImage + ':' + tag).join('\n')})}>Queue tags in bulk</a>{/if}
    </div>
  </div>
</section>
{/if}
