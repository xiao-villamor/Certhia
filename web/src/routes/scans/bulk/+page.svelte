<script lang="ts">
  import { productName } from '#lib/product.js';
  import { page } from '$app/state';
  import { onMount } from 'svelte';
  import { Layers } from '@lucide/svelte';
  import { api, apiPage, message, platforms, post, time, type Registry, allRegistries } from '#lib/api.js';
  interface Batch {id:string; createdAt:string; total:number; finished:number; failed:number;}
  let references = $state('');
  let platform = $state('linux/amd64');
  let registryId = $state('');
  let priority = $state(0);
  let registries = $state<Registry[]>([]);
  let batches = $state<Batch[]>([]);
  let links = $state<string[]>([]);
  let busy = $state(false);
  let issue = $state('');
  const images = $derived([...new Set(references.split('\n').map(value => value.trim()).filter(Boolean))]);
  let next=$state<string|null>(null);
  async function refresh(append=false) {
    try { const result=await apiPage<Batch[]>('/scans/bulk',append ? next : null); batches=append?[...batches,...result.items]:result.items;next=result.next; } catch (error) { issue = message(error); }
  }
  onMount(() => {
    references = page.url.searchParams.get('images') || '';
    registryId = page.url.searchParams.get('registry') || '';
    void refresh();
    void allRegistries().then(items => { registries = items; }).catch(error => { issue = message(error); });
    const timer = setInterval(() => {if (batches.some(batch => batch.finished < batch.total)) void refresh();}, 2500);
    return () => clearInterval(timer);
  });
  async function submit(event: SubmitEvent) {
    event.preventDefault();
    busy = true; issue = ''; links = [];
    try {
      const result = await api<{scanIds:string[]}>('/scans/bulk', post({ scans: images.map(reference => ({ reference, platform, priority, registryId: registryId || null })) }));
      links = result.scanIds;
      references = '';
      await refresh();
    } catch (error) { issue = message(error); }
    finally { busy = false; }
  }
</script>
<svelte:head><title>Batch scans · {productName}</title></svelte:head>
<div class="page-heading"><div><h1>Batch scans</h1><p>Queue up to 50 image references together.</p></div></div>
{#if issue}<div class="notice error" role="alert">{issue}</div>{/if}
{#if links.length}<div class="notice success" role="status">{links.length} scan(s) queued. <a href={'/scans/' + links[0]}>View first scan</a></div>{/if}
<section class="panel" aria-labelledby="batch-setup-title">
<div class="panel-title"><h2 id="batch-setup-title">Batch setup</h2></div>
<form class="form-panel wide" onsubmit={submit}>
  <label class="field"><span>Image references, one per line</span><textarea class="mono" placeholder={'registry.example.com/team/app:v1\nregistry.example.com/team/app:v2'} bind:value={references} required></textarea></label>
  <div class="form-grid">
    <label class="field"><span>Platform</span><select bind:value={platform}>{#each platforms as value}<option>{value}</option>{/each}</select></label>
    <label class="field"><span>Registry credentials</span><select bind:value={registryId}><option value="">Public images</option>
      {#each registries as registry}<option value={registry.id}>{registry.name}</option>{/each}</select></label>
  </div>
  <label class="field"><span>Queue priority</span><input type="number" min="-10" max="10" bind:value={priority} /></label>
  <div class="actions"><button class="button primary" disabled={busy || !images.length || images.length > 50}><Layers size={17} /> Queue {images.length} scans</button></div>
</form>
</section>
<section class="panel"><div class="panel-title"><h2>Batch history</h2></div>
  <div class="table-wrap"><table><thead><tr><th>Queued</th><th>Images</th><th>Finished</th><th>Failed</th></tr></thead>
    <tbody>{#each batches as batch (batch.id)}<tr><td>{time(batch.createdAt)}</td><td>{batch.total}</td><td>{batch.finished}</td><td>{batch.failed}</td></tr>
      {:else}<tr><td colspan="4">No batches yet.</td></tr>{/each}</tbody></table></div>
  {#if next}<button class="button secondary" onclick={() => refresh(true)}>Load more batches</button>{/if}
</section>
