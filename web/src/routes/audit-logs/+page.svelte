<script lang="ts">
  import { productName } from '#lib/product.js';
  import { onMount } from 'svelte';
  import { Search } from '@lucide/svelte';
  import { apiPage, message, time } from '#lib/api.js';
  interface Entry { id: number; action: string; resource: string; detail: string; actorUserId: string | null; createdAt: string; }
  let items = $state<Entry[]>([]);
  let query = $state('');
  let issue = $state('');
  let cursor=$state<string|null>(null);
  let request:AbortController|undefined;
  async function load(append=false){
    request?.abort();const controller=new AbortController();request=controller;
    try{const page=await apiPage<Entry[]>('/audit-logs?'+new URLSearchParams({q:query}),append ? cursor : null,{signal:controller.signal});
      if(!controller.signal.aborted){items=append?[...items,...page.items]:page.items;cursor=page.next;}
    }catch(error){if(!controller.signal.aborted)issue=message(error);}
  }
  onMount(()=>{void load();return ()=>request?.abort();});
</script>
<svelte:head><title>Activity history · {productName}</title></svelte:head>
<div class="page-heading"><div><h1>Activity history</h1><p>Review changes and scan activity in this workspace.</p></div></div>
{#if issue}<div class="notice error" role="alert">{issue}</div>{/if}
<section class="panel">
  <div class="panel-title"><h2>Recent events</h2><label class="search"><Search size={17} /><input bind:value={query} oninput={() => void load()} placeholder="Filter events" aria-label="Filter events" /></label></div>
  <div class="table-wrap"><table><thead><tr><th>Event</th><th>Resource</th><th>Details</th><th>Actor user ID</th><th>Timestamp</th></tr></thead>
    <tbody>{#each items as item (item.id)}<tr><td class="mono">{item.action}</td><td class="mono">{item.resource}</td><td>{item.detail || '—'}</td><td class="mono">{item.actorUserId ?? '—'}</td><td>{time(item.createdAt)}</td></tr>
    {:else}<tr><td colspan="5">No matching events.</td></tr>{/each}</tbody>
  </table></div>
  {#if cursor}<button class="button secondary" onclick={() => load(true)}>Load more events</button>{/if}
</section>
