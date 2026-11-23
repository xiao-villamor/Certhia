<script lang="ts">
  import { productName } from '#lib/product.js';
  import { onMount } from 'svelte';
  import { Search } from '@lucide/svelte';
  import { apiPage, message, time } from '#lib/api.js';
  interface Entry { id: number; action: string; resource: string; detail: string; actorUserId: string | null; createdAt: string;
    actorName?: string | null; resourceLabel?: string | null; resourcePath?: string | null; }
  const labels: Record<string, string> = {
    'finding.classified':'Finding tracking updated', 'finding.exception_set':'Finding exception saved',
    'finding.exception_revoked':'Finding exception removed', 'issue_tracker.removed':'Issue tracker removed',
    'settings.scanners.updated':'Scanner defaults updated', 'scan.requeued':'Scan retried'
  };
  function readable(action: string) {
    const words = action.replace(/[._]/g, ' ');
    return labels[action] ?? words.charAt(0).toUpperCase() + words.slice(1);
  }
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
  <div class="table-wrap"><table><thead><tr><th>Event</th><th>Resource</th><th>Details</th><th>Actor</th><th>Timestamp</th></tr></thead>
    <tbody>{#each items as item (item.id)}<tr>
      <td title={item.action}><strong>{readable(item.action)}</strong></td>
      <td>{#if item.resourceLabel && item.resourcePath}<a class="table-link break" href={item.resourcePath}>{item.resourceLabel}</a>
        {:else if item.resourceLabel}<span class="break">{item.resourceLabel}</span>
        {:else if /^[a-f0-9-]{36}$/i.test(item.resource)}<span class="field-help" title={item.resource}>Record {item.resource.slice(-8)}</span>
        {:else}<span class="break">{item.resource}</span>{/if}</td>
      <td>{item.detail || '—'}</td><td title={item.actorUserId ?? undefined}>{item.actorName || (item.actorUserId ? 'Former or unnamed user' : 'System')}</td><td>{time(item.createdAt)}</td></tr>
    {:else}<tr><td colspan="5">No matching events.</td></tr>{/each}</tbody>
  </table></div>
  {#if cursor}<button class="button secondary" onclick={() => load(true)}>Load more events</button>{/if}
</section>
