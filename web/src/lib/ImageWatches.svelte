<script lang="ts">
  import { onMount } from 'svelte';
  import { api, message, time, type ImageWatch } from '#lib/api.js';
  import { productName } from '#lib/product.js';

  interface Alert {
    reference: string;
    platform: string;
    scanId: string | null;
    advisories: string[];
    createdAt: string;
    delivery: 'pending' | 'delivered' | 'failed';
    error: string | null;
  }
  let { destination }: {destination?: boolean} = $props();
  let watches = $state<ImageWatch[]>([]);
  let alerts = $state<Alert[]>([]);
  let loading = $state(false);
  let loaded = $state(false);
  let busy = $state('');
  let issue = $state('');

  let watchCursor=$state<string|null>(null);
  let alertCursor=$state<number|null>(null);
  async function load(more?:'watches'|'alerts') {
    if (loading) return;
    loading = true;
    issue = '';
    try {
      const query=new URLSearchParams();
      if(more==='watches' && watchCursor)query.set('cursor',watchCursor);
      if(more==='alerts' && alertCursor)query.set('alertCursor',String(alertCursor));
      const result=await api<{watches:ImageWatch[];alerts:Alert[];nextCursor:string|null;nextAlertCursor:number|null}>('/image-watches?'+query);
      if(more!=='alerts'){watches=more?[...watches,...result.watches]:result.watches;watchCursor=result.nextCursor;}
      if(more!=='watches'){alerts=more?[...alerts,...result.alerts]:result.alerts;alertCursor=result.nextAlertCursor;}
      loaded = true;
    } catch (error) { issue = message(error); }
    finally { loading = false; }
  }
  onMount(() => {void load();});

  async function remove(watch: ImageWatch) {
    if (busy || loading || !confirm('Stop watching this image and remove its alert history?')) return;
    busy = watch.id;
    try {
      await api('/image-watches/' + watch.id, {method:'DELETE'});
      await load();
    } catch (error) { issue = message(error); }
    finally { busy = ''; }
  }
</script>

<section class="panel" id="image-watches" aria-labelledby="watches-title">
  <div class="panel-title"><div><h2 id="watches-title">Image watches</h2><p>Later scans create alerts when they detect new advisories for a watched image.</p></div>
    {#if watches.length}<button type="button" class="button secondary" onclick={() => load()} disabled={!!busy || loading}>Refresh alerts</button>{/if}
  </div>
  {#if issue}<div class="settings-empty"><p class="notice error" role="alert">{issue}</p>
    <button class="button secondary" type="button" onclick={() => load()} disabled={loading || !!busy}>Reload watches</button></div>
  {/if}
  {#if !loaded && !issue}<p class="compact-empty" role="status">Loading image watches…</p>
  {:else if !watches.length && !issue}
    <div class="settings-empty">
      <h3>No images watched</h3>
      <p>Open a scan report and choose Watch new vulnerabilities to track future findings for that image.</p>
      <a class="button secondary" href="/images">Open image catalog</a>
    </div>
  {:else if watches.length}
    {#if destination === false}<p class="panel-footer field-help">To receive alerts outside {productName}, <a href="/settings?section=retention-notifications#notifications-title">set up a notification destination</a>.</p>{/if}
    <!-- svelte-ignore a11y_no_noninteractive_tabindex (The table can scroll horizontally.) -->
    <div class="table-wrap" role="region" aria-labelledby="watches-title" tabindex="0"><table>
      <thead><tr><th>Image</th><th>Platform</th><th>Actions</th></tr></thead>
      <tbody>{#each watches as watch (watch.id)}
        <tr><td class="mono break">{watch.reference}</td><td>{watch.platform}</td>
          <td><button type="button" class="button secondary" disabled={!!busy || loading} onclick={() => remove(watch)}>Stop watching</button></td></tr>
      {/each}</tbody>
    </table></div>
    {#if watchCursor}<div class="panel-footer"><button class="button secondary" disabled={loading || !!busy} onclick={() => load('watches')}>Load more watches</button></div>{/if}
  {/if}
</section>

{#if watches.length || alerts.length}
  <section class="panel" aria-labelledby="alerts-title">
    <div class="panel-title"><h2 id="alerts-title">Recent alerts</h2></div>
    {#if alerts.length}
      <!-- svelte-ignore a11y_no_noninteractive_tabindex (The table can scroll horizontally.) -->
      <div class="table-wrap" role="region" aria-labelledby="alerts-title" tabindex="0"><table>
        <thead><tr><th>Image</th><th>New advisories</th><th>Detected</th><th>Delivery</th></tr></thead>
        <tbody>{#each alerts as alert}
          <tr>
            <td>{#if alert.scanId}<a class="table-link mono break" href={'/scans/' + alert.scanId}>{alert.reference}</a>
              {:else}<span class="mono break">{alert.reference}</span>{/if}<small>{alert.platform}</small></td>
            <td><strong>{alert.advisories.length}</strong><small>{alert.advisories.slice(0,8).join(', ')}{alert.advisories.length > 8 ? '…' : ''}</small></td>
            <td>{time(alert.createdAt)}</td>
            <td>{alert.delivery === 'failed' ? 'Failed' : alert.delivery === 'delivered' ? 'Delivered' : 'Pending'}
              {#if alert.error}<small>{alert.error}</small>{/if}</td>
          </tr>
        {/each}</tbody>
      </table></div>
      {#if alertCursor}<div class="panel-footer"><button class="button secondary" disabled={loading || !!busy} onclick={() => load('alerts')}>Load more alerts</button></div>{/if}
    {:else}
      <p class="compact-empty">No new advisory alerts yet.</p>
    {/if}
  </section>
{/if}

<style>
  .table-wrap:focus-visible { outline-offset: -3px; }
</style>
