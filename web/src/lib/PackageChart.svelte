<script lang="ts">
  import { onMount } from 'svelte';
  import { ArrowRight } from '@lucide/svelte';
  import { api, message } from './api.js';

  interface PackageImpact {
    id: number;
    name: string;
    version: string;
    total: number;
  }

  let packages = $state<PackageImpact[]>([]);
  let loading = $state(true);
  let issue = $state('');
  let request: AbortController | undefined;
  const max = $derived(Math.max(1, ...packages.map(item => item.total)));
  const format = new Intl.NumberFormat();

  async function load() {
    if (request) return;
    const controller = new AbortController();
    request = controller;
    loading = true;
    issue = '';
    try {
      const result = await api<{ items: PackageImpact[] }>('/library/top-packages?limit=5', { signal: controller.signal });
      if (!controller.signal.aborted) packages = result.items;
    } catch (error) {
      if (!controller.signal.aborted) issue = message(error);
    } finally {
      if (!controller.signal.aborted) loading = false;
      request = undefined;
    }
  }

  onMount(() => {
    void load();
    return () => request?.abort();
  });
</script>

<section class="panel" aria-labelledby="package-impact-title">
  <div class="panel-title">
    <div><h2 id="package-impact-title">Most affected package versions</h2><p>Ranked by findings across image digests</p></div>
    <a class="button secondary" href="/library?scope=history">Vulnerabilities <ArrowRight size={15} aria-hidden="true" /></a>
  </div>
  {#if loading}
    <div class="compact-empty" role="status">Loading package findings…</div>
  {:else if issue}
    <div class="compact-empty" role="alert">{issue} <button class="text-button" onclick={load}>Retry</button></div>
  {:else if packages.length}
    <ol class="package-impact">
      {#each packages as item (item.id)}
        <li>
          <div class="package-label">
            <a class="table-link mono break" href={'/library?' + new URLSearchParams({package: item.name, scope: 'history'})}>{item.name}</a>
            <small class="mono break">{item.version}</small>
          </div>
          <div class="package-track" aria-hidden="true"><span style:width={100 * item.total / max + '%'}></span></div>
          <strong aria-label={format.format(item.total) + ' findings'}>{format.format(item.total)}</strong>
        </li>
      {/each}
    </ol>
  {:else}
    <div class="compact-empty">No package findings to rank.</div>
  {/if}
</section>

<style>
  .package-impact { display: grid; flex: 1; list-style: none; margin: 0; padding: .35rem 1.15rem; }
  li {
    display: grid;
    grid-template-columns: minmax(0, 1.2fr) minmax(2rem, 1fr) minmax(3ch, max-content);
    align-items: center;
    gap: .75rem;
    padding: .55rem 0;
  }
  li + li { border-top: 1px solid var(--line); }
  .package-label { display: grid; gap: .2rem; }
  .package-label small { color: var(--muted); font-size: .72rem; }
  .package-track { height: .4rem; border-radius: .2rem; overflow: hidden; background: var(--inset); }
  .package-track span { display: block; height: 100%; background: var(--accent); }
  strong { text-align: end; font: 600 .84rem var(--mono); }
</style>
