<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { auth, loadSession, returnPath } from '#lib/auth.svelte.js';
  import EntryShell from '#lib/EntryShell.svelte';
  import { api, message, post, scannerProviders, type ScannerAvailability } from '#lib/api.js';

  const firstScan = $derived(page.url.searchParams.get('step') === 'scan' || !auth.admin);
  const requested = $derived(returnPath(new URL(page.url.href)));
  const next = $derived(requested.split(/[?#]/, 1)[0] === '/welcome' ? '/' : requested);
  let access = $state<ScannerAvailability>();
  let selected = $state<string[]>([]);
  let loading = $state(true);
  let busy = $state(false);
  let issue = $state('');

  const installed = $derived(scannerProviders.filter(provider => access?.registry.includes(provider.id)));
  const missing = $derived(scannerProviders.filter(provider => !access?.registry.includes(provider.id)));
  const heading = $derived(!auth.session ? 'Welcome to Certhia' : firstScan ? 'Add your first image report' : 'Choose your scanners');

  async function load() {
    loading = true;
    issue = '';
    try {
      await loadSession();
      if (!auth.operator) {
        await goto(next, { replaceState: true });
      } else if (!firstScan) {
        access = await api<ScannerAvailability>('/scanners/available');
        selected = (access.defaults ?? ['trivy']).filter(id => access?.registry.includes(id));
      }
    } catch (error) {
      issue = message(error);
    } finally {
      loading = false;
    }
  }

  onMount(() => { void load(); });

  async function saveScanners(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    issue = '';
    try {
      await api('/settings/scanners', { ...post({ scanners: selected }), method: 'PUT' });
      const url = new URL(page.url.href);
      url.searchParams.set('step', 'scan');
      await goto(url, { replaceState: true });
    } catch (error) {
      issue = message(error);
    } finally {
      busy = false;
    }
  }

</script>

<EntryShell title={heading} labelledby="welcome-heading" wide>
  <h1 id="welcome-heading">{heading}</h1>
  {#if issue}<div class="notice error" role="alert">{issue}</div>{/if}

  {#if loading}
    <p role="status">Loading workspace…</p>
  {:else if !auth.operator || (!firstScan && !access)}
    <button class="button secondary" onclick={load}>Retry</button>
  {:else if !firstScan}
    <p>Choose which scanners to use by default. You can change them later in Workspace preferences.</p>
    <form onsubmit={saveScanners}>
      <fieldset class="scanners" disabled={busy}>
        <legend class="visually-hidden">Scanners</legend>
        {#each installed as provider (provider.id)}
          <label class="scanner">
            <input type="checkbox" value={provider.id} bind:group={selected} />
            <span><strong>{provider.name}</strong><small>{provider.purpose}</small></span>
          </label>
        {/each}
      </fieldset>
      {#if missing.length}
        <p class="field-help">Not installed in this image: {missing.map(provider => provider.name).join(', ')}.</p>
      {/if}
      {#if !selected.length}<p class="field-help">Trivy runs when no scanner is selected.</p>{/if}
      <div class="actions">
        <button class="button primary" disabled={busy}>{busy ? 'Saving…' : 'Continue'}</button>
      </div>
    </form>
  {:else}
    <p>Start with a public registry image or upload an existing Trivy JSON report.</p>
    <div class="actions">
      <a class="button primary" href="/scans/new">Scan a public image</a>
      <a class="button secondary" href="/scans/new?mode=import">Import a report</a>
      <a class="button secondary" href={next === '/' ? '/' : next}>{next === '/' ? 'Go to Scan desk' : 'Continue to requested page'}</a>
    </div>
  {/if}
</EntryShell>

<style>
  form { display: grid; gap: .85rem; }
  .scanners { display: grid; gap: .5rem; margin: 0; padding: 0; border: 0; }
  .scanner {
    display: grid; grid-template-columns: auto 1fr; align-items: center; gap: .8rem;
    padding: .75rem .9rem; border: 1px solid var(--line); border-radius: var(--radius); cursor: pointer;
  }
  .scanner:has(input:checked) { border-color: var(--accent); background: var(--accent-soft); }
  .scanner span { display: grid; gap: .1rem; }
  .scanner small { color: var(--muted); font-size: var(--text-detail); }
  .actions { display: flex; flex-wrap: wrap; gap: .6rem; }
  .visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
</style>
