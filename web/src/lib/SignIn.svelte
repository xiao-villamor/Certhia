<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { api, message, post } from './api.js';
  import { returnPath, type AuthStatus } from './auth.svelte.js';
  import { productName } from './product.js';

  let { setup = false }: { setup?: boolean } = $props();
  let status = $state<AuthStatus>();
  let email = $state('');
  let displayName = $state('');
  let password = $state('');
  let setupCode = $state('');
  let busy = $state(false);
  let providerBusy = $state(false);
  let issue = $state('');
  let loading = $state(true);
  const heading = $derived(setup ? 'Create the first administrator' : 'Sign in');

  async function load() {
    issue = '';
    loading = true;
    try {
      const result = await api<AuthStatus>('/auth/status');
      if (result.setupRequired !== setup) {
        window.location.replace((result.setupRequired ? '/setup' : '/login') + page.url.search);
        return;
      }
      status = result;
      if (page.url.searchParams.get('error') === 'oidc') {
        issue = 'Single sign-on did not complete. Try again or contact your administrator.';
      }
    } catch (error) {
      issue = message(error);
    } finally {
      loading = false;
    }
  }

  onMount(() => { void load(); });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    issue = '';
    try {
      const body = setup ? { email, password, displayName, setupCode } : { email, password };
      await api(setup ? '/auth/setup' : '/auth/login', post(body));
      window.location.replace(returnPath(new URL(window.location.href)));
    } catch (error) {
      issue = message(error);
      busy = false;
    }
  }
</script>

<svelte:head><title>{heading} · {productName}</title></svelte:head>

<main class="entry-page">
  <section class="panel entry-panel" aria-labelledby="entry-heading">
    <img src="/certhia.png" width="40" height="40" alt={productName} />
    <h1 id="entry-heading">{heading}</h1>
    {#if setup}<p>Use the first-run code from your Certhia server to set up this workspace.</p>{/if}
    {#if !issue && page.url.searchParams.get('password') === 'changed'}
      <div class="notice success" role="status">Password changed. Sign in with your new password.</div>
    {/if}
    {#if issue}<div class="notice error" role="alert">{issue}</div>{/if}
    {#if loading}
      <p role="status">Loading sign-in options…</p>
    {:else if !status}
      <button class="button secondary" onclick={load}>Retry</button>
    {:else}
      {#if status.local || setup}
        <form onsubmit={submit}>
          {#if setup}
            <label class="field"><span>Setup code</span>
              <input type="password" bind:value={setupCode} autocomplete="off" required maxlength="512" />
            </label>
            <label class="field"><span>Display name</span>
              <input bind:value={displayName} autocomplete="name" required maxlength="100" />
            </label>
          {/if}
          <label class="field"><span>Email</span>
            <input type="email" bind:value={email} autocomplete="username" required maxlength="254" />
          </label>
          <label class="field"><span>Password</span>
            <input type="password" bind:value={password} required minlength={setup ? 12 : undefined}
              maxlength="1024" autocomplete={setup ? 'new-password' : 'current-password'} />
            {#if setup}<small>Use at least 12 characters.</small>{/if}
          </label>
          <button class="button primary" disabled={busy || providerBusy}>
            {busy ? (setup ? 'Creating administrator…' : 'Signing in…') : (setup ? 'Create administrator' : 'Sign in')}
          </button>
        </form>
      {/if}
      {#if !setup && status.providers.length}
        <div class="providers" class:with-password={status.local}>
          {#each status.providers as provider (provider.id)}
            <form method="post" action={'/api/auth/oidc/' + provider.id + '/start'}
              onsubmit={() => { providerBusy = true; }}>
              <button class="button secondary" disabled={busy || providerBusy}>Sign in with {provider.name}</button>
            </form>
          {/each}
        </div>
      {/if}
    {/if}
  </section>
</main>

<style>
  .entry-page { display: grid; align-content: center; justify-items: center; min-height: 100dvh; padding: 1.5rem; }
  .entry-panel { width: min(100%, 28rem); display: grid; gap: 1.05rem; padding: clamp(1.25rem, 5vw, 2rem); margin: 0; }
  .entry-panel h1 { font-size: 1.55rem; line-height: 1.15; }
  .entry-panel p { color: var(--muted); }
  .entry-panel .notice { margin: 0; }
  form, .providers { display: grid; gap: .85rem; }
  .with-password { border-top: 1px solid var(--line); padding-top: 1.05rem; }
</style>
