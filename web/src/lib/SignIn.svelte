<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { api, message, post } from './api.js';
  import { returnPath, type AuthStatus } from './auth.svelte.js';
  import EntryShell from './EntryShell.svelte';

  let { setup = false }: { setup?: boolean } = $props();
  let status = $state<AuthStatus>();
  let email = $state('');
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
      const body = setup ? { email, password, setupCode } : { email, password };
      await api(setup ? '/auth/setup' : '/auth/login', post(body));
      const next = returnPath(new URL(window.location.href));
      window.location.replace(setup ? '/welcome?' + new URLSearchParams({ next }) : next);
    } catch (error) {
      issue = message(error);
      busy = false;
    }
  }
</script>

<EntryShell title={heading} labelledby="entry-heading">
  <h1 id="entry-heading">{heading}</h1>
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
          {#if status.setupCodeRequired}
            <label class="field"><span>Setup code</span>
              <input type="password" bind:value={setupCode} autocomplete="off" required maxlength="512" />
            </label>
          {/if}
        {/if}
        <label class="field"><span>Username</span>
          <input bind:value={email} autocomplete="username" autocapitalize="none" spellcheck="false" required maxlength="254" />
        </label>
        <label class="field"><span>Password</span>
          <input type="password" bind:value={password} required minlength={setup ? 8 : undefined}
            maxlength="1024" autocomplete={setup ? 'new-password' : 'current-password'} />
          {#if setup}<small>Use at least 8 characters.</small>{/if}
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
</EntryShell>

<style>
  form, .providers { display: grid; gap: .85rem; }
  .providers form .button { width: 100%; }
  .with-password { border-top: 1px solid var(--line); padding-top: 1.05rem; }
</style>
