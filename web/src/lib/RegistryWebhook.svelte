<script lang="ts">
  import { Copy } from '@lucide/svelte';
  import ConfigDialog from '#lib/ConfigDialog.svelte';
  import { api, message, type Registry } from '#lib/api.js';

  interface Configuration { ciPath: string; harborPath: string; createdAt: string | null; }
  let { registry, dismiss }: { registry?: Registry; dismiss: () => void } = $props();
  let configuration = $state<Configuration>();
  let origin = $state('');
  let token = $state('');
  let busy = $state(false);
  let loading = $state(false);
  let issue = $state('');
  let notice = $state('');

  function load(path: string, signal: AbortSignal) {
    loading = true;
    void api<Configuration>(path, {signal}).then(result => {
      if (!signal.aborted) configuration = result;
    }).catch(error => {
      if (!signal.aborted) issue = message(error);
    }).finally(() => {
      if (!signal.aborted) loading = false;
    });
  }

  $effect(() => {
    const path = registry && '/registries/' + registry.id + '/webhook';
    configuration = undefined; token = ''; issue = ''; notice = '';
    if (!path) return;
    origin = window.location.origin;
    const controller = new AbortController();
    load(path, controller.signal);
    return () => controller.abort();
  });

  async function change(action: 'generate' | 'revoke') {
    if (!registry || busy || !configuration) return;
    if (configuration.createdAt && !window.confirm(action === 'revoke'
      ? 'Revoke this token? CI and Harbor will stop sending scans for this connection.'
      : 'Rotate this token? Update CI and Harbor with the new token.')) return;
    const path = '/registries/' + registry.id + '/webhook';
    busy = true; issue = ''; notice = '';
    try {
      if (action === 'revoke') {
        await api(path, {method:'DELETE'});
        token = '';
        configuration = {...configuration, createdAt:null};
        notice = 'Webhook token revoked.';
      } else {
        const {token: generated, ...details} = await api<Configuration & {token: string}>(path, {method:'POST'});
        configuration = details;
        token = generated;
      }
    } catch (error) { issue = message(error); }
    finally { busy = false; }
  }

  async function copy(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      notice = label + ' copied.';
    } catch {
      issue = 'Clipboard access is unavailable. Select and copy the value directly.';
    }
  }
</script>

<ConfigDialog id="registry-webhook" title="Scan webhook" description={registry?.name}
  open={!!registry} {busy} {dismiss}>
  {#if loading}
    <p role="status" class="field-help">Loading webhook settings…</p>
  {:else if configuration}
    {#if configuration.createdAt}
      {#if token}
        <label class="field"><span>Webhook token</span>
          <div class="copy-field">
            <input class="mono" readonly value={token} />
            <button type="button" class="button secondary" onclick={() => copy(token, 'Token')}><Copy size={16} /> Copy</button>
          </div>
          <small>Save this token now. It’s shown once.</small>
        </label>
      {:else}
        <p class="field-help">A token is active. Rotate it to generate a new one.</p>
      {/if}
      <label class="field"><span>CI endpoint</span>
        <div class="copy-field">
          <input class="mono" readonly value={origin + configuration.ciPath} />
          <button type="button" class="button secondary" onclick={() => configuration && copy(origin + configuration.ciPath, 'CI endpoint')}><Copy size={16} /> Copy</button>
        </div>
        <small>Send a JSON POST with <code>reference</code> and <code>Authorization: Bearer &lt;token&gt;</code>. Set <code>platform</code> to override <code>linux/amd64</code>.</small>
      </label>
      <label class="field"><span>Harbor endpoint</span>
        <div class="copy-field">
          <input class="mono" readonly value={origin + configuration.harborPath} />
          <button type="button" class="button secondary" onclick={() => configuration && copy(origin + configuration.harborPath, 'Harbor endpoint')}><Copy size={16} /> Copy</button>
        </div>
        <small>In your Harbor project, create an HTTP webhook for <strong>Artifact pushed</strong>. Paste the endpoint URL and use the token as the Auth Header.</small>
      </label>
    {:else}
      <p class="field-help">Generate a token to let a CI job or Harbor push event scan images from this registry.</p>
    {/if}
  {/if}
  {#if issue}<div class="notice error" role="alert">{issue}</div>{/if}
  {#if notice}<div class="notice success" role="status">{notice}</div>{/if}
  {#snippet actions()}
    <button type="button" class="button secondary" disabled={busy} onclick={dismiss}>Done</button>
    {#if configuration?.createdAt}
      <button type="button" class="button secondary" disabled={busy} onclick={() => change('revoke')}>Revoke token</button>
    {/if}
    {#if configuration}
      <button type="button" class="button primary" disabled={busy} onclick={() => change('generate')}>
        {configuration.createdAt ? 'Rotate token' : 'Generate token'}
      </button>
    {/if}
  {/snippet}
</ConfigDialog>

<style>
  .copy-field { display: flex; gap: .45rem; }
  .copy-field input { min-width: 0; }
  .copy-field button { flex: none; }
</style>
