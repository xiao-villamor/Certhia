<script lang="ts">
  import { onMount } from 'svelte';
  import { api, message, post } from './api.js';
  import { loadSession } from './auth.svelte.js';

  interface Settings {
    name: string;
    issuer: string;
    clientId: string;
    allowedDomains: string[];
    enabled: boolean;
    jit: boolean;
    trustEmail: boolean;
    secretPost: boolean;
  }

  interface Config {
    settings: Settings | null;
    callbackUrl: string | null;
    deploymentConflict: boolean;
    deploymentProviders: string[];
  }

  let config = $state<Config>();
  let settings = $state<Settings>({
    name: 'Work account', issuer: '', clientId: '', allowedDomains: [],
    enabled: true, jit: false, trustEmail: false, secretPost: false
  });
  let domains = $state('');
  let clientSecret = $state('');
  let loading = $state(true);
  let saving = $state(false);
  let issue = $state('');
  let notice = $state('');
  const secretRequired = $derived(!config?.settings || config.settings.issuer !== settings.issuer.trim()
    || config.settings.clientId !== settings.clientId.trim());

  function apply(result: Config) {
    config = result;
    if (result.settings) {
      settings = {...result.settings};
      domains = settings.allowedDomains.join(', ');
    }
  }

  async function load() {
    loading = true;
    issue = '';
    try {
      apply(await api<Config>('/settings/sso'));
    } catch (error) {
      issue = message(error);
    } finally {
      loading = false;
    }
  }

  async function save(event: SubmitEvent) {
    event.preventDefault();
    saving = true;
    issue = '';
    notice = '';
    try {
      const result = await api<Config>('/settings/sso', {
        ...post({
          settings: {...settings, allowedDomains: domains.split(',').map(value => value.trim()).filter(Boolean)},
          clientSecret: clientSecret || undefined
        }),
        method: 'PUT'
      });
      clientSecret = '';
      apply(result);
      await loadSession();
      notice = 'Single sign-on settings saved.';
    } catch (error) {
      issue = message(error);
    } finally {
      saving = false;
    }
  }

  onMount(() => { void load(); });
</script>

<section class="panel" aria-labelledby="sso-heading">
  <div class="panel-title">
    <div><h2 id="sso-heading">Single sign-on</h2>
      <p>Connect an OpenID Connect identity provider such as Microsoft Entra ID or Keycloak.</p></div>
    {#if config?.settings}
      <span class="badge" class:completed={config.settings.enabled && !config.deploymentConflict}>
        {config.settings.enabled && !config.deploymentConflict ? 'Enabled' : 'Disabled'}
      </span>
    {/if}
  </div>
  {#if loading && !config}
    <p class="compact-empty" role="status">Loading sign-in settings…</p>
  {:else if !config}
    <div class="panel-footer">
      <p class="notice error" role="alert">{issue}</p>
      <button class="button secondary" onclick={load}>Retry</button>
    </div>
  {:else}
    {#if config.deploymentProviders.length}
      <p class="panel-footer field-help">Deployment-managed providers · {config.deploymentProviders.join(', ')}</p>
    {/if}
    {#if !config.callbackUrl}
      <p class="panel-footer">Set <code>CERTHIA_AUTH_ORIGIN</code> to your dashboard’s public HTTPS origin and open Certhia at that address.</p>
    {:else}
      <form class="form-panel wide sso-form" onsubmit={save}>
        <label class="field"><span>Redirect URI</span>
          <input class="mono" value={config.callbackUrl} readonly />
          <small>Register this exact URI for a confidential web client at your identity provider.</small>
        </label>
        <div class="form-grid sso-fields">
          <label class="field"><span>Sign-in button name</span><input bind:value={settings.name} required maxlength="100" /></label>
          <label class="field"><span>OIDC issuer URL</span>
            <input type="url" bind:value={settings.issuer} placeholder="https://sso.example.com/realms/work" required maxlength="2048" />
            <small>For Entra ID, use https://login.microsoftonline.com/&lt;tenant-id&gt;/v2.0.</small>
          </label>
          <label class="field"><span>Client ID</span><input bind:value={settings.clientId} required maxlength="512" /></label>
          <label class="field"><span>Client secret</span>
            <input type="password" bind:value={clientSecret} required={secretRequired} maxlength="4096" autocomplete="new-password" />
            {#if !secretRequired}<small>Leave blank to keep the saved secret.</small>{/if}
          </label>
        </div>
        <label class="field"><span>Allowed email domains</span>
          <input bind:value={domains} required placeholder="example.com, example.org" />
          <small>Use commas to separate domains. Invite SSO-only users by work email in Users.</small>
        </label>
        <fieldset class="sso-options">
          <legend>Sign-in policy</legend>
          <label class="inline-check"><input type="checkbox" bind:checked={settings.enabled} /> Show this provider on the sign-in page</label>
          <label class="inline-check"><input type="checkbox" bind:checked={settings.jit} /> Give new users the Viewer role on first sign-in</label>
          <label class="inline-check"><input type="checkbox" bind:checked={settings.secretPost} /> Send the client secret in the token request body</label>
          <label class="inline-check"><input type="checkbox" bind:checked={settings.trustEmail} /> Allow sign-in when the provider omits email verification</label>
          {#if settings.trustEmail}<p class="field-help">Use this only for a directory that controls and verifies its users’ email addresses.</p>{/if}
        </fieldset>
        {#if config.deploymentConflict}
          <p class="notice warning">A deployment-managed provider uses the same issuer or redirect URI.</p>
        {/if}
        {#if issue}<p class="notice error" role="alert">{issue}</p>{/if}
        {#if notice}<p class="field-help" role="status">{notice}</p>{/if}
        <div class="actions"><button class="button primary" disabled={saving}>{saving ? 'Saving…' : 'Save single sign-on'}</button></div>
      </form>
    {/if}
  {/if}
</section>

<style>
  .sso-form { max-width: 55rem; }
  .sso-fields { align-items: start; }
  .sso-options { display: grid; gap: .7rem; min-width: 0; border: 1px solid var(--line); border-radius: var(--radius); padding: .75rem; }
  .sso-options legend { padding-inline: .25rem; font-weight: 750; }
</style>
