<script lang="ts">
  import { api, message, post } from '#lib/api.js';
  import { auth } from '#lib/auth.svelte.js';
  import { productName } from '#lib/product.js';

  let currentPassword = $state('');
  let newPassword = $state('');
  let confirmation = $state('');
  let issue = $state('');
  let busy = $state(false);

  async function changePassword(event: SubmitEvent) {
    event.preventDefault();
    if (newPassword !== confirmation) {
      issue = 'The new passwords do not match.';
      return;
    }
    busy = true;
    issue = '';
    try {
      await api('/auth/password', { ...post({ currentPassword, newPassword }), method: 'PUT' });
      window.location.replace('/login?password=changed');
    } catch (error) {
      issue = message(error);
      busy = false;
    }
  }
</script>

<svelte:head><title>Your account · {productName}</title></svelte:head>

<div class="page-heading">
  <div><h1>Your account</h1><p>{auth.session?.user.email}</p></div>
</div>
{#if auth.session?.local && auth.session?.user.hasPassword}
  <form class="panel form-panel" onsubmit={changePassword}>
    <h2>Change password</h2>
    <p>Changing your password signs you out on all devices.</p>
    <label class="field"><span>Current password</span>
      <input type="password" bind:value={currentPassword} autocomplete="current-password" required maxlength="1024" />
    </label>
    <label class="field"><span>New password</span>
      <input type="password" bind:value={newPassword} autocomplete="new-password" required minlength="8" maxlength="1024" />
      <small>Use at least 8 characters.</small>
    </label>
    <label class="field"><span>Confirm new password</span>
      <input type="password" bind:value={confirmation} autocomplete="new-password" required minlength="8" maxlength="1024" />
    </label>
    {#if issue}<div class="notice error" role="alert">{issue}</div>{/if}
    <div class="actions"><button class="button primary" disabled={busy}>{busy ? 'Saving…' : 'Change password'}</button></div>
  </form>
{:else}
  <p>Manage your sign-in credentials with your identity provider.</p>
{/if}
