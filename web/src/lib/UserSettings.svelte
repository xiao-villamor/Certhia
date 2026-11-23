<script lang="ts">
  import { onMount } from 'svelte';
  import { api, apiPage, message, post } from './api.js';
  import { auth, roles, type Role, type User } from './auth.svelte.js';

  let users = $state<User[]>([]);
  let cursor = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let adding = $state(false);
  let edited = $state<User>();
  let email = $state('');
  let displayName = $state('');
  let password = $state('');
  let role = $state<Role>('viewer');
  let disabled = $state(false);
  let issue = $state('');
  let notice = $state('');

  async function load(append = false) {
    loading = true;
    issue = '';
    try {
      const page = await apiPage<User[]>('/users', append ? cursor : null);
      users = append ? [...users, ...page.items] : page.items;
      cursor = page.next;
    } catch (error) {
      issue = message(error);
    } finally {
      loading = false;
    }
  }

  onMount(() => { void load(); });

  function edit(user?: User) {
    edited = user;
    adding = !user;
    email = user?.email ?? '';
    displayName = user?.displayName ?? '';
    role = user?.role ?? 'viewer';
    disabled = user?.disabled ?? false;
    password = '';
    issue = '';
    notice = '';
  }

  async function save(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    issue = '';
    try {
      if (edited) {
        const original = edited;
        const user = await api<User>('/users/' + original.id, {
          ...post({ displayName, role, disabled, newPassword: password || undefined }), method: 'PUT'
        });
        if (user.id === auth.session?.user.id) {
          window.location.reload();
          return;
        }
        users = users.map(item => item.id === user.id ? user : item);
        notice = 'User updated.';
      } else {
        await api('/users', post({ email, displayName, role, password: password || undefined }));
        await load();
        notice = 'Account created.';
      }
      adding = false;
      edited = undefined;
      password = '';
    } catch (error) {
      issue = message(error);
    } finally {
      busy = false;
    }
  }

  async function revoke(user: User) {
    if (!confirm('Sign out ' + user.displayName + ' on all devices?')) return;
    busy = true;
    issue = '';
    notice = '';
    try {
      await api('/users/' + user.id + '/sessions/revoke', { method: 'POST' });
      if (user.id === auth.session?.user.id) window.location.replace('/login');
      else notice = 'Sessions revoked for ' + user.displayName + '.';
    } catch (error) {
      issue = message(error);
    } finally {
      busy = false;
    }
  }
</script>

<section class="panel" aria-labelledby="users-heading">
  <div class="panel-title">
    <div><h2 id="users-heading">Users</h2><p>Manage workspace access and active sessions.</p></div>
    {#if !adding && !edited && (auth.session?.local || auth.session?.oidcEmailLinking)}
      <button class="button primary" onclick={() => edit()} disabled={busy}>Add user</button>
    {/if}
  </div>
  {#if notice}<div class="panel-footer" role="status">{notice}</div>{/if}
  {#if issue}<div class="panel-footer"><div class="notice error" role="alert">{issue}</div></div>{/if}
  {#if adding || edited}
    <form class="form-panel wide" onsubmit={save}>
      <h3>{adding ? 'Add user' : 'Edit user'}</h3>
      <div class="form-grid account-fields">
        <label class="field"><span>Username</span>
          <input bind:value={email} required maxlength="254" autocapitalize="none" spellcheck="false" readonly={!!edited} />
          {#if auth.session?.oidcEmailLinking}<small>Use their work email for an SSO-only account.</small>{/if}
        </label>
        <label class="field"><span>Display name</span>
          <input bind:value={displayName} required maxlength="100" />
        </label>
        <label class="field"><span>Role</span>
          <select bind:value={role}>{#each roles as item}<option value={item}>{item}</option>{/each}</select>
        </label>
        {#if adding && auth.session?.local}
          <label class="field"><span>Initial password</span>
            <input type="password" bind:value={password} required={!auth.session.oidcEmailLinking}
              minlength="8" maxlength="1024" autocomplete="new-password" />
            <small>{auth.session.oidcEmailLinking ? 'Leave blank for single sign-on only.' : 'Share this securely. Use at least 8 characters.'}</small>
          </label>
        {:else if edited?.hasPassword && auth.session?.local && edited.id !== auth.session.user.id}
          <label class="field"><span>Reset password <small>Optional</small></span>
            <input type="password" bind:value={password} minlength="8" maxlength="1024" autocomplete="new-password" />
            <small>Setting a new password signs this user out on all devices.</small>
          </label>
        {/if}
      </div>
      {#if edited}<label class="inline-check"><input type="checkbox" bind:checked={disabled} /> Disable sign-in</label>{/if}
      <div class="actions">
        <button class="button secondary" type="button" disabled={busy}
          onclick={() => {adding = false; edited = undefined; password = ''; issue = '';}}>Cancel</button>
        <button class="button primary" disabled={busy}>{busy ? 'Saving…' : (adding ? 'Create account' : 'Save changes')}</button>
      </div>
    </form>
  {/if}
  {#if users.length}
    <div class="table-wrap"><table>
      <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead>
      <tbody>
        {#each users as user (user.id)}
          <tr>
            <td><strong>{user.displayName}</strong>{#if user.email !== user.displayName}<small>{user.email}</small>{/if}</td>
            <td class="role">{user.role}</td>
            <td>{user.disabled ? 'Disabled' : 'Enabled'}</td>
            <td><div class="filters">
              <button class="button secondary" disabled={busy} onclick={() => edit(user)}>Edit<span class="sr-only"> {user.displayName}</span></button>
              <button class="button secondary" disabled={busy || user.disabled} onclick={() => revoke(user)}>Revoke sessions<span class="sr-only"> for {user.displayName}</span></button>
            </div></td>
          </tr>
        {/each}
      </tbody>
    </table></div>
  {:else if loading}
    <div class="compact-empty" role="status">Loading users…</div>
  {:else if issue}
    <div class="panel-footer"><button class="button secondary" onclick={() => load()}>Retry</button></div>
  {/if}
  {#if cursor}
    <div class="panel-footer"><button class="button secondary" disabled={loading} onclick={() => load(true)}>Load more users</button></div>
  {/if}
</section>

<style>
  .role { text-transform: capitalize; }
  .account-fields { align-items: start; }
  .account-fields :is(input, select) { height: 42px; }
</style>
