<script lang="ts">
  import { onMount } from 'svelte';
  import { Pencil, Plus, Trash2 } from '@lucide/svelte';
  import ConfigDialog from '#lib/ConfigDialog.svelte';
  import { allPages, api, message, post } from '#lib/api.js';
  import { issueTrackers, issueTrackersPath, trackerName, type IssueTracker } from '#lib/tracking.js';

  const initial = {name:'', provider:'jira', urlTemplate:''};
  let trackers = $state<IssueTracker[]>([]);
  let form = $state({...initial});
  let editing = $state('');
  let open = $state(false);
  let loading = $state(true);
  let busy = $state(false);
  let issue = $state('');
  let notice = $state('');
  let formIssue = $state('');

  async function refresh() {
    issue = '';
    try { trackers = await allPages<IssueTracker>(issueTrackersPath); }
    catch (error) { issue = message(error); }
    finally { loading = false; }
  }

  onMount(() => { void refresh(); });

  function edit(item?: IssueTracker) {
    editing = item?.id ?? '';
    form = item ? {name:item.name, provider:item.provider, urlTemplate:item.urlTemplate} : {...initial};
    formIssue = '';
    notice = '';
    open = true;
  }

  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    busy = true; formIssue = ''; issue = ''; notice = '';
    try {
      await api(issueTrackersPath + (editing ? '/' + editing : ''), {
        ...post(form), method:editing ? 'PUT' : 'POST'
      });
      open = false;
      await refresh();
      if (!issue) notice = editing ? 'Issue tracker updated.' : 'Issue tracker added.';
    } catch (error) { formIssue = message(error); }
    finally { busy = false; }
  }

  async function remove(item: IssueTracker) {
    if (busy || !window.confirm('Remove ' + item.name + '? Existing issue links will be kept.')) return;
    issue = ''; notice = ''; busy = true;
    try {
      await api(issueTrackersPath + '/' + item.id, {method:'DELETE'});
      await refresh();
      if (!issue) notice = 'Issue tracker removed.';
    } catch (error) { issue = message(error); }
    finally { busy = false; }
  }
</script>

<section class="panel" id="issue-trackers" aria-labelledby="issue-trackers-title">
  <div class="panel-title">
    <div><h2 id="issue-trackers-title">Issue trackers</h2><p>Manage the trackers used to link findings to existing issues.</p></div>
    <button type="button" class="button primary" aria-haspopup="dialog" onclick={() => edit()} disabled={busy}>
      <Plus size={16} aria-hidden="true" /> Add issue tracker
    </button>
  </div>
  {#if issue}<div class="settings-empty"><p class="notice error" role="alert">{issue}</p>
    <button class="button secondary" type="button" onclick={refresh} disabled={busy}>Reload trackers</button></div>
  {/if}
  {#if notice}<p class="panel-footer" role="status">{notice}</p>{/if}
  {#if loading}
    <p class="compact-empty" role="status">Loading issue trackers…</p>
  {:else if !trackers.length && !issue}
    <div class="settings-empty">
      <h3>No issue trackers configured</h3>
      <p>Add a tracker and its issue URL template. You can then link findings to issues from a scan report.</p>
    </div>
  {:else if trackers.length}
    <!-- svelte-ignore a11y_no_noninteractive_tabindex (The table can scroll horizontally.) -->
    <div class="table-wrap" role="region" aria-labelledby="issue-trackers-title" tabindex="0"><table>
      <thead><tr><th>Name</th><th>Provider</th><th>Issue URL template</th><th>Actions</th></tr></thead>
      <tbody>{#each trackers as item (item.id)}
        <tr>
          <td><strong>{item.name}</strong></td>
          <td>{trackerName(item.provider)}</td>
          <td class="mono break">{item.urlTemplate}</td>
          <td><div class="filters">
            <button type="button" class="button secondary" aria-haspopup="dialog" disabled={busy} onclick={() => edit(item)}>
              <Pencil size={16} aria-hidden="true" /> Edit
            </button>
            <button type="button" class="icon-button" aria-label={'Remove ' + item.name} disabled={busy} onclick={() => remove(item)}>
              <Trash2 size={16} aria-hidden="true" />
            </button>
          </div></td>
        </tr>
      {/each}</tbody>
    </table></div>
  {/if}
</section>

<ConfigDialog id="issue-tracker-editor" title={editing ? 'Edit issue tracker' : 'Add issue tracker'} {open} {busy}
  dismiss={() => {open = false;}} onsubmit={save}>
  <div class="form-grid">
    <label class="field"><span>Name</span>
      <input required maxlength="100" placeholder="Security project" bind:value={form.name} disabled={busy} />
    </label>
    <label class="field"><span>Provider</span>
      <select bind:value={form.provider} disabled={busy}>
        {#each issueTrackers as [value,label]}<option {value}>{label}</option>{/each}
      </select>
    </label>
  </div>
  <label class="field"><span>Issue URL template</span>
    <input required class="mono" maxlength="1900" placeholder="https://tracker.example.com/browse/{'{id}'}"
      bind:value={form.urlTemplate} disabled={busy} />
    <small>Copy a link to an issue and replace its ID with <code>{'{id}'}</code>.</small>
  </label>
  {#if formIssue}<div class="notice error" role="alert">{formIssue}</div>{/if}
  {#snippet actions()}
    <button type="button" class="button secondary" onclick={() => {open = false;}} disabled={busy}>Cancel</button>
    <button type="submit" class="button primary" disabled={busy}>{busy ? 'Saving…' : 'Save issue tracker'}</button>
  {/snippet}
</ConfigDialog>

<style>
  .table-wrap:focus-visible { outline-offset: -3px; }
  .table-wrap td:nth-child(3) { max-inline-size: 36rem; }
</style>
