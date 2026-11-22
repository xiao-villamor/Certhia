<script lang="ts">
  import { auth } from '#lib/auth.svelte.js';
  import { productName } from '#lib/product.js';
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { CalendarClock, Pencil, Play, Plus, Trash2 } from '@lucide/svelte';
  import ConfigDialog from '#lib/ConfigDialog.svelte';
  import { api, apiPage, message, platforms, post, time, type Registry, allRegistries } from '#lib/api.js';

  type Mode = 'specific' | 'pattern' | 'all' | 'kubernetes';
  interface Schedule { id:string; name:string; reference:string; platform:string; registryId:string|null; expression:string; enabled:boolean; dueAt:string; mode:Mode; references:string[]; imagePattern:string; tagPattern:string; excludeTagPattern:string; retainSbom:boolean; kubernetesNamespace?:string; }
  interface History { id:string; name:string; scanId:string|null; createdAt:string; trigger:string; status:string; }
  const initial = { name:'', reference:'', platform:'linux/amd64', registryId:'', expression:'0 3 * * *', enabled:true, mode:'specific' as Mode, imagePattern:'', tagPattern:'', excludeTagPattern:'', retainSbom:false, kubernetesNamespace:'' };
  let saved = $state<Schedule[]>([]);
  let history = $state<History[]>([]);
  let registries = $state<Registry[]>([]);
  let form = $state({...initial});
  let id = $state('');
  let open = $state(false);
  let busy = $state(false);
  let loading = $state(true);
  let issue = $state('');
  let formIssue = $state('');
  let notice = $state('');
  let recent = $state('');

  let nextSchedules=$state<string|null>(null);
  let nextHistory=$state<string|null>(null);
  async function moreSchedules(){
    if(nextSchedules){const p=await apiPage<Schedule[]>('/scheduled-scans',nextSchedules);saved=[...saved,...p.items];nextSchedules=p.next;}
  }
  async function moreHistory(){
    if(nextHistory){const p=await apiPage<History[]>('/scheduled-scans/history',nextHistory);history=[...history,...p.items];nextHistory=p.next;}
  }
  async function refresh() {
    try {
      const [s,h] = await Promise.all([apiPage<Schedule[]>('/scheduled-scans'), apiPage<History[]>('/scheduled-scans/history')]);
      saved=s.items;nextSchedules=s.next;history=h.items;nextHistory=h.next;
    } catch (error) { issue = message(error); }
    finally { loading = false; }
  }
  onMount(() => {
    void refresh();
    const image = page.url.searchParams.get('image');
    const platform = page.url.searchParams.get('platform');
    if (image && auth.operator) {
      edit();
      form.reference = image;
      if (platform && platforms.includes(platform)) form.platform = platform;
    }
    if (auth.operator) void allRegistries().then(data => {registries = data;}).catch(error => {issue = message(error);});
    const timer = setInterval(() => {if (history.some(run => run.status === 'queued' || run.status === 'running')) void refresh();}, 3000);
    return () => clearInterval(timer);
  });

  function edit(item?: Schedule) {
    id = item?.id ?? '';
    form = item ? { name:item.name, reference:item.references.length ? item.references.join('\n') : item.reference, platform:item.platform, registryId:item.registryId || '', expression:item.expression, enabled:item.enabled, mode:item.mode, imagePattern:item.imagePattern, tagPattern:item.tagPattern, excludeTagPattern:item.excludeTagPattern, retainSbom:item.retainSbom ?? false, kubernetesNamespace:item.kubernetesNamespace ?? '' } : {...initial};
    open = true;
    formIssue = ''; issue = ''; notice = ''; recent = '';
  }
  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    busy = true; formIssue = '';
    try {
      await api('/scheduled-scans' + (id ? '/' + id : ''), {...post({...form, references:form.mode === 'specific' ? form.reference.split(/\r?\n/).map(value => value.trim()).filter(Boolean) : [], registryId:form.registryId || null}), method:id ? 'PUT' : 'POST'});
      open = false;
      await refresh();
      notice = 'Schedule saved.';
    } catch (error) {formIssue = message(error);}
    finally {busy = false;}
  }
  async function run(item: Schedule) {
    busy = true; issue = ''; notice = '';
    try {
      const result = await api<{id:string|null; scanIds:string[]}>('/scheduled-scans/' + item.id + '/execute', post({}));
      recent = result.scanIds.length === 1 ? (result.id ?? '') : '';
      notice = result.scanIds.length ? `${result.scanIds.length} scan${result.scanIds.length === 1 ? '' : 's'} queued.` : item.mode === 'kubernetes' ? 'No new runtime image digests were observed.' : 'No tracked images matched this schedule.';
      await refresh();
    } catch (error) {issue = message(error);}
    finally {busy = false;}
  }
  async function toggle(item: Schedule) {
    busy = true; issue = ''; notice = '';
    try {
      await api('/scheduled-scans/' + item.id, { ...post({...item, enabled:!item.enabled}), method:'PUT' });
      await refresh();
    } catch (error) {issue = message(error);}
    finally {busy = false;}
  }
  async function remove(item: Schedule) {
    if (!confirm('Delete schedule ' + item.name + '?')) return;
    busy = true; issue = ''; notice = '';
    try {
      await api('/scheduled-scans/' + item.id, {method:'DELETE'});
      await refresh();
    } catch (error) {issue = message(error);}
    finally {busy = false;}
  }
</script>
<svelte:head><title>Scan schedules · {productName}</title></svelte:head>
<div class="page-heading"><div><h1>Scan schedules</h1><p>Run recurring scans for images you track.</p></div>
  {#if auth.operator}<button class="button primary" onclick={() => edit()} aria-haspopup="dialog" disabled={busy}><Plus size={17} /> Add schedule</button>{/if}</div>
{#if issue}<div class="notice error" role="alert">{issue}</div>{/if}
{#if notice}<div class="notice success" role="status">{notice}{#if recent} <a href={'/scans/' + recent}>Open scan</a>{/if}</div>{/if}
<ConfigDialog id="schedule-editor" title={id ? 'Edit schedule' : 'Add schedule'} {open} {busy}
  dismiss={() => {open = false;}} onsubmit={save}>
    <div class="form-grid">
    <label class="field"><span>Name</span><input required maxlength="100" bind:value={form.name} /></label>
    <label class="field"><span>Image selection</span><select bind:value={form.mode}><option value="specific">Specific images</option><option value="pattern">Match images and tags</option><option value="all">All tracked images</option><option value="kubernetes">Kubernetes digest changes</option></select></label>
    </div>
    {#if form.mode === 'specific'}
    <label class="field"><span>Image references</span><textarea required class="mono" rows="3" bind:value={form.reference} placeholder="registry.example.com/team/image:tag"></textarea><small>Enter one reference per line.</small></label>
    <div class="form-grid">
      <label class="field"><span>Platform</span><select bind:value={form.platform}>{#each platforms as value}<option>{value}</option>{/each}</select></label>
      <label class="field"><span>Registry credentials</span><select bind:value={form.registryId}><option value="">Public image</option>
      {#each registries as registry}<option value={registry.id}>{registry.name}</option>{/each}</select></label>
    </div>
    {:else if form.mode === 'kubernetes'}
    <label class="field"><span>Namespace</span><input bind:value={form.kubernetesNamespace} maxlength="63" placeholder="All namespaces" />
      <small>Enter a namespace if the Kubernetes connection has namespace-only permissions.</small>
    </label>
    <div class="form-grid">
      <label class="field"><span>Platform</span><select bind:value={form.platform}>{#each platforms as value}<option>{value}</option>{/each}</select></label>
      <label class="field"><span>Registry connection</span><select bind:value={form.registryId}><option value="">Public registries</option>
        {#each registries as registry}<option value={registry.id}>{registry.name}</option>{/each}
      </select><small>A saved connection limits the schedule to its registry host.</small></label>
    </div>
    {:else if form.mode === 'pattern'}
    <label class="field"><span>Image pattern</span><input bind:value={form.imagePattern} maxlength="250" placeholder="team/(api|worker)$" /></label>
    <div class="form-grid">
      <label class="field"><span>Include tags</span><input bind:value={form.tagPattern} maxlength="250" placeholder="^(latest|stable)$" /></label>
      <label class="field"><span>Exclude tags</span><input bind:value={form.excludeTagPattern} maxlength="250" placeholder="^(dev|test)$" /></label>
    </div>
    {/if}
    <label class="field"><span>UTC cron expression</span><input required class="mono" maxlength="120" bind:value={form.expression} /><small>For example, 0 3 * * * runs daily at 03:00 UTC.</small></label>
    <label class="inline-check"><input type="checkbox" bind:checked={form.enabled} /> Enable schedule</label>
    <label class="inline-check"><input type="checkbox" bind:checked={form.retainSbom} /> Retain a CycloneDX SBOM for each scan with package inventory</label>
    {#if formIssue}<div class="notice error" role="alert">{formIssue}</div>{/if}
    {#snippet actions()}
      <button type="button" class="button secondary" disabled={busy} onclick={() => {open = false;}}>Cancel</button>
      <button type="submit" class="button primary" disabled={busy}>{busy ? 'Saving…' : 'Save schedule'}</button>
    {/snippet}
</ConfigDialog>
<section class="panel"><div class="panel-title"><h2>Recurring scans</h2></div>
  {#if loading}<div class="empty" role="status">Loading schedules…</div>
  {:else if !saved.length}<div class="empty"><span class="empty-icon"><CalendarClock size={26} /></span><h3>No scheduled scans</h3>
    <p>Rescan specific images, every tracked image, or tags that match a pattern on a recurring schedule.</p>
    {#if auth.operator}<button class="button secondary" onclick={() => edit()} aria-haspopup="dialog" disabled={busy}><Plus size={16} aria-hidden="true" /> Add schedule</button>{/if}</div>
  {:else}<div class="table-wrap"><table><thead><tr><th>Schedule</th><th>Image</th><th>Next run</th>{#if auth.operator}<th>Actions</th>{/if}</tr></thead>
    <tbody>{#each saved as item (item.id)}<tr><td><strong>{item.name}</strong><small class="mono">{item.expression}</small></td>
      <td class="mono">{item.mode === 'all' ? 'All tracked images' : item.mode === 'pattern' ? (item.imagePattern || 'Tag rules') : item.mode === 'kubernetes' ? ('Kubernetes · ' + (item.kubernetesNamespace || 'All namespaces')) : item.references.length > 1 ? item.references.length + ' images' : item.reference}</td><td>{item.enabled ? time(item.dueAt) : 'Disabled'}</td>
      {#if auth.operator}<td><div class="filters">
        <button class="button secondary" onclick={() => run(item)} disabled={busy}><Play size={16} /> Run now</button>
        <button class="button secondary" onclick={() => toggle(item)} disabled={busy}>{item.enabled ? 'Disable' : 'Enable'}</button>
        <button class="button secondary" onclick={() => edit(item)} aria-haspopup="dialog" disabled={busy}><Pencil size={16} /> Edit</button>
        <button class="icon-button" aria-label={'Delete ' + item.name} onclick={() => remove(item)} disabled={busy}><Trash2 size={16} /></button>
      </div></td>{/if}</tr>{/each}</tbody></table></div>{/if}
{#if nextSchedules}<button class="button secondary" onclick={moreSchedules}>Load more schedules</button>{/if}
</section>
<section class="panel"><div class="panel-title"><h2>Execution history</h2></div>
  <div class="table-wrap"><table><thead><tr><th>Schedule</th><th>Trigger</th><th>Status</th><th>Queued</th></tr></thead>
    <tbody>{#each history as run (run.id + (run.scanId ?? ''))}<tr><td>{run.name}</td><td>{run.trigger}</td>
      <td>{#if run.status === 'removed'}Removed{:else if run.status === 'no_matches'}No images queued{:else}<a class="table-link" href={'/scans/' + run.scanId}>{run.status}</a>{/if}</td><td>{time(run.createdAt)}</td></tr>
      {:else}<tr><td colspan="4">No scheduled runs yet.</td></tr>{/each}</tbody></table></div>
{#if nextHistory}<button class="button secondary" onclick={moreHistory}>Load more runs</button>{/if}
</section>
