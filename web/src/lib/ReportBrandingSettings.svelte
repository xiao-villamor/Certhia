<script lang="ts">
  import { onMount } from 'svelte';
  import { Download, Image, Trash2 } from '@lucide/svelte';
  import { api, message, post } from '#lib/api.js';
  import { productName } from '#lib/product.js';

  interface Branding {
    organization: string;
    footer: string;
    hasLogo: boolean;
    sampleScanId: string | null;
  }

  const endpoint = '/settings/report-branding';
  let saved = $state<Branding>();
  let organization = $state('');
  let footer = $state('');
  let logoVersion = $state(0);
  let loading = $state(true);
  let busy = $state<'save' | 'upload' | 'remove'>();
  let issue = $state('');
  let notice = $state('');
  let logoIssue = $state(false);
  const dirty = $derived(!!saved && (organization.trim() !== saved.organization || footer.trim() !== saved.footer));

  function setBranding(result: Branding) {
    saved = result;
    organization = result.organization;
    footer = result.footer;
  }

  async function load() {
    loading = true;
    issue = '';
    try {
      setBranding(await api<Branding>(endpoint));
    } catch (error) {
      issue = message(error);
    } finally {
      loading = false;
    }
  }

  onMount(() => { void load(); });

  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (!dirty || busy) return;
    busy = 'save';
    issue = notice = '';
    try {
      setBranding(await api<Branding>(endpoint, { ...post({ organization, footer }), method: 'PUT' }));
      notice = 'Report branding saved.';
    } catch (error) {
      issue = message(error);
    } finally {
      busy = undefined;
    }
  }

  async function updateLogo(file?: File) {
    if (!saved || busy) return;
    busy = file ? 'upload' : 'remove';
    issue = notice = '';
    try {
      if (file && !['image/png', 'image/jpeg'].includes(file.type)) throw new Error('Choose a PNG or JPEG logo.');
      if (file && file.size > 1024 * 1024) throw new Error('The report logo must be 1 MB or smaller.');
      await api(endpoint + '/logo', file
        ? { method: 'PUT', headers: { 'content-type': file.type }, body: file }
        : { method: 'DELETE' });
      saved.hasLogo = !!file;
      logoIssue = false;
      logoVersion += 1;
      notice = file ? 'Report logo uploaded.' : 'Report logo removed.';
    } catch (error) {
      issue = message(error);
    } finally {
      busy = undefined;
    }
  }
</script>

{#if loading || !saved}
  <section class="panel" aria-labelledby="reports-title">
    <div class="panel-title"><h2 id="reports-title">Report branding</h2></div>
    {#if loading}<p class="compact-empty" role="status">Loading report branding…</p>
    {:else}<div class="panel-footer"><p class="notice error" role="alert">{issue}</p>
      <button type="button" class="button secondary" onclick={load}>Retry</button></div>
    {/if}
  </section>
{:else}
  <div class="reports-layout">
    <section class="panel" aria-labelledby="reports-title">
      <div class="panel-title">
        <div><h2 id="reports-title">Report branding</h2><p>Set the organization and logo for exported reports.</p></div>
      </div>
      <form class="form-panel wide" onsubmit={save}>
        <label class="field"><span>Organization name</span>
          <input type="text" maxlength="100" placeholder={productName} bind:value={organization} disabled={!!busy} />
          <small>Appears in PDF, Markdown, and Excel reports.</small>
        </label>
        <label class="field"><span>PDF footer text <small>Optional</small></span>
          <input type="text" maxlength="200" placeholder="Confidential: internal use only" bind:value={footer} disabled={!!busy} />
        </label>
        <div class="logo-field">
          <label class="field"><span>Report logo <small>Optional</small></span>
            <input type="file" accept="image/png,image/jpeg" disabled={!!busy} onchange={(event) => {
              const file = event.currentTarget.files?.[0];
              event.currentTarget.value = '';
              if (file) void updateLogo(file);
            }} />
            <small>PNG or JPEG, up to 1 MB. Uploads as soon as you choose a file.</small>
          </label>
          {#if saved.hasLogo}<button type="button" class="button secondary" disabled={!!busy} onclick={() => updateLogo()}>
            <Trash2 size={15} aria-hidden="true" /> Remove logo
          </button>{/if}
        </div>
        {#if issue}<p class="notice error" role="alert">{issue}</p>{/if}
        <div class="actions branding-actions">
          <p class="field-help" role="status">{busy === 'upload' ? 'Uploading logo…' : busy === 'remove' ? 'Removing logo…' : dirty ? 'Unsaved changes' : notice}</p>
          <button type="submit" class="button primary" disabled={!!busy || !dirty}>{busy === 'save' ? 'Saving…' : 'Save branding'}</button>
        </div>
      </form>
    </section>

    <section class="panel" aria-labelledby="report-preview-title">
      <div class="panel-title"><h2 id="report-preview-title">PDF preview</h2></div>
      <div class="panel-footer preview-body">
        <div class="report-preview">
          <div class="preview-header">
            {#if saved.hasLogo && !logoIssue}
              <img src={'/api' + endpoint + '/logo?v=' + logoVersion} alt="" onerror={() => { logoIssue = true; }} />
            {:else if logoIssue}
              <Image size={18} aria-label="Logo unavailable" />
            {/if}
            <strong>{organization.trim() || productName}</strong>
          </div>
          <p class="preview-title">Container image vulnerability report</p>
          {#if footer.trim()}<p class="preview-footer">{footer.trim()}</p>{/if}
        </div>
        {#if saved.sampleScanId && !dirty && !busy}
          <a class="button secondary" href={'/api/scans/' + saved.sampleScanId + '/report/pdf'} data-sveltekit-reload>
            <Download size={16} aria-hidden="true" /> Download sample PDF
          </a>
        {:else}
          <button type="button" class="button secondary" disabled><Download size={16} aria-hidden="true" /> Download sample PDF</button>
          {#if !saved.sampleScanId}<p class="field-help">Complete a scan to download a sample PDF.</p>
          {:else if dirty}<p class="field-help">Save your changes to download the updated PDF.</p>{/if}
        {/if}
      </div>
    </section>
  </div>
{/if}

<style>
  .reports-layout { display: grid; align-items: start; grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr); gap: 1rem; }
  .logo-field { display: flex; flex-wrap: wrap; align-items: center; gap: .75rem; }
  .logo-field .field { flex: 1 1 14rem; min-width: 0; }
  .logo-field input { width: 100%; }
  .branding-actions { justify-content: space-between; }
  .preview-body { display: grid; justify-items: start; gap: .8rem; }
  .report-preview { width: 100%; min-width: 0; border: 1px solid var(--line);
    border-radius: var(--radius); color: var(--ink); background: var(--canvas); padding: .8rem 1rem; overflow-wrap: anywhere; }
  .preview-header { display: flex; align-items: center; gap: .65rem; border-bottom: 1px solid var(--line); padding-bottom: .6rem; }
  .preview-header img { width: auto; height: auto; max-width: 5.3rem; max-height: 1.9rem; object-fit: contain; }
  .preview-title { margin-top: .75rem; font-size: 1.06rem; font-weight: 800; }
  .preview-footer { margin-top: .75rem; padding-top: .45rem; border-top: 1px solid var(--line); color: var(--muted); font-size: .77rem; }
  @media (max-width: 900px) {
    .reports-layout { grid-template-columns: minmax(0, 1fr); gap: 0; }
  }
</style>
