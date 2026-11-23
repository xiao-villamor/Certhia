<script lang="ts">
  import { page } from '$app/state';
  import { productName } from '#lib/product.js';
  import StartScanForm from '#lib/StartScanForm.svelte';
  import { api, message, type ScanRetryOptions } from '#lib/api.js';

  const retry = $derived(page.url.searchParams.get('retry'));
  let original = $state<ScanRetryOptions>();
  let loading = $state(false);
  let issue = $state('');
  let attempt = $state(0);
  const mode = $derived(page.url.searchParams.get('mode') || original?.source || 'registry');
  const importing = $derived(mode === 'import');

  $effect(() => {
    void attempt;
    const id = retry;
    original = undefined; issue = ''; loading = !!id;
    if (!id) return;
    const controller = new AbortController();
    void api<ScanRetryOptions>('/scans/' + encodeURIComponent(id) + '/retry-options', {signal: controller.signal})
      .then(result => { if (!controller.signal.aborted) original = result; })
      .catch(error => { if (!controller.signal.aborted) issue = message(error); })
      .finally(() => { if (!controller.signal.aborted) loading = false; });
    return () => controller.abort();
  });
</script>

<svelte:head><title>{retry ? 'Edit and retry' : importing ? 'Import report' : 'Start scan'} · {productName}</title></svelte:head>

<div class="page-heading">
  <div><h1>{retry ? 'Edit and retry' : importing ? 'Import report' : 'Start scan'}</h1>
    <p>{retry ? 'Review the original scan settings before starting a new attempt.' : importing ? 'Attach a Trivy JSON report to an image reference.' : 'Choose an image source and the target platform.'}</p></div>
</div>

{#if retry && (loading || !original && !issue)}
  <div class="panel compact-empty" role="status">Loading the original scan settings…</div>
{:else if issue}
  <div class="notice error" role="alert">{issue} <button class="button secondary" onclick={() => attempt++}>Try again</button></div>
{:else}
  <StartScanForm initialMode={mode} initialReference={page.url.searchParams.get('image') ?? original?.reference ?? ''}
    initialRegistry={page.url.searchParams.get('registry') ?? original?.registryId ?? ''} retryOptions={original} />
{/if}
