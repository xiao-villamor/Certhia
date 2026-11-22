<script lang="ts">
  import { page } from '$app/state';
  import { productName } from '#lib/product.js';
  import StartScanForm from '#lib/StartScanForm.svelte';

  const mode = $derived(page.url.searchParams.get('mode') || 'registry');
  const importing = $derived(mode === 'import');
</script>

<svelte:head><title>{importing ? 'Import report' : 'Start scan'} · {productName}</title></svelte:head>

<div class="page-heading">
  <div><h1>{importing ? 'Import report' : 'Start scan'}</h1><p>{importing ? 'Attach a Trivy JSON report to an image reference.' : 'Choose an image source and the target platform.'}</p></div>
</div>

<StartScanForm initialMode={mode} initialReference={page.url.searchParams.get('image') ?? ''}
  initialRegistry={page.url.searchParams.get('registry') ?? ''} />
