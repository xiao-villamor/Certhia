<script lang="ts">
  import { page } from '$app/state';
  import { ArrowLeft, Compass } from '@lucide/svelte';
  import { productName } from '#lib/product.js';

  const missing = $derived(page.status === 404);
</script>

<svelte:head><title>{missing ? 'Page not found' : 'Error'} · {productName}</title></svelte:head>

<section class="panel" aria-labelledby="error-title">
  <div class="empty">
    <span class="empty-icon" aria-hidden="true"><Compass size={20} /></span>
    <h1 id="error-title">{missing ? 'Page not found' : 'Something went wrong'}</h1>
    <p>{missing
      ? 'This address does not match a page in the workspace. Check the link or go back to the scan desk.'
      : page.error?.message || 'The page could not be loaded.'}</p>
    <p class="mono">{page.url.pathname}</p>
    <a class="button primary" href="/"><ArrowLeft size={16} aria-hidden="true" /> Back to scan desk</a>
  </div>
</section>

<style>
  h1 { color: var(--ink); font-size: 1.35rem; letter-spacing: -.035em; }
  p { max-width: 34rem; }
</style>
