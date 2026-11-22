<script lang="ts">
  import { productName, productSlug } from '#lib/product.js';
  import { onMount } from 'svelte';
  import { Download, Search } from '@lucide/svelte';
  import { api, message } from '#lib/api.js';
  interface Operation { summary:string;tags:string[];parameters:{in:string;name:string;required:boolean}[];security?:Record<string,unknown>[];'x-required-role'?:string }
  let schema = $state<{info:{version:string};paths:Record<string,Record<string,Operation>>}>();
  let search = $state('');
  let issue = $state('');
  const rows = $derived(Object.entries(schema?.paths || {}).flatMap(([path,methods]) =>
    Object.entries(methods).map(([method,operation]) => ({path,method,operation}))).filter(item =>
      (item.path + item.method + item.operation.summary + item.operation.tags.join(' ')).toLowerCase().includes(search.toLowerCase())
    ));
  onMount(async () => {try {schema = await api('/openapi.json');} catch (error) {issue = message(error);}});
</script>
<svelte:head><title>API reference · {productName}</title></svelte:head>
<div class="page-heading"><div><h1>API reference</h1><p>{productName} API{schema?.info.version ? ' · ' + schema.info.version : ''}</p></div>
  <a class="button secondary" href="/api/openapi.json" download={`${productSlug}-openapi.json`} data-sveltekit-reload><Download size={16} /> OpenAPI JSON</a></div>
{#if issue}<div class="notice error" role="alert">{issue}</div>{/if}
<section class="panel"><div class="panel-title"><h2>Endpoints</h2><label class="search"><Search size={16} /><input placeholder="Filter endpoints" aria-label="Filter endpoints" bind:value={search} /></label></div>
{#each rows as item (item.method+item.path)}
  <details class="image-group endpoint"><summary>
    <span class="endpoint-route"><strong data-method={item.method}>{item.method.toUpperCase()}</strong><code class="mono break">/api{item.path}</code></span>
    <span>{item.operation.summary}</span>
  </summary>
    <div class="panel-footer">
      {#if item.operation['x-required-role']}
        <p>Requires a signed-in {item.operation['x-required-role']} or higher.</p>
      {:else if item.operation.security?.some(requirement => 'RegistryWebhookToken' in requirement)}
        <p>Requires the registry webhook token.</p>
      {/if}
      {#if item.operation.parameters.length}<ul>{#each item.operation.parameters as parameter}
        <li><code>{parameter.name}</code> · {parameter.in} {parameter.required ? '(required)' : '(optional)'}</li>
      {/each}</ul>{/if}
      {#if item.method === 'get' && !item.operation.parameters.length && !item.operation.security}
        <a class="text-button" href={'/api' + item.path} data-sveltekit-reload>Open response</a>
      {/if}
    </div>
  </details>
{:else}<div class="compact-empty">No matching endpoints.</div>{/each}
</section>

<style>
  .endpoint summary { display: grid; grid-template-columns: .42rem minmax(0, 1.1fr) minmax(0, 1fr); }
  .endpoint-route { display: flex; align-items: center; gap: .65rem; min-width: 0; }
  .endpoint-route strong { min-width: 6ch; padding: .24rem .36rem; border-radius: 3px; background: var(--inset); color: var(--muted); font-size: var(--text-detail); font-weight: 750; text-align: center; }
  .endpoint-route strong[data-method="get"] { background: var(--low-bg); color: var(--low); }
  .endpoint-route strong[data-method="post"] { background: var(--successful-bg); color: var(--successful); }
  .endpoint-route strong[data-method="delete"] { background: var(--critical-bg); color: var(--critical); }
  .endpoint summary > span:last-child { color: var(--muted); font-size: .82rem; }
  @media (max-width: 640px) {
    .endpoint summary { grid-template-columns: .42rem minmax(0, 1fr); row-gap: .35rem; }
    .endpoint summary > span:last-child { grid-column: 2; }
  }
</style>
