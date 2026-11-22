<script lang="ts">
  import type { Snippet } from 'svelte';
  import { productName } from './product.js';

  let { title, labelledby, wide = false, children }:
    { title: string; labelledby: string; wide?: boolean; children: Snippet } = $props();
</script>

<svelte:head><title>{title} · {productName}</title></svelte:head>

<main class="entry-page">
  <div class="entry-form">
    <div class="entry-brand">
      <img src="/certhia.png" width="28" height="28" alt="" />
      <span>{productName}</span>
    </div>
    <section class="entry-column" class:wide aria-labelledby={labelledby}>
      {@render children()}
    </section>
  </div>
  <aside class="entry-product" aria-hidden="true">
    <p class="entry-pitch">Scan container images, compare versions, and track remediation.</p>
    <div class="entry-preview">
      <div class="entry-row"><code>registry/payments:1.4.2</code><span class="pill critical">3 critical</span><span>before</span></div>
      <div class="entry-row"><code>registry/payments:1.4.3</code><span class="pill clear">0 critical</span><span>after</span></div>
    </div>
  </aside>
</main>

<style>
  .entry-page { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); min-height: 100dvh; background: var(--surface); }
  .entry-form { display: grid; grid-template-rows: auto 1fr; padding: 2rem clamp(1rem, 4vw, 3rem); }
  .entry-brand { display: flex; align-items: center; gap: .6rem; font-weight: 800; font-size: 1.05rem; color: var(--ink); }
  .entry-column {
    align-self: center; justify-self: center; width: min(100%, 24rem);
    display: grid; gap: 1.05rem; padding-block: 2rem 4rem;
  }
  .entry-column.wide { width: min(100%, 30rem); }
  .entry-column :global(h1) { font-size: 1.55rem; line-height: 1.15; }
  .entry-column :global(> p) { color: var(--muted); }
  .entry-column :global(.notice) { margin: 0; }
  .entry-product {
    display: grid; align-content: center; gap: 1.5rem; padding: 3rem clamp(2rem, 5vw, 4rem);
    background: var(--rail); color: var(--rail-text);
  }
  .entry-pitch { max-width: 26rem; font-size: 1.35rem; font-weight: 800; line-height: 1.3; }
  .entry-preview {
    display: grid; gap: .6rem; padding: 1rem; border: 1px solid var(--rail-line);
    border-radius: var(--radius); background: var(--rail-surface);
  }
  .entry-row {
    display: grid; grid-template-columns: minmax(0, 1fr) auto auto; align-items: center; gap: .75rem;
    padding: .55rem .7rem; border-radius: calc(var(--radius) - 2px); background: var(--rail);
    font-size: var(--text-label); color: var(--rail-muted);
  }
  .entry-row code { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--mono); color: var(--rail-text); }
  .pill { padding: .15rem .5rem; border-radius: 999px; font-size: .72rem; font-weight: 800; }
  .pill.critical { background: var(--critical-bg); color: var(--critical); }
  .pill.clear { background: var(--successful-bg); color: var(--successful); }
  @media (max-width: 56rem) {
    .entry-page { grid-template-columns: minmax(0, 1fr); }
    .entry-product { display: none; }
  }
</style>
