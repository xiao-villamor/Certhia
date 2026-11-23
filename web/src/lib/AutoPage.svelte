<script lang="ts">
  let { busy, more, error, label, load, active = true }: {
    busy: boolean; more: boolean; error: string; label: string; load: () => void; active?: boolean;
  } = $props();
  let control = $state<HTMLButtonElement>();
  $effect(() => {
    if (!active || busy || error || !more || !control || typeof IntersectionObserver === 'undefined') return;
    const observer = new IntersectionObserver(entries => {
      if (entries.some(entry => entry.isIntersecting)) load();
    }, {rootMargin:'240px'});
    observer.observe(control);
    return () => observer.disconnect();
  });
</script>

{#if busy || more || error}
  <div class="panel-footer filters">
    {#if error}<p role="alert">{error}</p>{/if}
    {#if busy}<p class="field-help" role="status">Loading {label}…</p>
    {:else}
      <button type="button" class="button secondary" bind:this={control} onclick={load}>
        {error ? 'Try again' : 'Load more ' + label}
      </button>
    {/if}
  </div>
{/if}
