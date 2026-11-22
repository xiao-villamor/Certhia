<script lang="ts">
  import { ArrowUpRight } from '@lucide/svelte';
  import { advisoryDetail, referenceLabel, type AdvisoryDetail } from '#lib/advisory.js';

  /** `compact` keeps the dialog short: a clamped description and the first few references. */
  let { id, compact = false }: { id: string; compact?: boolean } = $props();
  let detail = $state<AdvisoryDetail | null>();
  let expanded = $state(false);

  $effect(() => {
    const current = id;
    detail = undefined;
    expanded = false;
    void advisoryDetail(current).then(found => { if (id === current) detail = found; });
  });

  const day = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
  const references = $derived(detail?.references ?? []);
  const shownReferences = $derived(compact && !expanded ? references.slice(0, 3) : references);
  const hasScores = $derived(!!detail && (detail.cvssScore != null || detail.epss != null || detail.kev || !!detail.publishedAt));
  const longDescription = $derived((detail?.description?.length ?? 0) > 280);
</script>

{#if detail === undefined}
  <p class="field-help" role="status">Loading advisory details…</p>
{:else if detail && (hasScores || detail.description || references.length)}
  <div class="advisory-details" class:compact>
    {#if hasScores}
      <dl class="advisory-scores">
        {#if detail.cvssScore != null}
          <div><dt>CVSS v3</dt><dd><span class="score">{detail.cvssScore.toFixed(1)}</span>{#if detail.cvssVector}<small class="mono" title={detail.cvssVector}>{detail.cvssVector.replace(/^CVSS:3\.\d\//, '')}</small>{/if}</dd></div>
        {/if}
        {#if detail.epss != null}<div><dt>EPSS</dt><dd><span class="score">{(detail.epss * 100).toFixed(detail.epss < .01 ? 2 : 1)}%</span><small>Exploit probability</small></dd></div>{/if}
        {#if detail.kev}<div><dt>Known exploited</dt><dd><span class="severity critical">CISA KEV</span></dd></div>{/if}
        {#if detail.publishedAt}<div><dt>Published</dt><dd>{day.format(new Date(detail.publishedAt))}</dd></div>{/if}
      </dl>
    {/if}
    {#if detail.description}
      <section aria-label="Advisory description">
        <h3>Description</h3>
        <p class="description" class:clamped={compact && longDescription && !expanded}>{detail.description}</p>
      </section>
    {/if}
    {#if references.length}
      <section aria-label="Advisory references">
        <h3>References</h3>
        <ul>
          {#each shownReferences as url (url)}
            <li><a href={url} target="_blank" rel="noreferrer noopener">{referenceLabel(url)} <ArrowUpRight size={13} aria-hidden="true" /></a></li>
          {/each}
        </ul>
      </section>
    {/if}
    {#if compact && !expanded && (longDescription || references.length > 3)}
      <button type="button" class="text-button more" onclick={() => { expanded = true; }}>
        Show full advisory{references.length > 3 ? ` · ${references.length} references` : ''}
      </button>
    {/if}
  </div>
{:else if !compact}
  <p class="field-help">The scanner did not record a description, scores or references for this advisory.</p>
{/if}

<style>
  .advisory-details { display: grid; gap: .9rem; }
  .advisory-scores { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 8.5rem), 1fr)); gap: .5rem; margin: 0; }
  .advisory-scores > div { display: grid; align-content: start; gap: .3rem; padding: .6rem .7rem; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); }
  .advisory-scores dt { color: var(--muted); font: 550 .66rem var(--mono); text-transform: uppercase; letter-spacing: .02em; }
  .advisory-scores dd { display: grid; gap: .2rem; justify-items: start; margin: 0; font-size: .85rem; font-weight: 750; }
  .advisory-scores small { color: var(--muted); font-size: .72rem; font-weight: 550; overflow-wrap: anywhere; }
  .score { font: 650 1.15rem/1 var(--mono); }
  h3 { margin-bottom: .35rem; font-size: .84rem; letter-spacing: -.01em; }
  .description { color: var(--ink); font-size: .86rem; white-space: pre-line; overflow-wrap: anywhere; }
  .description.clamped { display: -webkit-box; -webkit-line-clamp: 4; line-clamp: 4; -webkit-box-orient: vertical; overflow: hidden; }
  ul { display: grid; gap: .3rem; margin: 0; padding: 0; list-style: none; }
  li a { display: inline-flex; align-items: center; gap: .25rem; max-width: 100%; color: var(--accent-ink); font-size: .82rem; font-weight: 700; text-decoration: none; overflow-wrap: anywhere; }
  li a:hover { text-decoration: underline; text-underline-offset: 3px; }
  li a :global(svg) { flex: none; }
  .more { justify-self: start; padding: 0; color: var(--accent-ink); font-size: .82rem; }
</style>
