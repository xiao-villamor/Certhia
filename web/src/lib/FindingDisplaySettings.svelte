<script lang="ts">
  import { onMount } from 'svelte';
  import { defaultFindingColumns, findingColumns, readFindingColumns, saveFindingColumns, type FindingColumn } from './finding-columns.js';

  let selected = $state<FindingColumn[]>([]);
  let notice = $state('');
  let issue = $state('');

  onMount(() => { selected = readFindingColumns(); });

  function save(columns: FindingColumn[]) {
    try {
      saveFindingColumns(columns);
      selected = columns;
      issue = '';
      notice = 'Findings columns saved.';
    } catch {
      selected = readFindingColumns();
      notice = '';
      issue = 'Could not save your columns in this browser.';
    }
  }
</script>

<section class="panel" aria-labelledby="finding-display-title">
  <div class="panel-title">
    <div><h2 id="finding-display-title">Findings columns</h2><p>Choose what appears in scan reports on this browser. Finding and severity are always visible.</p></div>
  </div>
  <div class="form-panel wide">
    <div class="column-options" role="group" aria-label="Optional findings columns">
      {#each findingColumns as column (column.id)}
        <label class="inline-check">
          <input type="checkbox" checked={selected.includes(column.id)}
            onchange={(event) => save(event.currentTarget.checked ? [...selected, column.id] : selected.filter(id => id !== column.id))} />
          {column.label}
        </label>
      {/each}
    </div>
    {#if issue}<p class="notice error" role="alert">{issue}</p>{/if}
    <div class="actions">
      {#if notice}<p class="field-help" role="status">{notice}</p>{/if}
      <button type="button" class="button secondary" onclick={() => save([...defaultFindingColumns])}>Restore default columns</button>
    </div>
  </div>
</section>

<style>
  .column-options { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 12rem), 1fr)); gap: .5rem; }
  .column-options label { padding: .45rem .65rem; border: 1px solid var(--line); border-radius: var(--radius); }
  .column-options label:has(input:checked) { background: var(--accent-soft); }
  .actions { justify-content: space-between; }
</style>
