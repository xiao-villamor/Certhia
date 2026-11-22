<script lang="ts">
  import { ArrowUpRight } from '@lucide/svelte';
  import { trackerName, type TrackerIssue } from '#lib/tracking.js';

  let { issue }: { issue: TrackerIssue } = $props();
  const name = $derived(trackerName(issue.tracker));
</script>

<a class="table-link linked-issue" href={issue.url} target="_blank" rel="noopener noreferrer"
  aria-label={issue.key ? 'Open ' + name + ' issue ' + issue.key : 'Open ' + name + ' issue'}>
  {issue.key || (name === 'Other' ? 'Open issue' : name + ' issue')} <ArrowUpRight size={13} aria-hidden="true" />
</a>

<style>
  .linked-issue { display: inline-flex; align-items: center; gap: .22rem; overflow-wrap: anywhere; }
  .linked-issue :global(svg) { flex: none; }
</style>
