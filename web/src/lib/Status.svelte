<script lang="ts">
  import type { Status } from './api';
  let { status }: { status: Status } = $props();
</script>

<span class={'badge ' + status}><span class="status-dot"></span>{status}</span>
