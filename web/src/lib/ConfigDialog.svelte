<script lang="ts">
  import { X } from '@lucide/svelte';
  import type { Snippet } from 'svelte';

  let { id, title, description, open, busy = false, dismiss, onsubmit, children, actions }:
    {
      id: string;
      title: string;
      description?: string;
      open: boolean;
      busy?: boolean;
      dismiss: () => void;
      onsubmit?: (event: SubmitEvent) => void;
      children: Snippet;
      actions: Snippet;
    } = $props();
  let dialog = $state<HTMLDialogElement>();

  $effect(() => {
    if (open && dialog && !dialog.open) {
      dialog.showModal();
      dialog.querySelector<HTMLElement>('input:not([type="hidden"]):not([type="radio"]):not([readonly]), select, textarea')?.focus();
    } else if (!open && dialog?.open) {
      dialog.close();
    }
  });
</script>

<dialog {id} bind:this={dialog} aria-labelledby={id + '-title'}
  aria-describedby={description ? id + '-description' : undefined}
  oncancel={(event) => {event.preventDefault(); if (!busy) dismiss();}}>
  {#if open}
    <form onsubmit={onsubmit ?? ((event) => event.preventDefault())}>
      <header>
        <div>
          <h2 id={id + '-title'}>{title}</h2>
          {#if description}<p id={id + '-description'} class="field-help">{description}</p>{/if}
        </div>
        <button type="button" class="button secondary close" aria-label="Close dialog" disabled={busy} onclick={dismiss}>
          <X size={19} aria-hidden="true" />
        </button>
      </header>
      <div class="form-panel wide body">{@render children()}</div>
      <footer class="actions">{@render actions()}</footer>
    </form>
  {/if}
</dialog>

<style>
  dialog {
    width: min(39rem, calc(100% - 2rem));
    max-height: min(47rem, calc(100dvh - 2rem));
    margin: auto;
    padding: 0;
    overflow: hidden;
    color: var(--ink);
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: calc(var(--radius) * 2);
    box-shadow: 0 1rem 3rem color-mix(in srgb, var(--rail) 25%, transparent);
  }
  dialog::backdrop { background: color-mix(in srgb, var(--rail) 66%, transparent); }
  form { display: flex; flex-direction: column; max-height: inherit; }
  header, footer { flex: none; padding: .9rem 1.3rem; }
  header { display: flex; justify-content: space-between; align-items: start; gap: 1rem; border-bottom: 1px solid var(--line); }
  header p { margin-top: .25rem; }
  footer { border-top: 1px solid var(--line); background: var(--canvas); }
  .body { min-height: 0; overflow-y: auto; overscroll-behavior: contain; padding: 1.2rem 1.3rem; }
  .close { flex: none; justify-content: center; min-width: 2.4rem; padding-inline: .45rem; }
  @media (prefers-reduced-motion: no-preference) {
    dialog[open] { animation: dialog-enter 180ms cubic-bezier(.16, 1, .3, 1) both; }
    dialog[open]::backdrop { animation: backdrop-enter 150ms ease-out both; }
  }
  @keyframes dialog-enter { from { transform: translateY(8px) scale(.99); } }
  @keyframes backdrop-enter { from { opacity: 0; } }
  @media (max-width: 480px) {
    header, footer, .body { padding-inline: 1rem; }
  }
</style>
