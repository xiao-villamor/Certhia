<script lang="ts">
  import { afterNavigate } from '$app/navigation';
  import { page } from '$app/state';
  import { tick } from 'svelte';
  import { api, message } from '#lib/api.js';
  import { auth, loadSession } from '#lib/auth.svelte.js';
  import {
    Activity, Boxes, CalendarClock, CodeXml, Database, GitCompareArrows,
    LayoutDashboard, Menu, Plus, Settings2, ShieldAlert, UserRound, Wrench, X
  } from '@lucide/svelte';
  import { productName } from '#lib/product.js';
  import StartScanForm from '#lib/StartScanForm.svelte';
  import './app.css';

  let { children } = $props();
  let navigation = $state<HTMLDialogElement>();
  let scanOpen = $state(false);
  let issue = $state('');
  let signingOut = $state(false);
  let accountMenu = $state<HTMLDetailsElement>();

  async function checkSession() {
    issue = '';
    try { await loadSession(); }
    catch (error) { issue = message(error); }
  }

  async function logout() {
    signingOut = true;
    issue = '';
    try {
      await api('/auth/logout', { method: 'POST' });
      window.location.replace('/login');
    } catch (error) {
      issue = message(error);
      signingOut = false;
    }
  }


  let scanTrigger: HTMLElement | null;

  function startScan(event: MouseEvent) {
    const opener = event.currentTarget as HTMLElement;
    scanTrigger = navigation?.open ? document.querySelector('.mobile-scan-entry') : opener;
    navigation?.close();
    scanOpen = true;
  }

  async function dismissScan() {
    scanOpen = false;
    await tick();
    scanTrigger?.focus();
  }

  const groups = [
    { label: 'Monitor', links: [
      { href: '/', label: 'Scan desk', icon: LayoutDashboard },
      { href: '/images', label: 'Image catalog', icon: Boxes },
      { href: '/library', label: 'Vulnerabilities', icon: ShieldAlert }
    ] },
    { label: 'Scan infrastructure', links: [
      { href: '/scheduled-scans', label: 'Scan schedules', icon: CalendarClock },
      { href: '/registries', label: 'Registry connections', icon: Database, role: 'operator' }
    ] },
    { label: 'Reports & patches', links: [
      { href: '/compare', label: 'Report comparison', icon: GitCompareArrows },
      { href: '/patches', label: 'Patch builder', icon: Wrench }
    ] },
    { label: 'Workspace', links: [
      { href: '/audit-logs', label: 'Activity history', icon: Activity, role: 'admin' },
      { href: '/settings', label: 'Workspace preferences', icon: Settings2, role: 'admin' },
      { href: '/api-reference', label: 'API reference', icon: CodeXml }
    ] }
  ];

  const path = $derived(page.url.pathname.replace(/\/$/, '') || '/');
  const entry = $derived(path === '/login' || path === '/setup' || path === '/welcome');
  const restricted = $derived((path === '/audit-logs' && !auth.admin)
    || (['/settings', '/registries', '/scans/new', '/scans/bulk'].includes(path) && !auth.operator));
  const section = $derived.by(() => {
    for (const group of groups) {
      const link = group.links.find(({ href }) =>
        path === href || (href === '/' ? path.startsWith('/scans/') : path.startsWith(href + '/'))
      );
      if (link) return { group: group.label, ...link };
    }
  });
  const pageLabel = $derived.by(() => {
    if (page.error) return page.status === 404 ? 'Page not found' : 'Something went wrong';
    if (path === '/account') return 'Your account';
    if (path === '/scans/new') return page.url.searchParams.get('mode') === 'import' ? 'Import report' : 'Start scan';
    if (path === '/scans/bulk') return 'Batch scans';
    if (path.startsWith('/scans/')) return 'Scan report';
    if (path.startsWith('/library/')) return 'Advisory details';
    return section?.label;
  });

  afterNavigate(() => {
    navigation?.close();
    if (accountMenu) accountMenu.open = false;
    scanOpen = false;
    if (!entry && !auth.session && !issue) void checkSession();
  });
</script>

<svelte:head>
  <title>{productName}</title>
  <meta name="description" content="Scan container images, manage registries, and compare security reports." />
</svelte:head>

{#snippet brand()}
  <a class="brand" href="/" aria-label={`${productName} scan desk`}>
    <img class="brand-mark" src="/certhia.png" width="36" height="36" alt="" />
    <span>{productName}</span>
  </a>
{/snippet}

{#snippet navigationLinks()}
  {#if auth.operator}<button type="button" class="button primary scan-entry" aria-haspopup="dialog" onclick={startScan}>
    <Plus size={18} aria-hidden="true" /> Start scan
  </button>{/if}
  <nav class="nav-groups" aria-label="Main navigation">
    {#each groups as group (group.label)}
      <div class="nav-group">
        <p>{group.label}</p>
        <ul>
          {#each group.links.filter(link => !link.role || (link.role === 'admin' ? auth.admin : auth.operator)) as link (link.href)}
            <li><a href={link.href} class:current={section?.href === link.href} onclick={() => navigation?.close()}
              aria-current={section?.href === link.href ? (link.href === path ? 'page' : 'location') : undefined}>
              <link.icon size={16} aria-hidden="true" />{link.label}
            </a></li>
          {/each}
        </ul>
      </div>
    {/each}
  </nav>
{/snippet}

{#if entry}
  {@render children()}
{:else if !auth.session}
  <main class="content">
    {#if issue}
      <div class="notice error" role="alert">{issue}</div>
      <button class="button secondary" onclick={checkSession}>Retry</button>
    {:else}
      <p role="status">Checking your session…</p>
    {/if}
  </main>
{:else}
<a class="skip-link" href="#main">Skip to content</a>
<div class="shell">
  <aside class="sidebar">
    {@render brand()}
    {@render navigationLinks()}
    <div class="sidebar-foot"><span aria-hidden="true"></span>Local workspace</div>
  </aside>

  <div class="workspace">
    <header class="topbar">
      <button class="button secondary menu-toggle" type="button" aria-haspopup="dialog" aria-controls="mobile-navigation"
        onclick={() => navigation?.showModal()}><Menu size={18} aria-hidden="true" /> Menu</button>
      <div class="topbar-path">
        {#if section}<span class="path-group">{section.group}</span><span class="path-divider" aria-hidden="true">/</span>{/if}
        <span>{pageLabel ?? productName}</span>
      </div>
      {#if auth.operator}<button type="button" class="button primary mobile-scan-entry" aria-haspopup="dialog" onclick={startScan}><Plus size={16} aria-hidden="true" /> Start scan</button>{/if}
      <details class="account-menu" bind:this={accountMenu}>
        <summary class="button secondary" aria-label="Account menu">
          <UserRound size={16} aria-hidden="true" /><span>{auth.session.user.displayName}</span>
        </summary>
        <div class="account-options">
          <p><strong>{auth.session.user.displayName}</strong><small>{auth.session.user.role}</small></p>
          <a class="button secondary" href="/account">Your account</a>
          <button class="button secondary" disabled={signingOut} onclick={logout}>Sign out</button>
        </div>
      </details>
    </header>
    <main id="main" class="content" tabindex="-1">
      {#if issue}<div class="notice error" role="alert">{issue}</div>{/if}
      {#if restricted}
        <div class="page-heading"><div><h1>Access restricted</h1><p>Your role does not allow access to this page.</p></div></div>
        <a class="button secondary" href="/">Back to the scan desk</a>
      {:else}
        {@render children()}
      {/if}
    </main>
  </div>

  <dialog class="nav-dialog" id="mobile-navigation" aria-label="Workspace navigation" bind:this={navigation}>
    <div class="sidebar drawer">
      <div class="drawer-heading">
        {@render brand()}
        <button class="drawer-close" type="button" aria-label="Close menu" onclick={() => navigation?.close()}><X size={21} aria-hidden="true" /></button>
      </div>
      {@render navigationLinks()}
      <div class="sidebar-foot"><span aria-hidden="true"></span>Local workspace</div>
    </div>
  </dialog>
</div>

{#if scanOpen}<StartScanForm dismiss={dismissScan} />{/if}

{/if}

<style>
  .account-menu { position: relative; margin-inline-start: auto; flex: none; }
  .account-menu summary { list-style: none; cursor: pointer; }
  .account-menu summary::-webkit-details-marker { display: none; }
  .account-menu summary span { max-width: 10rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .account-options { position: absolute; z-index: 5; inset: calc(100% + .45rem) 0 auto auto; width: 12.5rem;
    display: grid; gap: .45rem; padding: .65rem; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); }
  .account-options p { padding: .25rem; overflow-wrap: anywhere; }
  .account-options small { display: block; text-transform: capitalize; color: var(--muted); }
  @media (max-width: 42rem) { .account-menu summary span { display: none; } }
</style>
