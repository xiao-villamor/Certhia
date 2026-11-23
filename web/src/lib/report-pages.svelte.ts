import { api, message } from './api.js';

export class ReportPages<T, Page extends { items: T[]; nextCursor: string | null }> {
  items = $state.raw<T[]>([]);
  first = $state.raw<Page>();
  next = $state<string | null>(null);
  busy = $state(false);
  error = $state('');
  #path = '';
  #controller: AbortController | undefined;

  open(path: string, debounce = 0) {
    this.#controller?.abort();
    this.#path = path;
    this.items = [];
    this.first = undefined;
    this.next = null;
    this.error = '';
    this.busy = Boolean(path);
    if (!path) return;
    const controller = this.#controller = new AbortController();
    const timer = setTimeout(() => void this.#load(null, controller), debounce);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }

  more() {
    if (!this.#controller || this.#controller.signal.aborted || this.busy || (this.first && !this.next)) return;
    void this.#load(this.next, this.#controller);
  }

  async #load(cursor: string | null, controller: AbortController) {
    this.busy = true;
    this.error = '';
    const url = new URL(this.#path, window.location.origin);
    if (cursor) url.searchParams.set('cursor', cursor);
    try {
      const page = await api<Page>(url.pathname + url.search, {signal: controller.signal});
      if (controller.signal.aborted) return;
      this.items = cursor ? [...this.items, ...page.items] : page.items;
      if (!cursor) this.first = page;
      this.next = page.nextCursor;
    } catch (error) {
      if (!controller.signal.aborted) this.error = message(error);
    } finally {
      if (!controller.signal.aborted) this.busy = false;
    }
  }
}
