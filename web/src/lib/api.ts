export type Status = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface Registry {
  id: string;
  name: string;
  host: string;
  authenticated: boolean;
  provider: string;
  autoSync: boolean;
  authHost: string | null;
  protocol: string;
  skipTls: boolean;
  namespace: string | null;
}

export interface Counts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  packages: number;
}

export interface Scan {
  id: string;
  reference: string;
  platform: string;
  status: Status;
  source: 'import' | 'registry' | 'docker' | 'archive' | 'kubernetes' | 'swarm';
  error: string | null;
  createdAt: string;
  finishedAt: string | null;
  counts: Counts | null;
}

export interface ScanProgress {
  id: string;
  status: Status | 'removed';
  queuePosition: number;
  startedAt?: string | null;
  activity?: { step: string; title: string; detail: string; at: string }[];
}

export interface Package {
  name: string;
  ecosystem: string;
  version: string;
}

export interface Finding {
  purl?: string;
  id: string;
  ecosystem: string;
  package: string;
  installed: string;
  fixed: string;
  severity: string;
  title: string;
}

export interface Report {
  packages: Package[];
  findings: Finding[];
  inventoryAvailable: boolean;
  digest: string | null;
  counts: Counts;
  checks: Check[];
  sizeBytes: number | null;
  os: string | null;
}

export interface Check {
  category: string;
  id: string;
  target: string;
  severity: string;
  title: string;
  detail: string;
}

export const classifications = [
  ['open', 'Open'], ['in_progress', 'In progress'], ['false_positive', 'False positive'],
  ['accepted_risk', 'Accepted risk'], ['will_not_fix', 'Will not fix'], ['fixed', 'Fixed']
];

export interface ScanDetail extends Scan {
  report: Report | null;
}

export interface ImageWatch {
  id: string;
  reference: string;
  platform: string;
  createdAt: string;
}

export interface Change {
  name: string;
  ecosystem: string;
  status: 'Added' | 'Removed' | 'Changed';
  before: string[];
  after: string[];
}

export interface Comparison {
  baseline: Scan;
  target: Scan;
  changes: { packages: Change[]; findings: Change[]; inventoryAvailable: boolean };
}

export const platforms = ['linux/amd64', 'linux/arm64', 'linux/arm/v7'];

export const scannerProviders = [
  { id: 'trivy', name: 'Trivy', purpose: 'Vulnerabilities, packages, and image checks' },
  { id: 'grype', name: 'Grype', purpose: 'Package vulnerabilities' },
  { id: 'syft', name: 'Syft', purpose: 'Package inventory and SBOM' },
  { id: 'dockle', name: 'Dockle', purpose: 'Container image checks' },
  { id: 'osv', name: 'OSV-Scanner', purpose: 'Open source vulnerabilities' },
  { id: 'dive', name: 'Dive', purpose: 'Image layers and wasted space' }
];

export interface ScannerAvailability {
  registry: string[];
  local: string[];
  defaults: string[] | null;
}

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const response = await fetch('/api' + path, init);
  if (response.status === 401 && path !== '/auth/login' && typeof window !== 'undefined') {
    const { pathname, search, hash } = window.location;
    if (!['/login', '/setup'].includes(pathname.replace(/\/$/, ''))) {
      window.location.replace('/login?' + new URLSearchParams({ next: pathname + search + hash }));
    }
  }
  if (!response.ok) {
    const data = await response.json().catch(() => null);
    throw new Error(data?.error || 'Request failed (' + response.status + ').');
  }
  return response;
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await apiFetch(path, init);
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function apiPage<T>(path: string, cursor?: string | null, init?: RequestInit) {
  const url = new URL(path, window.location.origin);
  if (cursor) url.searchParams.set('cursor', cursor);
  const response = await apiFetch(url.pathname + url.search, init);
  return {items: await response.json() as T, next: response.headers.get('x-next-cursor')};
}

export async function allPages<T>(path:string, init?:RequestInit):Promise<T[]> {
  const items:T[]=[];
  let cursor:string|null=null;
  do {
    const page: {items:T[];next:string|null}=await apiPage<T[]>(path,cursor,init);
    items.push(...page.items); cursor=page.next;
  } while(cursor);
  return items;
}

export async function registryPage(cursor?: string) {
  const query = new URLSearchParams({limit: '100'});
  if (cursor) query.set('cursor', cursor);
  const response = await apiFetch('/registries?' + query);
  return {items: await response.json() as Registry[], next: response.headers.get('x-next-cursor')};
}

export async function allRegistries(): Promise<Registry[]> {
  const items: Registry[] = [];
  let cursor: string | null = null;
  do {
    const page = await registryPage(cursor ?? undefined);
    items.push(...page.items);
    cursor = page.next;
  } while (cursor);
  return items;
}

export function post(body: unknown): RequestInit {
  return { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) };
}

export function message(error: unknown): string {
  return error instanceof Error ? error.message : 'The request could not be completed.';
}

export function active(scan: Scan): boolean {
  return scan.status === 'queued' || scan.status === 'running';
}

const date = new Intl.DateTimeFormat(undefined, {
  month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit'
});
export function time(value: string): string {
  return date.format(new Date(value));
}

export function imageName(reference: string): string {
  return reference.slice(reference.indexOf('/') + 1);
}

export function repositoryName(reference: string): string {
  if (reference.startsWith('sha256:')) return reference;
  const name = reference.split('@', 1)[0];
  const tag = name.lastIndexOf(':');
  return tag > name.lastIndexOf('/') ? name.slice(0, tag) : name;
}

export function shortDigest(digest: string): string {
  const [kind, hash = ''] = digest.split(':', 2);
  return kind === 'report' ? 'Report ' + hash.slice(0, 12) : digest.slice(0, 19);
}
