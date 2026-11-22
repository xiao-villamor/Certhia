import { api } from './api.js';

export const roles = ['viewer', 'operator', 'admin'] as const;
export type Role = typeof roles[number];

export interface User {
  id: string;
  email: string;
  displayName: string;
  role: Role;
  disabled: boolean;
  hasPassword: boolean;
}

interface Session {
  user: User;
  local: boolean;
  oidcEmailLinking: boolean;
}

export interface AuthStatus {
  local: boolean;
  setupRequired: boolean;
  providers: { id: string; name: string }[];
}

let session = $state<Session>();
export const auth = {
  get session() { return session; },
  get admin() { return session?.user.role === 'admin'; },
  get operator() { return session?.user.role === 'operator' || session?.user.role === 'admin'; }
};

export async function loadSession() {
  session = await api<Session>('/auth/me');
}

export function returnPath(url: URL) {
  const next = url.searchParams.get('next');
  if (!next?.startsWith('/') || next.startsWith('//') || next.includes('\\')) return '/';
  const target = new URL(next, url.origin);
  if (target.origin !== url.origin || ['/login', '/setup'].includes(target.pathname)
    || target.pathname.startsWith('/api/')) return '/';
  return target.pathname + target.search + target.hash;
}
