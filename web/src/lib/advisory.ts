import { api } from './api.js';

export interface AdvisoryDetail {
  id: string;
  source: string;
  severity: string;
  summary: string | null;
  description: string | null;
  cvssScore: number | null;
  cvssVector: string | null;
  epss: number | null;
  kev: boolean | null;
  references: string[];
  publishedAt: string | null;
  modifiedAt: string | null;
}

const cache = new Map<string, Promise<AdvisoryDetail | null>>();

/** Advisory metadata changes only on report import, so one request per session is enough. */
export function advisoryDetail(id: string): Promise<AdvisoryDetail | null> {
  let request = cache.get(id);
  if (!request) {
    request = api<AdvisoryDetail>('/advisories/' + encodeURIComponent(id)).catch(() => {
      cache.delete(id);
      return null;
    });
    cache.set(id, request);
  }
  return request;
}

export function referenceLabel(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname.replace(/^www\./, '') + (parsed.pathname.length > 1 ? parsed.pathname.replace(/\/$/, '') : '');
  } catch {
    return url;
  }
}
