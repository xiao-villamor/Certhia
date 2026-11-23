import { api, scannerName, type Finding } from './api.js';

type FindingIdentity = Pick<Finding, 'id' | 'ecosystem' | 'package' | 'installed' | 'purl'>;
type Detection = FindingIdentity & {scanner: string};

export function detectionKey(finding: FindingIdentity) {
  return JSON.stringify([finding.id, finding.ecosystem, finding.package, finding.installed, finding.purl ?? null]);
}

export function findingDescription(title: string): {summary: string; full?: string} {
  const summary = title.replace(/^issue summary:\s*/i, '').replace(/\s+/g, ' ').trim();
  if (summary.length <= 120) return {summary};
  const endOfWord = summary.lastIndexOf(' ', 120);
  return {summary: summary.slice(0, endOfWord > 80 ? endOfWord : 120) + '…', full: title.trim()};
}

export async function findingDetectors(scanId: string, signal: AbortSignal) {
  const rows = await api<Detection[]>('/scans/' + scanId + '/finding-sources', {signal});
  const grouped = new Map<string, Set<string>>();
  for (const row of rows) {
    const key = detectionKey(row);
    const names = grouped.get(key) ?? new Set<string>();
    names.add(scannerName(row.scanner));
    grouped.set(key, names);
  }
  return new Map([...grouped].map(([key, names]) => [key, [...names].sort()]));
}
