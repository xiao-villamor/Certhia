import { productSlug } from '#lib/product.js';

export const findingColumns = [
  { id: 'package', label: 'Package' },
  { id: 'installed', label: 'Installed version' },
  { id: 'fix', label: 'Fix available' },
  { id: 'scanners', label: 'Detected by' },
  { id: 'tracking', label: 'Tracking status' },
  { id: 'issue', label: 'Linked issue' }
] as const;

export type FindingColumn = (typeof findingColumns)[number]['id'];
export const defaultFindingColumns: FindingColumn[] = ['package', 'installed', 'fix', 'tracking', 'issue'];
const storageKey = `${productSlug}.finding-columns`;

export function readFindingColumns(): FindingColumn[] {
  try {
    const saved = localStorage.getItem(storageKey);
    const values: unknown = JSON.parse(saved ?? 'null');
    if (Array.isArray(values)) {
      return findingColumns.filter(column => values.includes(column.id)).map(column => column.id);
    }
  } catch {
    // Report tables can still use their defaults when browser storage is unavailable.
  }
  return [...defaultFindingColumns];
}

export function saveFindingColumns(columns: FindingColumn[]) {
  localStorage.setItem(storageKey, JSON.stringify(columns));
}
