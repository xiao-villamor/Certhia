import type { Finding } from './api.js';
import type { TrackerIssue, TrackingTarget } from './tracking.js';

export interface Affected {
  reference: string;
  scanId: string;
  platform: string;
  digest: string;
  status: string;
  package: string;
  ecosystem?: string;
  installed?: string;
  fixed?: string;
  purl?: string | null;
  finishedAt?: string | null;
  issue?: TrackerIssue | null;
}
export interface Advisory {
  finding: Finding;
  affected: Affected[];
}

export type ImageVersion = Pick<Affected, 'reference' | 'platform' | 'digest'>;

export function imageVersionKey(image: ImageVersion) {
  return JSON.stringify([image.reference, image.platform, image.digest]);
}

export interface ImageFinding {
  key: string;
  image: Affected;
  finding: Finding;
  packages: Finding[];
}

export function findingsByImage(advisories: Advisory[]): ImageFinding[] {
  const rows = new Map<string, ImageFinding>();
  for (const {finding, affected} of advisories) {
    for (const image of affected) {
      const key = finding.id + imageVersionKey(image);
      const detail = {
        ...finding,
        package: image.package,
        ecosystem: image.ecosystem ?? finding.ecosystem,
        installed: image.installed ?? '',
        fixed: image.fixed ?? '',
        purl: image.purl ?? undefined
      };
      const row = rows.get(key);
      if (row) row.packages.push(detail);
      else rows.set(key, {key, image, finding, packages: [detail]});
    }
  }
  return [...rows.values()];
}

export function trackingTarget(row: ImageFinding): TrackingTarget {
  const {scanId, reference, platform, digest} = row.image;
  return {scanId, reference, platform, digest, finding: row.finding.id, details: row.packages};
}
