import { classifications, type Finding } from './api.js';

export const issueTrackers = [
  ['jira', 'Jira'], ['linear', 'Linear'], ['github', 'GitHub'], ['gitlab', 'GitLab'],
  ['youtrack', 'YouTrack'], ['plane', 'Plane'], ['openproject', 'OpenProject'],
  ['redmine', 'Redmine'], ['other', 'Other']
] as const;

export type IssueScope = 'image' | 'advisory';
export type ExceptionScope = 'reference' | 'repository';

export interface FindingException {
  scope: ExceptionScope;
  reason: string;
  expiresAt: string;
}

export const trackingFilters = [...classifications, ['excepted', 'Excepted']] as const;

export interface TrackerIssue {
  scope?: IssueScope;
  trackerId?: string;
  tracker: string;
  url: string;
  key: string;
}

export const issueTrackersPath = '/settings/issue-trackers';

export interface IssueTracker {
  id: string;
  name: string;
  provider: string;
  urlTemplate: string;
}

export interface FindingTracking {
  finding: string;
  status: string;
  note: string;
  issue?: TrackerIssue | null;
  exception?: FindingException;
}

export interface TrackingTarget {
  scanId: string;
  reference: string;
  platform: string;
  digest?: string | null;
  finding: string;
  details: Finding[];
}

export function classificationsPath(scanId: string, finding?: string) {
  return '/scans/' + scanId + '/classifications' + (finding ? '?' + new URLSearchParams({finding}) : '');
}

export function trackingStatus(status = 'open'): string {
  return trackingFilters.find(([value]) => value === status)?.[1] ?? 'Open';
}

export function effectiveTrackingStatus(tracking?: FindingTracking): string {
  const status = tracking?.status ?? 'open';
  return status === 'open' && tracking?.exception ? 'excepted' : status;
}

export function trackerName(tracker: string): string {
  return issueTrackers.find(([value]) => value === tracker)?.[1] ?? 'Issue';
}

export function findingReportPath(scanId: string, finding: string, track = false) {
  const params = new URLSearchParams({ finding });
  if (track) params.set('track', '1');
  return '/scans/' + encodeURIComponent(scanId) + '?' + params;
}
