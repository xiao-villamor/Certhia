import { classifications, type Finding } from './api.js';

export const issueTrackers = [
  ['jira', 'Jira'], ['linear', 'Linear'], ['github', 'GitHub'], ['gitlab', 'GitLab'],
  ['youtrack', 'YouTrack'], ['plane', 'Plane'], ['openproject', 'OpenProject'],
  ['redmine', 'Redmine'], ['other', 'Other']
] as const;

export interface TrackerIssue {
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
  return classifications.find(([value]) => value === status)?.[1] ?? 'Open';
}

export function trackerName(tracker: string): string {
  return issueTrackers.find(([value]) => value === tracker)?.[1] ?? 'Issue';
}
