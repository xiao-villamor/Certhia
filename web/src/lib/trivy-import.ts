import { platforms } from './api.js';

interface PlatformMetadata {
  os?: string;
  architecture?: string;
  variant?: string;
  OS?: string;
  Architecture?: string;
  Variant?: string;
  Os?: string;
}

interface TrivyDocument {
  ArtifactName?: string;
  Metadata?: {
    RepoTags?: string[];
    RepoDigests?: string[];
    ImageConfig?: PlatformMetadata;
    Platform?: string | PlatformMetadata;
    Architecture?: string;
    OS?: { Family?: string };
  };
  Platform?: string | PlatformMetadata;
}

function isReference(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 1024) return false;
  return /^(?:[\w.:[\]-]+\/)?[a-z0-9]+(?:[._/-]+[a-z0-9]+)*(?::[\w][\w.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$/.test(value)
    && !/^(?:sha256:)?[a-f0-9]{64}$/.test(value)
    && !/\.(?:tar(?:\.(?:gz|zst))?|tgz|json)$/i.test(value);
}

function platformFrom(value: string | PlatformMetadata | undefined, fallbackOS?: string) {
  if (typeof value === 'string') return value.trim().toLowerCase().replace(/^linux\/arm64\/v8$/, 'linux/arm64');
  if (!value) return '';
  const os = value.os ?? value.OS ?? value.Os ?? fallbackOS;
  const architecture = value.architecture ?? value.Architecture;
  const variant = value.variant ?? value.Variant;
  if (typeof os !== 'string' || typeof architecture !== 'string') return '';
  const base = (os + '/' + architecture).toLowerCase();
  if (base === 'linux/arm64' && (!variant || variant === 'v8')) return base;
  return typeof variant === 'string' && variant ? base + '/' + variant.toLowerCase() : base;
}

export function trivyImportDetails(raw: unknown) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Choose a Trivy container image JSON report.');
  const { ArtifactName, Metadata: metadata, Platform } = raw as TrivyDocument;
  const references = [
    ...(typeof ArtifactName === 'string' ? [ArtifactName.trim().replace(/ \([^()]*\)$/, '')] : []),
    ...(Array.isArray(metadata?.RepoTags) ? metadata.RepoTags : []),
    ...(Array.isArray(metadata?.RepoDigests) ? metadata.RepoDigests : [])
  ];
  const os = metadata?.OS?.Family;
  const linux = typeof os === 'string'
    && /^(alpine|amazon|arch|centos|debian|fedora|oracle|photon|redhat|rocky|alma|suse|ubuntu|wolfi)/i.test(os) ? 'linux' : undefined;
  const reportedPlatform = [platformFrom(metadata?.ImageConfig, linux), platformFrom(metadata?.Platform, linux),
    platformFrom(Platform, linux), platformFrom({ architecture: metadata?.Architecture }, linux)]
    .find(candidate => (platforms as readonly string[]).includes(candidate));

  return { reference: references.find(isReference) ?? '', platform: reportedPlatform ?? '' };
}
