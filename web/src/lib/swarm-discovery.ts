export type SwarmImage = {
  reference: string;
  digest?: string | null;
  registryHost?: string | null;
};

export function uniqueSwarmImages(items: SwarmImage[], registryHost?: string) {
  const images = new Map<string, SwarmImage>();
  for (const item of items) {
    if (!item.digest) continue;
    const existing = images.get(item.digest);
    if (!existing || (registryHost && item.registryHost === registryHost && existing.registryHost !== registryHost)) {
      images.set(item.digest, item);
    }
  }
  return images;
}
