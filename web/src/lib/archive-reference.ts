const block = 512;
const decoder = new TextDecoder();
const maxSize = 2 * 1024 ** 3;

type Read = (offset: number, length: number) => Promise<Uint8Array>;

async function manifestReference(read: Read) {
  for (let offset = 0, entries = 0; offset < maxSize && entries < 50_000; entries++) {
    const data = await read(offset, block);
    if (data.length < block || data[0] === 0) break;
    const name = decoder.decode(data.subarray(0, 100)).split('\0')[0].replace(/^\.\//, '');
    const rawSize = decoder.decode(data.subarray(124, 136)).replace(/\0/g, '').trim();
    if (!/^[0-7]+$/.test(rawSize)) break;
    const size = Number.parseInt(rawSize, 8);
    if (!Number.isSafeInteger(size)) break;
    offset += block;
    if (name === 'manifest.json' && size <= 1024 ** 2) {
      const manifest: unknown = JSON.parse(decoder.decode(await read(offset, size)));
      if (!Array.isArray(manifest)) return '';
      const tags = [...new Set(manifest.flatMap(entry => Array.isArray(entry?.RepoTags) ? entry.RepoTags : []))];
      return tags.length === 1 && typeof tags[0] === 'string' && /^[a-zA-Z0-9][^\s\u0000-\u001f]{0,1023}$/.test(tags[0]) ? tags[0] : '';
    }
    offset += Math.ceil(size / block) * block;
  }
  return '';
}

export async function archiveReference(file: File, signal: AbortSignal) {
  if (file.size > maxSize) return '';
  const [first, second] = new Uint8Array(await file.slice(0, 2).arrayBuffer());
  const compressed = first === 0x1f && second === 0x8b;
  if (!compressed) {
    return manifestReference(async (offset, length) => signal.aborted ? new Uint8Array()
      : new Uint8Array(await file.slice(offset, offset + length).arrayBuffer()));
  }
  const reader = file.stream().pipeThrough(new DecompressionStream('gzip')).getReader();
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, {once:true});
  let cursor = 0;
  let chunk: Uint8Array = new Uint8Array();
  try {
    return await manifestReference(async (offset, length) => {
      const result = new Uint8Array(length);
      let written = 0;
      while (!signal.aborted && written < length) {
        if (!chunk.length) {
          const next = await reader.read();
          if (next.done) break;
          chunk = next.value;
        }
        const skip = Math.min(chunk.length, Math.max(0, offset - cursor));
        const take = Math.min(chunk.length - skip, length - written);
        result.set(chunk.subarray(skip, skip + take), written);
        written += take;
        cursor += skip + take;
        chunk = chunk.subarray(skip + take);
      }
      return result.subarray(0, written);
    });
  } finally {
    signal.removeEventListener('abort', cancel);
    await reader.cancel().catch(() => {});
  }
}
