import assert from 'node:assert/strict';
import { test } from 'node:test';
import { uniqueSwarmImages } from '../web/src/lib/swarm-discovery.ts';

test('Swarm bulk discovery selects one reference per digest and skips tag-only services', () => {
  const first = 'sha256:' + 'a'.repeat(64);
  const second = 'sha256:' + 'b'.repeat(64);
  const publicCopy = { reference: 'public.test/api@' + first, digest: first, registryHost: 'public.test' };
  const privateCopy = { reference: 'private.test/api:stable@' + first, digest: first, registryHost: 'private.test' };
  const worker = { reference: 'public.test/worker@' + second, digest: second, registryHost: 'public.test' };
  const tagOnly = { reference: 'private.test/api:latest', digest: null, registryHost: 'private.test' };
  const discovered = [publicCopy, worker, privateCopy, tagOnly];

  assert.deepEqual([...uniqueSwarmImages(discovered).values()], [publicCopy, worker]);
  assert.deepEqual([...uniqueSwarmImages(discovered, 'private.test').values()], [privateCopy, worker]);
});
