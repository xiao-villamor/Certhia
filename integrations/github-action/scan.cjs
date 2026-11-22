const { appendFileSync } = require('node:fs');
const { setTimeout: wait } = require('node:timers/promises');

const uuid = '[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}';
const ciPath = new RegExp('^/api/webhooks/registries/' + uuid + '/ci/?$', 'i');
const scanId = new RegExp('^' + uuid + '$', 'i');

async function run(env) {
  const input = name => env['INPUT_' + name.toUpperCase()]?.trim();
  let endpoint;
  try {
    endpoint = new URL(input('webhook-url'));
  } catch {
    throw new Error('Enter a valid Certhia CI webhook URL.');
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(endpoint.hostname);
  if ((!loopback || endpoint.protocol !== 'http:') && endpoint.protocol !== 'https:'
      || endpoint.username || endpoint.password || endpoint.search || endpoint.hash
      || !ciPath.test(endpoint.pathname)) {
    throw new Error('Use the HTTPS CI webhook endpoint from the Certhia registry connection.');
  }
  endpoint.pathname = endpoint.pathname.replace(/\/$/, '');
  const token = input('webhook-token');
  const image = input('image');
  const platform = input('platform') || 'linux/amd64';
  const threshold = input('fail-on-fixable') || 'none';
  const seconds = Number(input('timeout-seconds') || 600);
  if (!token || /[\r\n]/.test(token) || !/^\S+@sha256:[a-f0-9]{64}$/.test(image ?? '')) {
    throw new Error('Provide a registry webhook token and an image pinned to a SHA-256 manifest digest.');
  }
  if (!['none', 'high', 'critical'].includes(threshold)
      || !Number.isInteger(seconds) || seconds < 1 || seconds > 3600) {
    throw new Error('Use a fix threshold of none, high, or critical and a timeout of 1 to 3600 seconds.');
  }

  const deadline = Date.now() + seconds * 1000;
  function remaining() {
    const left = deadline - Date.now();
    if (left <= 0) throw new Error('Timed out waiting for the Certhia scan.');
    return left;
  }
  async function request(url, body) {
    const signal = AbortSignal.timeout(Math.min(remaining(), 15000));
    let response;
    try {
      response = await fetch(url, {
        method: body ? 'POST' : 'GET',
        headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
        redirect: 'error', signal, body: body ? JSON.stringify(body) : undefined,
      });
    } catch {
      remaining();
      throw new Error('Could not reach the Certhia CI endpoint.');
    }
    if (response.status !== (body ? 202 : 200)) {
      throw new Error('Certhia CI endpoint returned HTTP ' + response.status + '.');
    }
    try {
      return await response.json();
    } catch {
      throw new Error('Certhia returned an invalid CI response.');
    }
  }
  function output(key, value) {
    if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, key + '=' + value + '\n');
  }

  const created = await request(endpoint, { reference: image, platform });
  const id = created?.scanIds?.[0];
  if (typeof id !== 'string' || !scanId.test(id)) throw new Error('Certhia did not return a scan ID.');
  const report = new URL('/scans/' + id, endpoint);
  const resultUrl = new URL(endpoint.pathname + '/' + id, endpoint);
  output('scan-id', id);
  output('report-url', report.href);
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, '### Certhia image scan\n\n[Open report](' + report.href + ')\n\n');

  let result;
  for (;;) {
    result = await request(resultUrl);
    if (result?.id !== id || result.platform !== platform) throw new Error('Unexpected Certhia result.');
    if (result.status === 'completed') break;
    if (!['queued', 'running'].includes(result.status)) throw new Error('Certhia scan did not complete.');
    await wait(Math.min(2000, remaining()));
  }
  if (result.observationComplete !== true || !Number.isSafeInteger(result.fixableHigh)
      || !Number.isSafeInteger(result.fixableCritical) || result.fixableHigh < 0 || result.fixableCritical < 0) {
    throw new Error('Certhia did not record a complete vulnerability scan.');
  }

  output('fixable-high', result.fixableHigh);
  output('fixable-critical', result.fixableCritical);
  if (env.GITHUB_STEP_SUMMARY) {
    appendFileSync(env.GITHUB_STEP_SUMMARY, 'Advisories with a reported fix\n\n- Critical: '
      + result.fixableCritical + '\n- High: ' + result.fixableHigh + '\n');
  }
  if (threshold !== 'none' && (result.fixableCritical > 0 || (threshold === 'high' && result.fixableHigh > 0))) {
    throw new Error('The image has advisories with reported fixes at or above the selected severity.');
  }
}

run(process.env).catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
