import { createHash } from 'node:crypto';
import { readFileSync, appendFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const hash = value => createHash('sha256').update(value).digest('hex');
const attr = (key, value) => ({ key, value: { stringValue: value } });

export function config(env = process.env) {
  const image = env.SDLC_IMAGE || '';
  const digest = env.SDLC_DIGEST || '';
  const [registry, ...repository] = image.split('/');
  const registryPattern = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]+)?$/;
  const componentPattern = /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/;
  if (!registryPattern.test(registry) || !(registry.includes('.') || registry.includes(':') || registry === 'localhost') ||
      repository.length === 0 || !repository.every(part => componentPattern.test(part))) {
    throw new Error('image must be a fully qualified name without a tag or digest');
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(digest)) throw new Error('digest must be sha256 followed by 64 lowercase hex characters');
  const endpoint = new URL(env.SDLC_GATEWAY_URL || 'https://sdlc-github.grafana.net');
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.hash || endpoint.search || (endpoint.pathname !== '/' && endpoint.pathname !== '')) {
    throw new Error('gateway-url must be an HTTPS origin without credentials, path, query or fragment');
  }
  return { image, digest, endpoint: endpoint.origin + '/v1/ingest/auths', audience: endpoint.origin };
}

export function createEvent(options, bundle, now = Date.now()) {
  // Structural matching only. Cryptographic provenance verification belongs to the image processor.
  if (bundle !== null) {
    if (!bundle.mediaType?.startsWith('application/vnd.dev.sigstore.bundle.') ||
        !bundle.verificationMaterial || !bundle.dsseEnvelope?.signatures?.length ||
        bundle.dsseEnvelope.payloadType !== 'application/vnd.in-toto+json') {
      throw new Error('expected a Sigstore bundle with verification material and a DSSE envelope');
    }
    const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString('utf8'));
    if (statement._type !== 'https://in-toto.io/Statement/v1' || statement.predicateType !== 'https://slsa.dev/provenance/v1' ||
        !statement.subject?.some(s => s.name === options.image && s.digest?.sha256 === options.digest.slice(7))) {
      throw new Error('bundle must contain SLSA provenance for the supplied image and digest');
    }
  } else if (!options.buildIdentity || !/^[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*$/.test(options.buildIdentity)) {
    throw new Error('unattested events require repository ID, run ID and run attempt');
  }
  const id = hash(JSON.stringify([options.image, options.digest, bundle, ...(bundle === null ? [options.buildIdentity] : [])]));
  const body = { schema_version: 2, image: { name: options.image, digest: options.digest },
    attestation: bundle === null ? 'unavailable' : 'sigstore', ...(bundle === null ? {} : { provenance: bundle }) };
  const record = { eventName: 'grafana.sdlc.image.provenance', timeUnixNano: String(BigInt(now) * 1000000n),
    severityNumber: 9, attributes: [attr('grafana.sdlc.event.id', id)], body: { stringValue: JSON.stringify(body) } };
  const event = { resourceLogs: [{ resource: { attributes: [attr('service.name', 'sdlc-github-action')] }, scopeLogs: [{ scope: { name: 'grafana.sdlc.github', version: '1' }, logRecords: [record] }] }] };
  // The ingester's default exclusive limit is 512 KiB including its Kafka key.
  // Leave room for protobuf JSON normalization; never silently truncate a bundle.
  if (Buffer.byteLength(JSON.stringify(event)) + id.length >= 500000) throw new Error('image event exceeds the supported 500000-byte budget');
  return { id, event };
}

export async function send(endpoint, event, { fetchImpl = fetch, getToken = async () => { throw new Error('ingestion token provider is required'); }, sleep = ms => new Promise(r => setTimeout(r, ms)) } = {}) {
  const body = JSON.stringify(event);
  for (let attempt = 0; attempt < 3; attempt++) {
    let response;
    const token = await getToken(attempt);
    if (!token) throw new Error('Gateway returned an empty ingestion token');
    try {
      response = await fetchImpl(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body, redirect: 'error', signal: AbortSignal.timeout(30000) });
    } catch (error) {
      if (attempt === 2) throw new Error('ingester request failed');
    }
    if (response) {
      if (response.ok) {
        const result = await response.json();
        if (result.partialSuccess && (Number(result.partialSuccess.rejectedLogRecords || 0) > 0 || result.partialSuccess.errorMessage)) {
          throw new Error('ingester reported partial success; image event was not fully accepted');
        }
        return;
      }
      await response.body?.cancel();
      if (![401, 408, 429, 500, 502, 503, 504].includes(response.status) || attempt === 2) {
        throw new Error(`ingester returned HTTP ${response.status}`);
      }
    }
    await sleep(1000 * 2 ** attempt);
  }
}

export async function discover(options, { getIDToken, mask = () => {}, fetchImpl = fetch, sleep = ms => new Promise(r => setTimeout(r, ms)) } = {}) {
  if (!getIDToken) throw new Error('GitHub OIDC token provider is required');
  for (let attempt = 0; attempt < 3; attempt++) {
    const token = await getIDToken(options.audience);
    if (!token) throw new Error('GitHub returned an empty OIDC token');
    mask(token);
    let response;
    try {
      response = await fetchImpl(options.endpoint, { method: 'POST', headers: { Authorization: `Bearer ${token}` },
        redirect: 'error', signal: AbortSignal.timeout(30000) });
    } catch {
      if (attempt === 2) throw new Error('gateway request failed');
    }
    if (response?.ok) {
      // Bound the authorization response before parsing or logging any token.
      const reader = response.body.getReader();
      const chunks = []; let size = 0;
      try {
        for (;;) {
          const { done, value } = await reader.read(); if (done) break;
          size += value.length;
          if (size > 1024 * 1024) throw new Error('gateway response too large');
          chunks.push(value);
        }
      } finally { await reader.cancel(); }
      let data;
      try { data = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new Error('invalid gateway response'); }
      if (!Array.isArray(data.destinations) || data.destinations.length === 0 || data.destinations.length > 100) throw new Error('gateway returned no valid destinations');
      const destinations = new Map();
      for (const d of data.destinations) {
        if (typeof d.token === 'string') mask(d.token);
        let url; try { url = new URL(d.url); } catch { throw new Error('invalid regional destination'); }
        if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/github/v1/logs' ||
            typeof d.token !== 'string' || !d.token || d.token.length > 32768 || /\s/.test(d.token) || destinations.has(url.href)) throw new Error('invalid regional destination');
        destinations.set(url.href, d.token);
      }
      return destinations;
    }
    if (response) {
      await response.body?.cancel();
      if (![408, 429, 500, 502, 503, 504].includes(response.status) || attempt === 2) throw new Error(`gateway returned HTTP ${response.status}`);
    }
    await sleep(1000 * 2 ** attempt);
  }
}

export async function deliver(options, event, dependencies = {}) {
  let destinations = await discover(options, dependencies);
  let refreshing;
  const refresh = () => {
    if (!refreshing) refreshing = discover(options, dependencies).then(value => { destinations = value; }).finally(() => { refreshing = undefined; });
    return refreshing;
  };
  // Each destination retries independently; successful regions are never resent.
  const results = await Promise.allSettled([...destinations.keys()].map(endpoint => send(endpoint, event, {
    fetchImpl: dependencies.fetchImpl, sleep: dependencies.sleep,
    getToken: async attempt => {
      if (attempt > 0) await refresh();
      const token = destinations.get(endpoint);
      if (!token) throw new Error('regional authorization was revoked');
      return token;
    },
  })));
  const failed = results.filter(result => result.status === 'rejected').length;
  if (failed) throw new Error(`Image delivery failed for ${failed} of ${results.length} regions; successful deliveries were retained`);
}

export function loadBundle(env = process.env) {
  // Only native generation failure permits fallback. Explicit/malformed bundles
  // and missing output from an otherwise successful step remain errors.
  if (env.SDLC_BUNDLE_PATH) {
    const bundle = JSON.parse(readFileSync(env.SDLC_BUNDLE_PATH, 'utf8'));
    if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) throw new Error('invalid attestation bundle');
    return bundle;
  }
  if (env.SDLC_ATTESTATION_FAILED === 'true') return null;
  throw new Error('attestation bundle is missing');
}

export async function main({ getIDToken, mask = () => {} } = {}) {
  const options = config();
  if (process.argv.includes('--validate')) return;
  const bundle = loadBundle();
  options.buildIdentity = [process.env.GITHUB_REPOSITORY_ID, process.env.GITHUB_RUN_ID, process.env.GITHUB_RUN_ATTEMPT].join(':');
  if (bundle === null) console.log('::warning::Native attestation unavailable; sending authenticated build metadata without an attestation.');
  const { id, event } = createEvent(options, bundle);
  await deliver(options, event, { getIDToken, mask });
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `event-id=${id}\nattestation-status=${bundle === null ? 'unavailable' : 'sigstore'}\n`);
  console.log(`Sent image provenance: ${options.image}@${options.digest} event=${id}`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
