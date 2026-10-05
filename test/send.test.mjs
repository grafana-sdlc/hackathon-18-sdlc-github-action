import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { config, createEvent, loadBundle, send, discover, deliver } from '../src/send.mjs';

const image = 'ghcr.io/acme/app';
const digest = `sha256:${'a'.repeat(64)}`;
const environment = { SDLC_IMAGE: image, SDLC_DIGEST: digest, SDLC_GATEWAY_URL: 'https://gateway.example' };
function bundle() {
  return { mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json', verificationMaterial: { certificate: { rawBytes: 'fixture' } },
    dsseEnvelope: { payloadType: 'application/vnd.in-toto+json', signatures: [{ sig: 'fixture' }],
      payload: Buffer.from(JSON.stringify({ _type: 'https://in-toto.io/Statement/v1', predicateType: 'https://slsa.dev/provenance/v1',
        subject: [{ name: image, digest: { sha256: digest.slice(7) } }], predicate: {} })).toString('base64') } };
}
const options = config(environment);

test('require digest identity and HTTPS', () => {
  assert.equal(options.audience, 'https://gateway.example');
  for (const override of [{ SDLC_DIGEST: 'sha256:abc' }, { SDLC_IMAGE: 'ghcr.io/acme/app:latest' }, { SDLC_IMAGE: 'acme/app' }, { SDLC_IMAGE: 'https://ghcr.io/acme/app' },
    { SDLC_GATEWAY_URL: 'http://ingester.example/github/v1/logs' }, { SDLC_GATEWAY_URL: 'https://user:secret@ingester.example/github/v1/logs' }]) {
    assert.throws(() => config({ ...environment, ...override }));
  }
});
test('preserve complete bundle and stable event identity while keeping credentials out of OTLP', () => {
  const input = bundle();
  const first = createEvent(options, input, 1);
  const second = createEvent(options, input, 2);
  assert.equal(first.id, second.id);
  const record = first.event.resourceLogs[0].scopeLogs[0].logRecords[0];
  assert.equal(record.eventName, 'grafana.sdlc.image.provenance');
  const body = JSON.parse(record.body.stringValue);
  assert.deepEqual(body.provenance, input);
  assert.deepEqual(body.image, { name: image, digest });
  assert.deepEqual(Object.keys(body).sort(), ['attestation', 'image', 'provenance', 'schema_version']);
  assert.equal(record.timeUnixNano, '1000000');
});
test('reject mismatched, unsigned, non-provenance and oversized bundles', () => {
  assert.throws(() => createEvent({ ...options, digest: `sha256:${'b'.repeat(64)}` }, bundle()));
  const unsigned = bundle(); unsigned.dsseEnvelope.signatures = [];
  assert.throws(() => createEvent(options, unsigned));
  const oversized = bundle(); oversized.verificationMaterial.certificate.rawBytes = 'a'.repeat(500000);
  assert.throws(() => createEvent(options, oversized), /byte budget/);
  const wrongType = bundle();
  const statement = JSON.parse(Buffer.from(wrongType.dsseEnvelope.payload, 'base64'));
  statement.predicateType = 'https://example/sbom';
  wrongType.dsseEnvelope.payload = Buffer.from(JSON.stringify(statement)).toString('base64');
  assert.throws(() => createEvent(options, wrongType), /SLSA provenance/);
});
test('retry transient HTTP failures with same payload and fresh masked-by-caller credentials', async () => {
  const calls = []; let tokens = 0;
  await send(options.endpoint, { resourceLogs: [] }, { getToken: async () => `token-${++tokens}`, sleep: async () => {},
    fetchImpl: async (url, init) => { calls.push({ url, ...init }); return new Response('{}', { status: calls.length === 1 ? 503 : 200 }); } });
  assert.equal(calls.length, 2);
  assert.equal(calls[0].body, calls[1].body);
  assert.equal(calls[1].headers.Authorization, 'Bearer token-2');
  assert.equal(calls[0].redirect, 'error');
  assert.ok(!calls[0].body.includes('token'));
});
test('do not retry permanent rejection or swallow partial success', async () => {
  for (const [status, payload] of [[403, '{}'], [400, '{}'], [200, '{"partialSuccess":{"rejectedLogRecords":"1"}}']]) {
    let calls = 0;
    await assert.rejects(send(options.endpoint, {}, { getToken: async () => 'token', sleep: async () => {},
      fetchImpl: async () => { calls++; return new Response(payload, { status }); } }));
    assert.equal(calls, 1);
  }
});
test('network retry is bounded and missing ingestion token provider fails closed', async () => {
  let calls = 0;
  await assert.rejects(send(options.endpoint, {}, { getToken: async () => 'token', sleep: async () => {},
    fetchImpl: async () => { calls++; throw new Error('offline'); } }));
  assert.equal(calls, 3);
  await assert.rejects(send(options.endpoint, {}, {}), /token provider/);
});
test('real HTTP transport carries OTLP and bearer token without following redirects', async t => {
  const server = createServer(async (req, res) => {
    if (req.url === '/redirect') { res.writeHead(302, { Location: '/leak' }); res.end(); return; }
    assert.equal(req.url, '/github/v1/logs');
    assert.equal(req.headers.authorization, 'Bearer fixture-token');
    assert.equal(req.headers['content-type'], 'application/json');
    let body = ''; for await (const chunk of req) body += chunk;
    assert.deepEqual(JSON.parse(body), { resourceLogs: [] });
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  await send(origin + '/github/v1/logs', { resourceLogs: [] }, { getToken: async () => 'fixture-token' });
  await assert.rejects(send(origin + '/redirect', {}, { getToken: async () => 'fixture-token', sleep: async () => {} }));
});

test('discover routes using GitHub OIDC and mask both credential types', async () => {
  const masked = [];
  const routes = await discover(options, { getIDToken: async audience => { assert.equal(audience, 'https://gateway.example'); return 'github-oidc'; }, mask: token => masked.push(token),
    fetchImpl: async (url, init) => { assert.equal(url, 'https://gateway.example/v1/ingest/auths'); assert.equal(init.headers.Authorization, 'Bearer github-oidc'); assert.equal(init.redirect, 'error'); assert.equal(init.body, undefined); return Response.json({ destinations: [{ url: 'https://eu.example/github/v1/logs', token: 'eu-token' }] }); } });
  assert.equal(routes.get('https://eu.example/github/v1/logs'), 'eu-token');
  assert.deepEqual(masked, ['github-oidc', 'eu-token']);
});
test('regional retries refresh authorization without resending successful regions', async () => {
  let discoveries = 0; const calls = [];
  await deliver(options, { event: 'stable' }, { getIDToken: async () => 'github-oidc', sleep: async () => {},
    fetchImpl: async (url, init) => {
      if (url === options.endpoint) { discoveries++; return Response.json({ destinations: ['eu', 'us'].map(region => ({ url: `https://${region}.example/github/v1/logs`, token: `${region}-${discoveries}` })) }); }
      calls.push({ url, ...init });
      assert.ok(!init.headers.Authorization.includes('github-oidc'));
      assert.deepEqual(Object.keys(init.headers).sort(), ['Authorization', 'Content-Type']);
      return Response.json({}, { status: url.includes('us.') && calls.filter(c => c.url === url).length === 1 ? 503 : 200 });
    } });
  assert.equal(discoveries, 2);
  assert.equal(calls.filter(c => c.url.includes('eu.')).length, 1);
  const us = calls.filter(c => c.url.includes('us.'));
  assert.equal(us.length, 2); assert.equal(us[0].body, us[1].body);
  assert.equal(us[1].headers.Authorization, 'Bearer us-2');
});
test('reject unsafe and ambiguous routing before sending any event', async () => {
  for (const destinations of [[], [{ url: 'http://eu.example/github/v1/logs', token: 'x' }], [{ url: 'https://user:secret@eu.example/github/v1/logs', token: 'x' }],
    [{ url: 'https://eu.example/github/v1/logs', token: '' }], [{ url: 'https://eu.example/github/v1/logs', token: 'x' }, { url: 'https://eu.example/github/v1/logs', token: 'y' }]]) {
    let calls = 0;
    await assert.rejects(deliver(options, {}, { getIDToken: async () => 'oidc', fetchImpl: async () => { calls++; return Response.json({ destinations }); } }));
    assert.equal(calls, 1);
  }
});
test('revoked destination on refresh fails delivery without leaking tokens', async () => {
  let discoveries = 0, deliveries = 0;
  await assert.rejects(deliver(options, {}, { getIDToken: async () => 'secret-oidc', sleep: async () => {}, fetchImpl: async url => {
    if (url === options.endpoint) { discoveries++; return Response.json({ destinations: [{ url: `https://${discoveries === 1 ? 'eu' : 'us'}.example/github/v1/logs`, token: 'secret-ingest' }] }); }
    deliveries++; return Response.json({}, { status: 401 });
  } }), /failed for 1 of 1 regions/);
  assert.equal(deliveries, 1);
});



test('native failure has explicit status, no invented bundle, and run-specific identity', () => {
  const first = createEvent({ ...options, buildIdentity: '77:123:1' }, null);
  const second = createEvent({ ...options, buildIdentity: '77:123:2' }, null);
  const body = JSON.parse(first.event.resourceLogs[0].scopeLogs[0].logRecords[0].body.stringValue);
  assert.equal(body.schema_version, 2);
  assert.equal(body.attestation, 'unavailable');
  assert.equal(body.provenance, undefined);
  assert.deepEqual(body.image, { name: image, digest });
  assert.notEqual(first.id, second.id);
  assert.throws(() => createEvent(options, null));
  assert.equal(loadBundle({ SDLC_ATTESTATION_FAILED: 'true' }), null);
  assert.throws(() => loadBundle({}));
  assert.throws(() => loadBundle({ SDLC_ATTESTATION_FAILED: 'false' }));
  assert.throws(() => loadBundle({ SDLC_BUNDLE_PATH: '/nonexistent/bundle', SDLC_ATTESTATION_FAILED: 'true' }));
});

test('a supplied null or malformed bundle never becomes an unattested event', () => {
 const dir=mkdtempSync(join(tmpdir(),'sdlc-bundle-'));
 try {
  for (const content of ['null','[]','{']) {
   const path=join(dir,'bundle.json');writeFileSync(path,content);
   assert.throws(()=>loadBundle({SDLC_BUNDLE_PATH:path,SDLC_ATTESTATION_FAILED:'true'}));
  }
 } finally {rmSync(dir,{recursive:true,force:true});}
});
