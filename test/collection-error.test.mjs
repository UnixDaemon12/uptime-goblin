import test from 'node:test';
import assert from 'node:assert/strict';
import { collectionError } from '../server.mjs';
import { CollectionError } from '../lib/collectors.mjs';

// collectionError turns a collection failure into the text an admin sees on the dashboard and in
// the test-service answer. Only CollectionError texts (fixed, written by the authors) pass through
// unchanged; any other text that names an address or a credential gives way to a generic message,
// and every form of a configured secret is redacted first.
const generic = 'Collection failed. Check the endpoint, credentials, and source compatibility.';
const service = { apiKey: 'AB!CD/ef+g=', username: 'u', password: 'p@ss word' };
const secretForms = [
  service.apiKey,
  encodeURIComponent(service.apiKey),
  new URLSearchParams({ k: service.apiKey }).toString().slice(2),
  service.password,
  encodeURIComponent(service.password),
  new URLSearchParams({ k: service.password }).toString().slice(2),
  Buffer.from(`${service.username}:${service.password}`).toString('base64'),
];
const leaks = text => secretForms.filter(form => text.includes(form));

test('collectionError: a URL-encoded key in a query URL is not shown because the text says check', () => {
  const key = encodeURIComponent(service.apiKey);
  const text = collectionError(
    new Error(`Request to https://192.0.2.10/api?apikey=${key} failed, check the source`),
    service
  );
  assert.deepEqual(leaks(text), []);
  assert.equal(text, generic);
});

test('collectionError: a base64 Basic credential is not shown because the text says authentication', () => {
  const basic = Buffer.from(`${service.username}:${service.password}`).toString('base64');
  const text = collectionError(new Error(`Basic ${basic} rejected; check authentication`), service);
  assert.deepEqual(leaks(text), []);
  assert.ok(!text.includes(basic));
});

test('collectionError: other bypass words and secret encodings fail closed', () => {
  for (const message of [
    `token ${service.apiKey} lacks permissions`,
    `GET http://192.0.2.10/x?k=${new URLSearchParams({ k: service.password }).toString().slice(2)} Authentication required`,
    `sessionID=${encodeURIComponent(service.password)}; Check it`,
  ]) {
    const text = collectionError(new Error(message), service);
    assert.deepEqual(leaks(text), [], message);
    assert.equal(text, generic, message);
  }
});

test('collectionError: author-written collector texts reach the admin unchanged', () => {
  for (const message of [
    'The source did not answer with TLS on this port. Check whether the address should use http:// or https://.',
    'Cosmos rejected the request. Check API token permissions.',
    'AMP login failed. Check credentials or use a service login token.',
    'No resources visible. Check API token permissions.',
    'The selected Proxmox node is not uniquely visible. Check its exact name and token read permissions.',
    'Authentication failed.',
    'Permission denied.',
    'Nginx Proxy Manager sign-in returned an unusable session token.',
  ])
    assert.equal(collectionError(new CollectionError(message), service), message);
  // Plain errors without an address or credential word keep their text, as before.
  for (const message of [
    'UniFi login failed. Use a local account with Network View Only access.',
    'Source returned an empty response. Check the API URL.',
    'Website check timed out after 10 seconds',
  ])
    assert.equal(collectionError(new Error(message), service), message);
  // The fixed texts for JavaScript's own error classes are unchanged.
  assert.equal(
    collectionError(new TypeError('fetch failed'), service),
    'Collection failed. Check the address and credential format.'
  );
  assert.equal(collectionError(new SyntaxError('Unexpected token'), service), generic);
  // A raw secret inside an author text is still redacted.
  assert.equal(
    collectionError(new CollectionError(`Rejected ${service.apiKey}.`), service),
    'Rejected [redacted].'
  );
});
