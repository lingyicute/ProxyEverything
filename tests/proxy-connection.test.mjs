import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { default: worker, buildUpstreamHeaders } = await import(
	'data:text/javascript;base64,' + Buffer.from(source + '\nexport { buildUpstreamHeaders };').toString('base64')
);
const origin = 'https://proxy.example';
const target = new URL('https://site.example/file');
const env = { ALLOWED_TARGET_ORIGINS: target.origin };
const request = () => new Request(origin + '/~' + encodeURIComponent(target.origin) + target.pathname, {
	headers: { 'Proxy-Connection': 'keep-alive', 'X-End-To-End': 'retain' },
});

test('legacy Proxy-Connection is not forwarded by the shared HTTP/WebSocket header builder', () => {
	const headers = buildUpstreamHeaders(request(), origin, target, env);
	assert.equal(headers.get('Proxy-Connection'), null);
	assert.equal(headers.get('X-End-To-End'), 'retain');
});

test('legacy Proxy-Connection is removed from upstream responses', async t => {
	t.mock.method(globalThis, 'fetch', async () => new Response('fixture', {
		headers: { 'Content-Type': 'text/plain', 'Proxy-Connection': 'keep-alive', 'X-End-To-End': 'retain' },
	}));
	const response = await worker.fetch(request(), env);
	assert.equal(response.headers.get('Proxy-Connection'), null);
	assert.equal(response.headers.get('X-End-To-End'), 'retain');
	assert.equal(await response.text(), 'fixture');
});

test('the shared upstream header builder drops the entire X-Forwarded family', () => {
	const input = request();
	for (const name of ['X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Prefix', 'X-Forwarded-Uri']) {
		input.headers.set(name, 'fixture');
	}
	const headers = buildUpstreamHeaders(input, origin, target, env);
	assert.ok([...headers.keys()].every(name => !name.startsWith('x-forwarded-')));
	assert.equal(headers.get('X-End-To-End'), 'retain');
});
