import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { default: worker, cookieNamespace } = await import(
	'data:text/javascript;base64,' + Buffer.from(source + '\nexport { cookieNamespace };').toString('base64')
);
const origin = 'https://proxy.example';
const target = 'https://example.com';
const proxy = origin + '/~' + encodeURIComponent(target) + '/asset';
const env = { ALLOWED_TARGET_ORIGINS: target };

function fixtures(t, responses) {
	const seen = [];
	t.mock.method(globalThis, 'fetch', async (_, options) => {
		seen.push({ headers: new Headers(options.headers), cache: options.cache, method: options.method });
		const next = responses.shift();
		assert.ok(next, 'unexpected upstream fetch');
		return next();
	});
	return seen;
}
const notModified = (headers = {}) => () => new Response(null, { status: 304, headers });
const response = (type, etag = '"source"', body = 'a{background:url(pic.png)}', extra = {}) =>
	() => new Response(body, { headers: { 'content-type': type, etag, ...extra } });

test('source validators cannot produce 304 for a rewritten representation', async t => {
	const seen = fixtures(t, [notModified({ ETag: '"source"' }), response('text/css')]);
	const ns = cookieNamespace(new URL(target));
	const r = await worker.fetch(new Request(proxy, { headers: {
		'If-None-Match': '"source"', 'If-Modified-Since': 'Wed, 01 Jan 2025 00:00:00 GMT',
		'If-Match': '"source"', Cookie: ns + 'sid=1',
	} }), env);
	assert.equal(r.status, 200);
	assert.equal(r.headers.get('etag'), null);
	assert.equal(await r.text(), `a{background:url("${origin}/~${encodeURIComponent(target)}/pic.png")}`);
	assert.equal(seen.length, 2);
	assert.equal(seen[0].headers.get('if-none-match'), '"source"');
	assert.equal(seen[1].headers.get('if-none-match'), null);
	assert.equal(seen[1].headers.get('if-modified-since'), null);
	assert.equal(seen[1].headers.get('if-match'), '"source"');
	assert.equal(seen[1].headers.get('cookie'), 'sid=1');
	assert.equal(seen[1].cache, 'no-store');
});

test('untransformed 304 responses are retained only if the retry confirms their validator', async t => {
	const seen = fixtures(t, [notModified({ ETag: '"source"' }), response('image/png', '"source"', 'image')]);
	const r = await worker.fetch(new Request(proxy, { headers: { 'If-None-Match': '"source"' } }), env);
	assert.equal(r.status, 304);
	assert.equal(r.headers.get('etag'), '"source"');
	assert.equal(seen.length, 2);
});

test('a changed or cookie-setting retry returns the new complete response', async t => {
	const seen = fixtures(t, [
		notModified({ ETag: '"source"' }), response('image/png', '"new"', 'new image'),
		notModified({ ETag: '"source"' }), response('image/png', '"source"', 'image', { 'Set-Cookie': 'sid=1; Path=/' }),
	]);
	let r = await worker.fetch(new Request(proxy, { headers: { 'If-None-Match': '"source"' } }), env);
	assert.equal(r.status, 200);
	assert.equal(await r.text(), 'new image');
	r = await worker.fetch(new Request(proxy, { headers: { 'If-None-Match': '"source"' } }), env);
	assert.equal(r.status, 200);
	assert.match(r.headers.getSetCookie()[0], /_sid=1/);
	assert.equal(r.headers.get('Cache-Control'), 'no-store');
	assert.equal(seen.length, 4);
});

test('wildcard conditions remain 304 without source validators and keep retry cookies', async t => {
	fixtures(t, [notModified({ ETag: '"source"' }), response('text/css', '"source"', 'a{}', { 'Set-Cookie': 'sid=1; Path=/' })]);
	const r = await worker.fetch(new Request(proxy, { headers: { 'If-None-Match': '*' } }), env);
	assert.equal(r.status, 304);
	assert.equal(r.headers.get('ETag'), null);
	assert.equal(r.headers.get('Content-Type'), null);
	assert.match(r.headers.getSetCookie()[0], /_sid=1/);
	assert.equal(r.headers.get('Cache-Control'), 'no-store');
});

test('no-transform revalidation is not retried and a repeated unconditional 304 fails safely', async t => {
	const seen = fixtures(t, [notModified({ ETag: '"source"' }), notModified(), notModified()]);
	let r = await worker.fetch(new Request(proxy, { headers: { 'If-None-Match': '"source"', 'Cache-Control': 'no-transform' } }), env);
	assert.equal(r.status, 304);
	assert.equal(seen.length, 1);
	r = await worker.fetch(new Request(proxy, { headers: { 'If-Modified-Since': 'Wed, 01 Jan 2025 00:00:00 GMT' } }), env);
	assert.equal(r.status, 502);
	assert.equal(r.headers.get('Cache-Control'), 'no-store');
});

test('HEAD revalidation fetches metadata again before selecting the transformed representation', async t => {
	const seen = fixtures(t, [notModified({ ETag: '"source"' }), () => new Response(null, { headers: { 'Content-Type': 'text/html', ETag: '"source"' } })]);
	const r = await worker.fetch(new Request(proxy, { method: 'HEAD', headers: { 'If-None-Match': '"source"' } }), env);
	assert.equal(r.status, 200);
	assert.equal(r.body, null);
	assert.equal(r.headers.get('ETag'), null);
	assert.equal(r.headers.get('Content-Type'), 'text/html; charset=UTF-8');
	assert.deepEqual(seen.map(x => x.method), ['HEAD', 'HEAD']);
});

test('cookies from the original 304 and the replacement 200 are both retained', async t => {
	fixtures(t, [notModified({ ETag: '"source"', 'Set-Cookie': 'first=1; Path=/' }),
		response('text/css', '"source"', 'a{}', { 'Set-Cookie': 'second=2; Path=/' })]);
	const r = await worker.fetch(new Request(proxy, { headers: { 'If-None-Match': '"source"' } }), env);
	assert.equal(r.status, 200);
	assert.deepEqual(r.headers.getSetCookie().map(cookie => cookie.match(/_(first|second)=/)[1]), ['first', 'second']);
	assert.equal(r.headers.get('Cache-Control'), 'no-store');
	assert.equal(await r.text(), 'a{}');
});
