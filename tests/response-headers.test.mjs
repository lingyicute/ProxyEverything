import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

// Load the standalone Worker as an ES module without changing its deployment exports.
const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { default: worker, scopeRequestCookie } = await import(
	'data:text/javascript;base64,' + Buffer.from(source + '\nexport { scopeRequestCookie };').toString('base64')
);

const origin = 'https://proxy.example';
const proxy = url => {
	const u = new URL(url);
	return origin + '/~' + encodeURIComponent(u.origin) + u.pathname + u.search;
};

async function fetchThrough(target, upstreamHeaders, body = 'body', requestHeaders = {}) {
	const originalFetch = globalThis.fetch;
	globalThis.fetch = async () => new Response(body, { headers: upstreamHeaders });
	try {
		return await worker.fetch({ url: proxy(target), method: 'GET', headers: new Headers(requestHeaders), body: null }, {
			ALLOWED_TARGET_ORIGINS: new URL(target).origin,
		});
	} finally {
		globalThis.fetch = originalFetch;
	}
}

test('Refresh response header is rewritten through the proxy instead of dropped', async () => {
	const page = 'https://example.com/dir/page';
	for (const [contentType, value, expected] of [
		['text/plain', '3; url=next?a=1', `3; url=${proxy('https://example.com/dir/next?a=1')}`],
		['image/png', "0; URL='https://cdn.example.net/x'", `0; url=${proxy('https://cdn.example.net/x')}`],
		['text/css', '5', '5'],
	]) {
		const response = await fetchThrough(page, { 'content-type': contentType, refresh: value }, 'a{}');
		assert.equal(response.headers.get('refresh'), expected, contentType);
	}

	const connResp = await fetchThrough(page, {
		'content-type': 'text/plain',
		refresh: '2; url=/done',
		connection: 'Refresh, X-Hop',
		'x-hop': '1',
	}, 'ok');
	assert.equal(connResp.headers.get('refresh'), `2; url=${proxy('https://example.com/done')}`);
	assert.equal(connResp.headers.get('x-hop'), null);
});

test('origin-wide persistent policy headers do not leak onto the shared proxy origin', async () => {
	const headers = {
		'content-type': 'image/png',
		'accept-ch': 'Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model',
		'critical-ch': 'Sec-CH-UA-Model',
		'origin-agent-cluster': '?1',
		'set-login': 'logged-in',
	};
	const response = await fetchThrough('https://example.com/a.png', headers);
	for (const name of Object.keys(headers).slice(1)) assert.equal(response.headers.get(name), null, name);
	assert.equal(response.headers.get('content-type'), 'image/png');
});

test('only exact supported media types are transformed; attachments and no-transform stay untouched', async () => {
	const page = 'https://example.com/dir/page';
	const original = 'a{background:url(untouched.png)}';
	for (const headers of [
		{ 'content-type': 'application/x-text/css-extra' },
		{ 'content-type': 'text/css', 'content-disposition': 'attachment; filename="sheet.css"' },
		{ 'content-type': 'text/css', 'cache-control': 'public, no-transform, max-age=60' },
	]) {
		const response = await fetchThrough(page, { ...headers, 'x-content-type-options': 'nosniff', etag: '"source"' }, original);
		assert.equal(response.headers.get('content-type'), headers['content-type']);
		assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
		assert.equal(response.headers.get('etag'), '"source"');
		assert.equal(await response.text(), original);
	}
});

test('JSON variants vary on the manifest destination in both forwarding paths', async () => {
	const page = 'https://example.com/app.json';
	const json = '{"start_url":"/home"}';
	for (const dest of ['empty', 'manifest']) {
		const response = await fetchThrough(page, { 'content-type': 'application/json' }, json, { 'sec-fetch-dest': dest });
		assert.match(response.headers.get('vary'), /\bSec-Fetch-Dest\b/i);
		assert.equal((await response.json()).start_url, dest === 'manifest' ? proxy('https://example.com/home') : '/home');
	}
});

test('Set-Cookie fields retain separate values and commas within Expires', async () => {
	const headers = new Headers({ 'content-type': 'text/plain' });
	headers.append('set-cookie', 'first=one; Expires=Wed, 01 Jan 2031 00:00:00 GMT');
	headers.append('set-cookie', 'second=two; HttpOnly');
	const response = await fetchThrough('https://example.com/state', headers);
	const values = response.headers.getSetCookie();
	assert.equal(values.length, 2);
	assert.match(values[0], /_first=one; Expires=Wed, 01 Jan 2031 00:00:00 GMT/);
	assert.match(values[1], /_second=two; HttpOnly/);
	assert.equal(response.headers.get('Cache-Control'), 'no-store');
});

test('upstream source variants retain Referer in the downstream cache key', async () => {
	const response = await fetchThrough('https://example.com/asset', {
		'content-type': 'text/plain', vary: 'Origin, Sec-Fetch-Site, Accept-Language',
	});
	for (const field of ['origin', 'sec-fetch-site', 'accept-language', 'referer']) {
		assert.ok(response.headers.get('vary').toLowerCase().split(/,\s*/).includes(field));
	}
});

test('HTTP upstreams do not turn secure cookies into ordinary cookies', async () => {
	const headers = new Headers({ 'content-type': 'text/plain' });
	for (const value of ['tls=1; Secure', 'partition=2; Partitioned', 'cross=3; SameSite=None', 'plain=4']) {
		headers.append('set-cookie', value);
	}
	const response = await fetchThrough('http://example.com/state', headers);
	const values = response.headers.getSetCookie();
	assert.equal(values.length, 1);
	assert.match(values[0], /_plain=4; Path=\//);
});

test('streaming HTML uses the same downstream CORS policy as other media', async t => {
	const previous = globalThis.HTMLRewriter;
	globalThis.HTMLRewriter = class { on() { return this; } transform(r) { return r; } };
	t.after(() => { if (previous) globalThis.HTMLRewriter = previous; else delete globalThis.HTMLRewriter; });
	for (const headers of [{}, { origin }]) {
		const r = await fetchThrough('https://example.com/page', {
			'content-type': 'text/html', 'access-control-allow-origin': '*',
			'access-control-expose-headers': 'X-Fixture', vary: 'Sec-Fetch-Site',
		}, '<p>fixture</p>', headers);
		assert.equal(r.status, 200);
		assert.equal(r.headers.get('access-control-allow-origin'), headers.origin ?? null);
		assert.equal(r.headers.get('access-control-expose-headers'), null);
		assert.match(r.headers.get('vary'), /\bReferer\b/i);
		await r.text();
	}
});


test('client no-transform selects an intact, separately cacheable representation', async () => {
	const css = 'a{background:url(tile.png)}';
	for (const [policy, unchanged] of [
		['max-age=0, No-Transform', true], ['extension="a,no-transform,b"', false], ['', false],
	]) {
		const r = await fetchThrough('https://example.com/style.css', {
			'content-type': 'text/css', etag: '"original"', 'cache-control': 'public, max-age=60',
		}, css, { 'cache-control': policy });
		assert.match(r.headers.get('vary'), /\bCache-Control\b/i);
		assert.equal(r.headers.get('etag'), unchanged ? '"original"' : null);
		assert.equal((await r.text()) === css, unchanged);
	}
});

test('authenticated redirects stay within the original target origin', async t => {
	const target = 'https://example.com/start';
	const env = { ALLOWED_TARGET_ORIGINS: 'https://example.com,https://cdn.example' };
	let location;
	t.mock.method(globalThis, 'fetch', async () => new Response(null, { status: 307, headers: { location } }));
	for (const [next, authenticated, status] of [
		['/next', true, 307], ['https://cdn.example/next', false, 307],
		['https://cdn.example/next', true, 502], [proxy('https://cdn.example/next'), true, 502],
		['http://example.com/next', true, 502], ['https://example.com:8443/next', true, 502],
	]) {
		location = next;
		const r = await worker.fetch(new Request(proxy(target), {
			headers: authenticated ? { authorization: 'Bearer fixture' } : {},
		}), env);
		assert.equal(r.status, status);
		assert.equal(r.headers.has('Location'), status === 307);
		if (status === 502) assert.equal(r.headers.get('Cache-Control'), 'no-store');
	}
});

test('bodyless responses do not advertise source metadata for a rewritten GET', async t => {
	const target = 'https://example.com/asset';
	let upstream;
	t.mock.method(globalThis, 'fetch', () => upstream);
	for (const [method, status, type, policy, intact] of [
		['HEAD', 200, 'text/css', '', false], ['GET', 304, 'text/html', '', false],
		['HEAD', 200, 'image/png', '', true], ['HEAD', 200, 'text/css', 'no-transform', true],
		['HEAD', 206, 'text/css', '', true],
	]) {
		upstream = new Response(null, { status, headers: {
			'content-type': type, 'content-length': '99', etag: '"source"', 'content-encoding': 'gzip',
		} });
		const r = await worker.fetch(new Request(proxy(target), { method, headers: { 'cache-control': policy } }),
			{ ALLOWED_TARGET_ORIGINS: new URL(target).origin });
		assert.equal(r.status, status);
		assert.equal(r.body, null);
		for (const field of ['content-type', 'content-length', 'content-encoding', 'etag']) {
			assert.equal(r.headers.get(field), intact ? upstream.headers.get(field) : null, field);
		}
	}
});

test('reserved cookie prefixes remain browser-visible and require their original attributes', async () => {
	const target = 'https://example.com/cookies';
	const headers = new Headers();
	for (const value of [
		'__Host-a=1; Secure; Path=/', '__Secure-b=2; Secure', '__Http-c=3; HttpOnly; Secure',
		'__Host-Http-d=4; HttpOnly; Secure; Path=/', 'ordinary=5',
		'__Host-missing-path=x; Secure', '__Host-domain=x; Secure; Path=/; Domain=example.com',
		'__Host-wrong-path=x; Secure; Path=/sub', '__Secure-no-tls=x; SameSite=None',
		'__Http-missing-http=x; Secure', '__Host-Http-missing-secure=x; HttpOnly; Path=/',
	]) headers.append('Set-Cookie', value);
	const r = await fetchThrough(target, headers);
	const names = r.headers.getSetCookie().map(c => c.split(';')[0]);
	const key = encodeURIComponent(new URL(target).origin);
	const ns = '__pe_' + key.length.toString(36) + '_' + key + '_';
	assert.deepEqual(names, [`__Host-${ns}a=1`, `__Secure-${ns}b=2`, `__Http-${ns}c=3`, `__Host-Http-${ns}d=4`, `${ns}ordinary=5`]);
	assert.equal(scopeRequestCookie([...names, ns + '__Host-old=x'].join('; '), ns),
		'__Host-a=1; __Secure-b=2; __Http-c=3; __Host-Http-d=4; ordinary=5');
});

test('cacheable scripts vary on both service-worker request markers', async () => {
	for (const type of ['text/javascript', 'application/octet-stream']) {
		const r = await fetchThrough('https://example.com/script', {
			'content-type': type, 'cache-control': 'public, max-age=60',
		});
		const vary = r.headers.get('vary').toLowerCase().split(/,\s*/);
		assert.ok(vary.includes('service-worker'));
		assert.ok(vary.includes('sec-fetch-dest'));
	}
});
