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
		'accept-ch-lifetime': '86400',
		'critical-ch': 'Sec-CH-UA-Model',
		'origin-agent-cluster': '?1',
		'set-login': 'logged-in',
		'activate-storage-access': 'load',
		'observe-browsing-topics': '?1',
		'supports-loading-mode': 'credentialed-prerender',
		'permissions-policy-report-only': 'camera=()',
	};
	const response = await fetchThrough('https://example.com/a.png', headers);
	for (const name of Object.keys(headers).slice(1)) assert.equal(response.headers.get(name), null, name);
	assert.equal(response.headers.get('content-type'), 'image/png');
});

test('integrity and legacy feature policies do not block rewritten pages', async () => {
	const headers = {
		'content-type': 'text/javascript',
		'integrity-policy': 'blocked-destinations=(script)',
		'integrity-policy-report-only': 'blocked-destinations=(script)',
		'feature-policy': "camera 'none'",
	};
	const response = await fetchThrough('https://example.com/a.js', headers, 'void 0;');
	assert.equal(response.status, 200);
	for (const name of Object.keys(headers).slice(1)) assert.equal(response.headers.get(name), null, name);
});

test('document isolation and report-only isolation headers are not forwarded', async () => {
	const headers = {
		'content-type': 'image/png',
		'document-isolation-policy': 'isolate-and-require-corp',
		'document-isolation-policy-report-only': 'isolate-and-require-corp',
		'cross-origin-opener-policy-report-only': 'same-origin',
		'cross-origin-embedder-policy-report-only': 'require-corp',
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
		[origin + '/~wss%3A%2F%2Fexample.com/next', true, 502],
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
	// HEAD 仍需给出媒体类型：HTML 必定改写为 UTF-8，其它类型只保留不带 charset 的媒体类型；304 不重复声明。
	for (const [method, status, type, policy, intact, contentType = intact ? type : null] of [
		['HEAD', 200, 'text/css', '', false, 'text/css'],
		['HEAD', 200, 'text/html; charset=gbk', '', false, 'text/html; charset=UTF-8'],
		['HEAD', 200, 'application/javascript; charset=gbk', '', false, 'application/javascript'],
		['GET', 304, 'text/html', '', false], ['HEAD', 200, 'image/png', '', true],
		['HEAD', 200, 'text/css', 'no-transform', true], ['HEAD', 206, 'text/css', '', true],
	]) {
		upstream = new Response(null, { status, headers: {
			'content-type': type, 'content-length': '99', etag: '"source"', 'content-encoding': 'gzip',
		} });
		const r = await worker.fetch(new Request(proxy(target), { method, headers: { 'cache-control': policy } }),
			{ ALLOWED_TARGET_ORIGINS: new URL(target).origin });
		assert.equal(r.status, status, type);
		assert.equal(r.body, null);
		assert.equal(r.headers.get('content-type'), contentType, type);
		for (const field of ['content-length', 'content-encoding', 'etag']) {
			assert.equal(r.headers.get(field), intact ? upstream.headers.get(field) : null, `${type} ${field}`);
		}
	}

	// 声明长度超过改写上限且无需解码的正文一定会原样透传，HEAD 沿用 GET 的表示元数据。
	for (const [length, encoding, intact] of [
		['3000000', null, true], ['3000000', 'gzip', false], ['2097152', null, false],
		['Infinity', null, false], ['1e9', null, false], ['0x300000', null, false],
	]) {
		const headers = { 'content-type': 'text/css; charset=gbk', 'content-length': length, etag: '"big"' };
		if (encoding) headers['content-encoding'] = encoding;
		upstream = new Response(null, { headers });
		const r = await worker.fetch(new Request(proxy(target), { method: 'HEAD' }), { ALLOWED_TARGET_ORIGINS: new URL(target).origin });
		assert.equal(r.headers.get('content-type'), intact ? 'text/css; charset=gbk' : 'text/css', `${length} ${encoding}`);
		assert.equal(r.headers.get('content-length'), intact ? length : null, `${length} ${encoding}`);
		assert.equal(r.headers.get('etag'), intact ? '"big"' : null, `${length} ${encoding}`);
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

test('created resources expose a usable proxy Location without discarding their body', async t => {
	const target = 'https://example.com/items/';
	t.mock.method(globalThis, 'fetch', () => new Response('created', { status: 201, headers: { location: 'item%2F1?' } }));
	const r = await worker.fetch(new Request(proxy(target), { method: 'POST' }), { ALLOWED_TARGET_ORIGINS: new URL(target).origin });
	assert.equal(r.status, 201);
	assert.equal(r.headers.get('location'), proxy(target) + 'item%2F1?');
	assert.equal(await r.text(), 'created');
});

test('redirects to external protocol handlers keep their Location', async t => {
	let location;
	t.mock.method(globalThis, 'fetch', async () => new Response(null, { status: 302, headers: { location } }));
	for (const [next, expected] of [
		['mailto:team@example.com?subject=hi', 'mailto:team@example.com?subject=hi'],
		['zoommtg://zoom.us/join?confno=1', 'zoommtg://zoom.us/join?confno=1'],
		['/next', proxy('https://example.com/next')],
		[origin + '/~https%3A%2F%2Fexample.com/a/../../~https%3A%2F%2Fother.example/x', proxy('https://example.com/~https%3A%2F%2Fother.example/x')],
		[origin + '/foo/../~https%3A%2F%2Fother.example/x', proxy('https://example.com/~https%3A%2F%2Fother.example/x')],
		['https://[', null],
	]) {
		location = next;
		const r = await worker.fetch(new Request(proxy('https://example.com/start')), {
			ALLOWED_TARGET_ORIGINS: 'https://example.com',
		});
		assert.equal(r.status, 302);
		assert.equal(r.headers.get('Location'), expected);
	}
});

test('redirect status without a Location keeps the explanatory representation', async t => {
	t.mock.method(globalThis, 'fetch', () => new Response('Choose a new address.', { status: 302 }));
	const r = await worker.fetch(new Request(proxy('https://example.com/old')), { ALLOWED_TARGET_ORIGINS: 'https://example.com' });
	assert.equal(r.status, 302);
	assert.equal(await r.text(), 'Choose a new address.');
});

test('hardening a personalized response preserves the upstream no-transform directive', async () => {
	const r = await fetchThrough('https://example.com/style.css', {
		'content-type': 'text/css', 'cache-control': 'private, no-transform',
	}, '@import "tile.css";', { authorization: 'Bearer fixture' });
	assert.equal(r.headers.get('cache-control'), 'no-store, no-transform');
	assert.equal(await r.text(), '@import "tile.css";');
});

test('bodyless revalidation preserves the request cache policy variant without Content-Type', async t => {
	let status = 200;
	t.mock.method(globalThis, 'fetch', () => new Response(status === 200 ? 'a{}' : null, {
		status, headers: status === 200 ? { 'Content-Type': 'text/css', ETag: '"source"' } : { ETag: '"source"' },
	}));
	const request = new Request(proxy('https://example.com/style.css'), { headers: { 'Cache-Control': 'no-transform' } });
	const env = { ALLOWED_TARGET_ORIGINS: 'https://example.com' };
	const raw = await worker.fetch(request, env);
	status = 304;
	const refreshed = await worker.fetch(request, env);
	assert.equal(refreshed.status, 304);
	assert.match(refreshed.headers.get('Vary'), /\bCache-Control\b/i);
	assert.equal(refreshed.headers.get('Vary'), raw.headers.get('Vary'));
	assert.equal(refreshed.headers.get('ETag'), raw.headers.get('ETag'));
});

test('SameSite=None and Partitioned cookies require an upstream Secure attribute', async () => {
	const headers = new Headers({ 'content-type': 'text/plain' });
	for (const cookie of ['cross=1; SameSite=None', 'chips=2; Partitioned', 'ctl=1\x7f; Path=/',
		'valid=3; SameSite=None; Secure', 'part=4; Secure; Partitioned', 'lax=5; SameSite=None; SameSite=Lax']) {
		headers.append('Set-Cookie', cookie);
	}
	const r = await fetchThrough('https://example.com/cookies', headers);
	const values = r.headers.getSetCookie();
	assert.equal(values.length, 3);
	assert.match(values[0], /_valid=3; Secure; SameSite=None;/);
	assert.match(values[1], /_part=4; Secure; Partitioned;/);
	assert.match(values[2], /_lax=5; SameSite=Lax;/);
});

test('authenticated redirects reject opaque non-HTTP schemes carrying the same host', async t => {
	const env = { ALLOWED_TARGET_ORIGINS: 'https://example.com' };
	for (const location of ['blob:https://example.com/id', 'mailto:example.com/path']) {
		t.mock.method(globalThis, 'fetch', async () => new Response(null, { status: 302, headers: { location } }));
		const r = await worker.fetch(new Request(proxy('https://example.com/start'), {
			headers: { authorization: 'Bearer tok' },
		}), env);
		assert.equal(r.status, 502, location);
	}
});

test('Connection header cannot strip X-Content-Type-Options', async () => {
	const r = await fetchThrough('https://example.com/file.txt', {
		'content-type': 'text/plain',
		'x-content-type-options': 'nosniff',
		connection: 'X-Content-Type-Options, X-Transient',
		'x-transient': '1',
	}, 'ok');
	assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
	assert.equal(r.headers.get('x-transient'), null);
});

test('strips Use-As-Dictionary origin-wide compression dictionary header', async () => {
	const r = await fetchThrough('https://example.com/app.js', {
		'content-type': 'text/plain',
		'use-as-dictionary': 'match="/app/*"',
	}, 'ok');
	assert.equal(r.headers.get('use-as-dictionary'), null);
});

test('strips Available-Dictionary and Dictionary-ID request headers before forwarding', async t => {
	let seen;
	t.mock.method(globalThis, 'fetch', async (_, init) => {
		seen = new Headers(init.headers);
		return new Response('ok');
	});
	const r = await worker.fetch(new Request(proxy('https://example.com/app.js'), {
		headers: { 'available-dictionary': ':abc:', 'dictionary-id': '"dict"', 'x-keep': '1' },
	}), { ALLOWED_TARGET_ORIGINS: 'https://example.com' });
	assert.equal(r.status, 200);
	assert.equal(seen.get('available-dictionary'), null);
	assert.equal(seen.get('dictionary-id'), null);
	assert.equal(seen.get('x-keep'), '1');
});
