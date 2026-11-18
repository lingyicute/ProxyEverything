import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

// Load the standalone Worker as an ES module without changing its deployment exports.
const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { default: worker } = await import(
	'data:text/javascript;base64,' + Buffer.from(source).toString('base64')
);

const origin = 'https://proxy.example';
const proxy = url => {
	const u = new URL(url);
	return origin + '/' + encodeURIComponent(u.origin) + u.pathname.split('/').map(encodeURIComponent).join('/') + u.search;
};

async function fetchThrough(target, upstreamHeaders, body = 'body', requestHeaders = {}) {
	const originalFetch = globalThis.fetch;
	globalThis.fetch = async () => new Response(body, { headers: upstreamHeaders });
	try {
		return await worker.fetch({ url: proxy(target), method: 'GET', headers: new Headers(requestHeaders), body: null });
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
		assert.match(r.headers.get('vary'), /\bOrigin\b/i);
		await r.text();
	}
});
