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
