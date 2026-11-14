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

async function fetchThrough(target, upstreamHeaders, body = 'body') {
	const originalFetch = globalThis.fetch;
	globalThis.fetch = async () => new Response(body, { headers: upstreamHeaders });
	try {
		return await worker.fetch({ url: proxy(target), method: 'GET', headers: new Headers(), body: null });
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
