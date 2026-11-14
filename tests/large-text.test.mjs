import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { default: worker } = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
const origin = 'https://proxy.example';
const limit = 2 * 1024 * 1024;

function upstreamResponse(bytes, contentType) {
	const boundaries = [0, 3, 81_919, 1_019_039, bytes.length];
	let next = 0;
	const body = new ReadableStream({
		pull(controller) {
			if (next === boundaries.length - 1) return controller.close();
			controller.enqueue(bytes.subarray(boundaries[next], boundaries[++next]));
		},
	});
	return new Response(body, { headers: {
		'Content-Type': contentType,
		'Content-Length': String(bytes.length),
		'Content-Encoding': 'identity',
		ETag: '"source-v1"',
		'Last-Modified': 'Wed, 01 Jan 2025 00:00:00 GMT',
		'Cache-Control': 'public, max-age=3600',
	} });
}

async function proxyResponse(bytes, contentType, path) {
	const originalFetch = globalThis.fetch;
	globalThis.fetch = async () => upstreamResponse(bytes, contentType);
	try {
		return await worker.fetch(new Request(origin + '/' + encodeURIComponent('https://site.example') + path), {});
	} finally {
		globalThis.fetch = originalFetch;
	}
}

for (const [name, mime, path, prefix, suffix] of [
	['CSS', 'text/css', '/assets/style.css', '@charset "windows-1252";body{background:url(logo.png)}/*é', '*/'],
	['JavaScript', 'application/javascript', '/assets/main.js', 'import "./part.js";/*é', '*/'],
	['SVG', 'image/svg+xml', '/assets/icon.svg', '<?xml version="1.0" encoding="windows-1252"?><svg><!--é', '--></svg>'],
	['manifest', 'application/manifest+json', '/assets/app.webmanifest', '{"start_url":"/home","pad":"é', '"}'],
]) {
	test(`oversized ${name} keeps original bytes, charset and validators`, async () => {
		const input = Buffer.alloc(limit + 57, 0x20);
		input.write(prefix, 0, 'latin1');
		input.write(suffix, input.length - Buffer.byteLength(suffix, 'latin1'), 'latin1');
		const contentType = mime + '; charset=windows-1252';
		const response = await proxyResponse(input, contentType, path);
		assert.equal(response.status, 200);
		assert.equal(response.headers.get('content-type'), contentType);
		assert.equal(response.headers.get('content-length'), String(input.length));
		assert.equal(response.headers.get('content-encoding'), 'identity');
		assert.equal(response.headers.get('etag'), '"source-v1"');
		assert.equal(response.headers.get('last-modified'), 'Wed, 01 Jan 2025 00:00:00 GMT');
		assert.equal(response.headers.get('cache-control'), 'public, max-age=3600');
		assert.deepEqual(Buffer.from(await response.arrayBuffer()), input);
	});
}

test('CSS exactly at the buffer limit is transformed rather than passed through', async () => {
	const input = Buffer.alloc(limit, 0x20);
	input.write('@import "theme.css";', 0, 'latin1');
	const response = await proxyResponse(input, 'text/css; charset=windows-1252', '/assets/style.css');
	assert.equal(response.headers.get('content-type'), 'text/css; charset=UTF-8');
	assert.equal(response.headers.get('content-length'), null);
	assert.equal(response.headers.get('etag'), null);
	assert.ok((await response.text()).startsWith(
		'@import "' + origin + '/https%3A%2F%2Fsite.example/assets/theme.css";'));
});

test('small CSS is still decoded, rewritten and marked as a new representation', async () => {
	const input = Buffer.from('body{content:"é";background:url(logo.png)}', 'latin1');
	const response = await proxyResponse(input, 'text/css; charset=windows-1252', '/assets/style.css');
	assert.equal(response.status, 200);
	assert.equal(response.headers.get('content-type'), 'text/css; charset=UTF-8');
	for (const header of ['content-length', 'content-encoding', 'etag', 'last-modified']) {
		assert.equal(response.headers.get(header), null);
	}
	const text = await response.text();
	assert.ok(text.includes('content:"é"'));
	assert.ok(text.includes('url("' + origin + '/https%3A%2F%2Fsite.example/assets/logo.png")'));
});
