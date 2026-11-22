import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { default: worker, readTransformText, rewriteCss, rewriteJsModuleSpecifiers, rewriteSrcset,
	rewriteImportMap, rewriteSpeculationRules, rewriteSvg, rewriteJsonUrls } = await import(
	'data:text/javascript;base64,' + Buffer.from(source + '\nexport { readTransformText, rewriteCss, rewriteJsModuleSpecifiers, rewriteSrcset, rewriteImportMap, rewriteSpeculationRules, rewriteSvg, rewriteJsonUrls };').toString('base64')
);
const origin = 'https://proxy.example';
const limit = 2 * 1024 * 1024;

function upstreamResponse(bytes, contentType, encoding = 'identity') {
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
		'Content-Encoding': encoding,
		ETag: '"source-v1"',
		'Last-Modified': 'Wed, 01 Jan 2025 00:00:00 GMT',
		'Cache-Control': 'public, max-age=3600',
	} });
}

async function proxyResponse(bytes, contentType, path, encoding) {
	const originalFetch = globalThis.fetch;
	globalThis.fetch = async () => upstreamResponse(bytes, contentType, encoding);
	try {
		return await worker.fetch(new Request(origin + '/~' + encodeURIComponent('https://site.example') + path), {
			ALLOWED_TARGET_ORIGINS: 'https://site.example',
		});
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
		'@import "' + origin + '/~https%3A%2F%2Fsite.example/assets/theme.css";'));
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
	assert.ok(text.includes('url("' + origin + '/~https%3A%2F%2Fsite.example/assets/logo.png")'));
});

test('oversized decoded HTTP streams do not re-use the original encoded validators', async () => {
	const bytes = Buffer.alloc(limit + 57, 0x20);
	const type = 'text/css; charset=windows-1252';
	// In Workerd the HTTP stream is decoded when read, but still carries the wire headers.
	const response = await proxyResponse(bytes, type, '/assets/large.css', 'gzip');
	assert.equal(response.headers.get('content-type'), type);
	assert.equal(response.headers.get('content-encoding'), 'gzip');
	for (const header of ['content-length', 'etag', 'last-modified']) assert.equal(response.headers.get(header), null);
	assert.deepEqual(Buffer.from(await response.arrayBuffer()), bytes);
});

test('bounded text reader accepts fragmented multibyte text', async () => {
	const input = '海😀'.repeat(700);
	const bytes = Buffer.from(input);
	let offset = 0;
	const stream = new ReadableStream({
		pull(controller) {
			if (offset === bytes.length) controller.close();
			else controller.enqueue(bytes.subarray(offset, ++offset));
		},
	});
	assert.equal((await readTransformText(stream)).text, input);
	assert.equal(stream.locked, false);
});

test('canceling an oversized stream releases the upstream reader', async () => {
	let canceled;
	const stream = new ReadableStream({
		start(controller) { controller.enqueue(new Uint8Array(limit + 1)); },
		cancel(reason) { canceled = reason; },
	});
	const { passthrough } = await readTransformText(stream);
	await passthrough.cancel('consumer stopped');
	assert.equal(canceled, 'consumer stopped');
	assert.equal(stream.locked, false);
});

test('CSS only sniffs the exact @charset byte signature within the first 1024 bytes', async () => {
	for (const prefix of ["@charset 'windows-1252';", '@CHARSET "windows-1252";',
		'@charset  "windows-1252";', '@charset "windows-1252" ;',
		'@charset "' + ' '.repeat(1010) + 'windows-1252";']) {
		const css = prefix + 'a{content:"海"}';
		const r = await proxyResponse(Buffer.from(css), 'text/css', '/sheet.css');
		assert.equal(await r.text(), css);
	}
	const prefix = '@charset "' + ' '.repeat(1000) + 'windows-1252";';
	assert.equal(prefix.length, 1024);
	const r = await proxyResponse(Buffer.from(prefix + 'a{content:"é"}', 'latin1'), 'text/css', '/sheet.css');
	assert.equal(await r.text(), '@charset "UTF-8";a{content:"é"}');
});

test('CSS, JavaScript and srcset keep their full source when rewrite expansion hits the budget', () => {
	const base = 'https://site.example/' + 'folder/'.repeat(1100) + 'page';
	for (const [rewrite, unit] of [
		[rewriteCss, '.tile{background:url(tile.png)}'],
		[rewriteJsModuleSpecifiers, 'import "./part.js";'],
		[rewriteSrcset, 'tile.png 1x, '],
	]) {
		assert.ok(rewrite(unit, base, origin).includes(origin + '/~'));
		const source = unit.repeat(650);
		assert.equal(rewrite(source, base, origin), source);
	}
});

test('XML and JSON documents stop accumulating rewritten URLs across members', () => {
	const base = 'https://site.example/' + 'folder/'.repeat(1100) + 'doc';
	for (const [rewrite, make] of [
		[rewriteSvg, n => '<svg>' + '<image href="tile.png"/>'.repeat(n) + '</svg>'],
		[rewriteImportMap, n => JSON.stringify({ imports: Object.fromEntries(Array.from({ length: n }, (_, i) => ['part-' + i, './part.js'])) })],
		[rewriteSpeculationRules, n => JSON.stringify({ prefetch: [{ urls: Array(n).fill('page.html') }] })],
		[rewriteJsonUrls, n => JSON.stringify({ icons: Array(n).fill({ src: 'tile.png' }) })],
	]) {
		assert.ok(rewrite(make(1), base, origin).includes(origin + '/~'));
		const source = make(650);
		assert.equal(rewrite(source, base, origin), source);
	}
});
