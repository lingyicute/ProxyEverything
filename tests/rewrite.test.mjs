import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

// Load the standalone Worker as an ES module without changing its deployment exports.
const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { default: worker, rewriteCss, rewriteLazyValue, rewriteSvg, cookieNamespace, getShimScript } = await import(
	'data:text/javascript;base64,' + Buffer.from(source +
		'\nexport { rewriteCss, rewriteLazyValue, rewriteSvg, cookieNamespace, getShimScript };').toString('base64')
);

const base = 'https://example.com/dir/page';
const origin = 'https://proxy.example';
const proxy = (url) => {
	const u = new URL(url, base);
	return origin + '/' + encodeURIComponent(u.origin + u.pathname) + u.search;
};

test('css: @namespace URLs are identifiers and stay untouched', () => {
	const ns = '@namespace svg url(http://www.w3.org/2000/svg);';
	assert.equal(rewriteCss(ns, base, origin), ns);
	assert.equal(rewriteCss(ns + 'a{background:url(a.png)}', base, origin),
		ns + `a{background:url("${proxy('a.png')}")}`);
});

test('css: every @namespace form stays literal and ends at its own terminator', () => {
	const input = [
		'@namespace url("http://www.w3.org/1999/xhtml");',
		'@namespace x "http://example.com/ns" /* ; */;',
		'@namespace svg url(http://www.w3.org/2000/svg)',
	].join('\n');
	// The last prelude is unterminated: it ends at the next block, whose url() is a real resource.
	assert.equal(rewriteCss(input + '\n.a{background:url(b.png)}', base, origin),
		input + `\n.a{background:url("${proxy('b.png')}")}`);
	assert.equal(rewriteCss('@namespace x "http://example.com/ns";@import "c.css";', base, origin),
		`@namespace x "http://example.com/ns";@import "${proxy('c.css')}";`);
});

test('shim: script is valid both as HTML raw text and as XHTML CDATA content', () => {
	const shim = getShimScript(origin, '__pe_x_');
	assert.ok(shim.startsWith('<script>//<![CDATA[\n'));
	assert.ok(shim.endsWith('\n//]]></script>'));
	const html = shim.slice('<script>'.length, -'</script>'.length);
	const inner = html.slice('//<![CDATA['.length, -'//]]>'.length);
	assert.ok(!inner.includes(']]>'), 'the CDATA section must not be closed early');
	assert.ok(!/<\/|<!--/.test(inner), 'the HTML tokenizer must not leave script data early');
	assert.doesNotThrow(() => new vm.Script(html));
	assert.doesNotThrow(() => new vm.Script('//' + inner + '//'));
});

test('lazy data-*: only URL-like values are rewritten', () => {
	const lazy = (value, attr = 'data-src') => rewriteLazyValue(attr, value, base, origin);
	for (const value of ['true', '1', '0.5', 'dark', '{"src":"a/b.png"}', 'Read more...', 'rgba(0,0,0,.5)']) {
		assert.equal(lazy(value), value);
	}
	assert.equal(lazy('img/a.jpg'), proxy('img/a.jpg'));
	assert.equal(lazy('/uploads/My Photo.jpg'), proxy('/uploads/My Photo.jpg'));
	assert.equal(lazy('?page=2'), proxy('?page=2'));
	assert.equal(lazy('url(lazy.jpg)', 'data-bg'), `url("${proxy('lazy.jpg')}")`);
	assert.equal(lazy('a.png 1x, b.png 2x', 'data-srcset'), `${proxy('a.png')} 1x, ${proxy('b.png')} 2x`);
});

test('svg: attribute-like text inside quoted values is left alone', () => {
	const svg = `<svg><a onclick="location.href='/x'" title="see href='q'" href='p.html'/></svg>`;
	assert.equal(rewriteSvg(svg, base, origin),
		`<svg><a onclick="location.href='/x'" title="see href='q'" href="${proxy('p.html')}"/></svg>`);
});

// Call the fetch handler directly; the upstream is a stub that records the forwarded request.
let forwarded = null;
globalThis.fetch = async (url, init) => {
	forwarded = { url: String(url), headers: new Headers(init.headers) };
	return new Response('PNG', { headers: { 'content-type': 'image/png', 'cache-control': 'public, max-age=3600' } });
};
const send = (url, { method = 'GET', headers = {} } = {}) => {
	forwarded = null;
	return worker.fetch({ url, method, headers: new Headers(headers), body: null });
};
const referer = proxy('https://example.com/dir/page?secret=1');

test('upstream Referer: full URL same-origin, origin only cross-origin', async () => {
	await send(proxy('https://example.com/img.png'), { headers: { referer } });
	assert.equal(forwarded.headers.get('referer'), 'https://example.com/dir/page?secret=1');
	await send(proxy('https://cdn.example.net/img.png'), { headers: { referer } });
	assert.equal(forwarded.headers.get('referer'), 'https://example.com/');
});

test('upstream Origin: referring origin for CORS and non-GET requests only', async () => {
	const target = proxy('https://api.example.net/data');
	await send(target, { headers: { referer, 'sec-fetch-mode': 'cors' } });
	assert.equal(forwarded.headers.get('origin'), 'https://example.com');
	await send(target, { method: 'POST', headers: { referer, origin } });
	assert.equal(forwarded.headers.get('origin'), 'https://example.com');
	await send(target, { headers: { referer, 'sec-fetch-mode': 'no-cors' } });
	assert.equal(forwarded.headers.get('origin'), 'https://api.example.net');
});

test('cache policy: only cookies forwarded to the target disable caching', async () => {
	const target = proxy('https://example.com/img.png');
	const ns = cookieNamespace(new URL('https://example.com/'));
	let response = await send(target, { headers: { cookie: 'unrelated=1; __pe_x_other_=1' } });
	assert.equal(forwarded.headers.get('cookie'), null);
	assert.equal(response.headers.get('cache-control'), 'public, max-age=3600');
	response = await send(target, { headers: { cookie: ns + 'sid=1' } });
	assert.equal(forwarded.headers.get('cookie'), 'sid=1');
	assert.equal(response.headers.get('cache-control'), 'no-store');
});

test('site-relative requests that escaped rewriting are redirected via Referer', async () => {
	let response = await send(origin + '/static/app.js?v=1', { headers: { referer } });
	assert.equal(response.status, 307);
	assert.equal(response.headers.get('location'), proxy('/static/app.js?v=1'));
	assert.equal(forwarded, null);
	response = await send(origin + '/static/app.js');
	assert.equal(response.status, 400);
});
