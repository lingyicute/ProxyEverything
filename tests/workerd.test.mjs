import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const miniflare = process.env.PE_MINIFLARE;
const proxy = 'https://proxy.example/~https%3A%2F%2Fsite.example';
const upstream = `
export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/html') {
      const headers = new Headers({ 'Content-Type': 'text/html', 'Access-Control-Allow-Origin': '*', 'Access-Control-Expose-Headers': 'X-Fixture', Vary: 'Sec-Fetch-Site' });
      headers.append('Set-Cookie', 'first=one; HttpOnly');
      headers.append('Set-Cookie', 'second=two; Secure');
      return new Response('<!doctype html><head><base href="/assets/"></head><body><img src="a&#47;b.png?x=1&amp;y=2"><form action=""></form></body>', { headers });
    }
    if (url.pathname === '/template-base') {
      return new Response('<!doctype html><head></head><body><template><template><base href="/nested/"></template><base href="/inert/"></template><svg><base href="/foreign/"/></svg><img src="first.png"><base href="/assets/"><img src="second.png"></body>', { headers: { 'Content-Type': 'text/html' } });
    }
    if (url.pathname === '/xhtml') {
      const xml = '<?xml version="1.0" encoding="windows-1252"?><html xmlns="http://www.w3.org/1999/xhtml"><head><style>a{background:url(pic.png?x=1&amp;y=2)}</style></head><body>Caf\u00e9</body></html>';
      return new Response(Uint8Array.from(xml, c => c.charCodeAt(0)), { headers: { 'Content-Type': 'application/xhtml+xml' } });
    }
    if (url.pathname === '/style.css') {
      return new Response('a{background:url(pic.png)}', { headers: { 'Content-Type': 'text/css', 'Content-Encoding': 'gzip' } });
    }
    if (url.pathname === '/socket' || url.pathname === '/' || url.pathname === '/robots.txt') {
      const pair = new WebSocketPair();
      pair[0].accept();
      pair[0].binaryType = 'arraybuffer';
      pair[0].addEventListener('message', event => {
        pair[0].send(event.data);
        pair[0].close(4000, 'fixture finished');
      });
      return new Response(null, { status: 101, webSocket: pair[1], headers: { 'Sec-WebSocket-Protocol': 'fixture' } });
    }
    return new Response(url.pathname + url.search);
  },
};`;

test('real Workerd: HTML, compressed HTTP, URL encoding and WebSocket', {
	skip: miniflare ? false : 'Set PE_MINIFLARE to an installed Miniflare 4 module path',
	timeout: 20_000,
}, async t => {
	const { Miniflare } = createRequire(import.meta.url)(miniflare);
	const runtime = new Miniflare({
		cf: false,
		workers: [
			{
				name: 'proxy', modules: true, compatibilityDate: '2026-07-30', outboundService: 'fixture',
				scriptPath: fileURLToPath(new URL('../worker.js', import.meta.url)),
				bindings: { ALLOWED_TARGET_ORIGINS: 'https://site.example' },
			},
			{ name: 'fixture', modules: true, compatibilityDate: '2026-07-30', script: upstream },
		],
	});
	t.after(() => runtime.dispose());

	const page = await runtime.dispatchFetch(proxy + '/html');
	assert.equal(page.status, 200);
	assert.equal(page.headers.get('Access-Control-Allow-Origin'), null);
	assert.equal(page.headers.get('Access-Control-Expose-Headers'), null);
	assert.match(page.headers.get('Vary'), /\bOrigin\b/i);
	assert.match(page.headers.get('Vary'), /\bReferer\b/i);
	const html = await page.text();
	assert.ok(html.includes('src="' + proxy + '/assets/a/b.png?x=1&amp;y=2"'));
	assert.match(html, /<form action="">/);
	assert.equal(page.headers.getSetCookie().length, 2);

	const templates = await (await runtime.dispatchFetch(proxy + '/template-base')).text();
	assert.ok(templates.includes('<base href="/inert/">'));
	assert.ok(templates.includes('src="' + proxy + '/first.png"'));
	assert.ok(templates.includes('src="' + proxy + '/assets/second.png"'));

	const xhtml = await runtime.dispatchFetch(proxy + '/xhtml');
	const xml = await xhtml.text();
	assert.equal(xhtml.status, 200, xml.match(/<p class="t-body-md muted">([^<]+)/)?.[1]);
	assert.equal(xhtml.headers.get('Content-Type'), 'application/xhtml+xml; charset=UTF-8');
	assert.match(xml, /^<\?xml version="1\.0" encoding="UTF-8"\?>/);
	assert.match(xml, /Caf\u00e9/);
	assert.ok(xml.includes(proxy + '/pic.png?x=1&amp;y=2'));

	const css = await runtime.dispatchFetch(proxy + '/style.css');
	assert.equal(await css.text(), `a{background:url("${proxy}/pic.png")}`);
	const path = await runtime.dispatchFetch(proxy + '/asset/a%2Fb?x=1');
	assert.equal(await path.text(), '/asset/a%2Fb?x=1');

	for (const url of [proxy + '/socket', 'https://proxy.example/', 'https://proxy.example/robots.txt']) {
		const upgrade = await runtime.dispatchFetch(url, {
			headers: { Upgrade: 'websocket', 'Sec-WebSocket-Protocol': 'fixture', Referer: proxy + '/html' },
		});
		assert.equal(upgrade.status, 101);
		assert.equal(upgrade.headers.get('Sec-WebSocket-Protocol'), 'fixture');
		const socket = upgrade.webSocket;
		socket.accept();
		const result = new Promise((resolve, reject) => {
			const messages = [];
			socket.addEventListener('message', event => messages.push(Buffer.from(event.data)));
			socket.addEventListener('error', reject);
			socket.addEventListener('close', event => resolve({ messages, code: event.code, reason: event.reason }));
		});
		const payload = new Uint8Array([0, 1, 255]);
		socket.send(payload.buffer);
		assert.deepEqual(await result, { messages: [Buffer.from(payload)], code: 4000, reason: 'fixture finished' });
	}
	assert.match(await (await runtime.dispatchFetch('https://proxy.example/')).text(), /Proxy Everything/);
	assert.match(await (await runtime.dispatchFetch('https://proxy.example/robots.txt')).text(), /Disallow: \//);
});
