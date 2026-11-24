import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { default: worker, cookieNamespace, scopeSetCookie, scopeRequestCookie, getShimScript } = await import(
	'data:text/javascript;base64,' + Buffer.from(source + '\nexport { cookieNamespace, scopeSetCookie, scopeRequestCookie, getShimScript };').toString('base64')
);
const origin = 'https://proxy.example';
const targetOrigin = 'https://example.com';
const target = targetOrigin + '/dir/page';
const namespace = cookieNamespace(new URL(target));
const proxy = path => origin + '/~' + encodeURIComponent(targetOrigin) + path;
const scoped = value => scopeSetCookie(value, namespace, true, false, target);
const pair = value => value.split(';', 1)[0];

test('cookie path matching, defaults, duplicate names and deletion are preserved', () => {
	const root = scoped('sid=root; Path=/');
	const dir = scoped('sid=dir; Path=/dir');
	const sub = scoped('sid=sub; Path=/dir/sub');
	const byDefault = scoped('default=1');
	const invalidPath = scoped('invalid=1; Path=relative');
	const header = [root, dir, sub, byDefault, invalidPath].map(pair).join('; ');
	assert.equal(scopeRequestCookie(header, namespace, '/dir/sub/page'), 'sid=sub; sid=dir; default=1; invalid=1; sid=root');
	assert.equal(scopeRequestCookie(header, namespace, '/dir'), 'sid=dir; default=1; invalid=1; sid=root');
	assert.equal(scopeRequestCookie(header, namespace, '/directory'), 'sid=root');
	assert.equal(scopeRequestCookie(header, namespace, '/'), 'sid=root');
	assert.equal(pair(scoped('sid=; Max-Age=0; Path=/dir')), pair(dir).replace('=dir', '='));
	assert.notEqual(pair(root).split('=')[0], pair(dir).split('=')[0]);
	assert.equal(pair(scoped('root=1; Path=/')), namespace + 'root=1');
});

test('path markers cannot collide with ordinary names and keep protected prefixes', () => {
	const odd = scoped("__Secure-token=1; Secure; Path=/a(1)/");
	const plain = scoped('__pepath_token=2; Path=/');
	assert.ok(odd.startsWith('__Secure-__pepath_'));
	assert.match(odd, /%28/);
	assert.equal(scopeRequestCookie([pair(odd), pair(plain)].join('; '), namespace, '/a(1)/next'), '__Secure-token=1; __pepath_token=2');
	assert.equal(scopeRequestCookie([pair(odd), pair(plain)].join('; '), namespace, '/elsewhere'), '__pepath_token=2');
	assert.equal(scoped('__Host-token=1; Secure; Path=/'), '__Host-' + namespace + 'token=1; Secure; Path=/');
	assert.equal(scoped('__Host-token=1; Secure; Path=/dir'), null);
});

test('HTTP and WebSocket forwarding send only cookies matching the target path', async t => {
	let sent;
	let responseHeaders = new Headers({ 'Content-Type': 'text/plain' });
	for (const cookie of ['sid=root; Path=/', 'sid=dir; Path=/dir', 'sid=sub; Path=/dir/sub', 'default=1']) {
		responseHeaders.append('Set-Cookie', cookie);
	}
	t.mock.method(globalThis, 'fetch', async (_, init) => {
		sent = new Headers(init.headers);
		return new Response('ok', { status: init.headers.get('Upgrade') ? 403 : 200, headers: responseHeaders });
	});
	const env = { ALLOWED_TARGET_ORIGINS: targetOrigin };
	const response = await worker.fetch(new Request(proxy('/dir/page')), env);
	const cookies = response.headers.getSetCookie().map(pair).join('; ');
	responseHeaders = new Headers();
	await worker.fetch(new Request(proxy('/dir/sub/page'), { headers: { Cookie: cookies } }), env);
	assert.equal(sent.get('Cookie'), 'sid=sub; sid=dir; default=1; sid=root');
	await worker.fetch(new Request(proxy('/directory'), { headers: { Cookie: cookies } }), env);
	assert.equal(sent.get('Cookie'), 'sid=root');
	await worker.fetch(new Request(proxy('/dir/socket'), { headers: { Cookie: cookies, Upgrade: 'websocket' } }), env);
	assert.equal(sent.get('Cookie'), 'sid=dir; default=1; sid=root');
});

test('document.cookie filters and orders paths and computes the default from the current target', () => {
	let last = '';
	let jar = [scoped('sid=root; Path=/'), scoped('sid=dir; Path=/dir'), scoped('sid=sub; Path=/dir/sub')].map(pair).join('; ');
	class Document {
		get cookie() { return jar; }
		set cookie(value) { last = value; }
	}
	class Element { setAttribute() {} removeAttribute() {} }
	class XMLHttpRequest { open() {} }
	const document = new Document();
	document.querySelectorAll = () => [];
	document.addEventListener = () => {};
	const location = { href: proxy('/dir/sub/page'), origin, protocol: 'https:', hostname: 'proxy.example', port: '', pathname: new URL(proxy('/dir/sub/page')).pathname };
	const ctx = { URL, Document, Element, XMLHttpRequest, document, navigator: {}, history: {}, console, location };
	ctx.window = ctx;
	vm.runInNewContext(getShimScript(origin, namespace).replace(/^<script>/, '').replace(/<\/script>$/, ''), ctx);
	assert.equal(document.cookie, 'sid=sub; sid=dir; sid=root');
	document.cookie = 'new=1';
	assert.equal(last, scopeSetCookie('new=1; Path=/dir/sub', namespace, true, false, target));
	location.href = proxy('/directory');
	location.pathname = new URL(location.href).pathname;
	assert.equal(document.cookie, 'sid=root');
	jar = '';
	assert.equal(document.cookie, '');
});
