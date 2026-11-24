import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { default: worker, cookieNamespace, scopeSetCookie, getShimScript } = await import(
	'data:text/javascript;base64,' + Buffer.from(source + '\nexport { cookieNamespace, scopeSetCookie, getShimScript };').toString('base64')
);
const target = 'https://api.example.com/dir/page';
const origin = 'https://proxy.example';
const namespace = cookieNamespace(new URL(target));
const proxy = origin + '/~' + encodeURIComponent(new URL(target).origin) + '/dir/page';

test('cookie Domain is checked against the original host before it is removed', () => {
	for (const domain of ['api.example.com', '.example.com', 'EXAMPLE.COM', '']) {
		const out = scopeSetCookie('sid=ok; Domain=' + domain, namespace, true, false, target);
		assert.equal(out, namespace + 'sid=ok; Path=/', domain);
	}
	for (const domain of ['other.example.com', 'ample.com', '.com', 'example.com.', '..example.com',
		'example.com:443', '%65xample.com', 'example.com/path', '']) {
		if (!domain) continue; // An empty Domain attribute is ignored by browsers.
		assert.equal(scopeSetCookie('sid=bad; Domain=' + domain, namespace, true, false, target), null, domain);
	}
	assert.equal(scopeSetCookie('sid=bad; Domain=example.com', namespace, true), null);
	assert.equal(scopeSetCookie('sid=ok; Domain=evil.example; Domain=.example.com', namespace, true, false, target), namespace + 'sid=ok; Path=/');
	assert.equal(scopeSetCookie('sid=bad; Domain=.example.com; Domain=evil.example; Domain=', namespace, true, false, target), null);
	assert.notEqual(scopeSetCookie('sid=ok; Domain=bücher.example', namespace, true, false, 'https://api.bücher.example/'), null);
	assert.equal(scopeSetCookie('__Host-sid=bad; Secure; Path=/; Domain=', namespace, true, false, target), null);
});

test('HTTP responses discard cookies for an unrelated Domain', async t => {
	const headers = new Headers({ 'Content-Type': 'text/plain' });
	headers.append('Set-Cookie', 'valid=1; Domain=.example.com; Secure');
	headers.append('Set-Cookie', 'invalid=2; Domain=elsewhere.example; Secure');
	t.mock.method(globalThis, 'fetch', async () => new Response('ok', { headers }));
	const response = await worker.fetch(new Request(proxy), { ALLOWED_TARGET_ORIGINS: 'https://api.example.com' });
	assert.deepEqual(response.headers.getSetCookie(), [namespace + 'valid=1; Secure; Path=/']);
});

test('document.cookie applies the same Domain check as HTTP responses', () => {
	let last = '';
	class Document {
		get cookie() { return ''; }
		set cookie(value) { last = value; }
	}
	class Element { setAttribute() {} removeAttribute() {} }
	class XMLHttpRequest { open() {} }
	const document = new Document();
	document.querySelectorAll = () => [];
	document.addEventListener = () => {};
	const ctx = {
		URL, Document, Element, XMLHttpRequest, document, navigator: {}, history: {}, console,
		location: { href: proxy, origin, protocol: 'https:', hostname: 'proxy.example', port: '', pathname: new URL(proxy).pathname },
	};
	ctx.window = ctx;
	vm.runInNewContext(getShimScript(origin, namespace).replace(/^<script>/, '').replace(/<\/script>$/, ''), ctx);
	document.cookie = 'bad=1; Domain=elsewhere.example';
	assert.equal(last, '');
	document.cookie = 'good=1; Domain=.example.com';
	assert.equal(last, namespace + 'good=1; Path=/');
});
