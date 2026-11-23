import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

// Load the standalone Worker as an ES module without changing its deployment exports.
const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { transformHtml } = await import(
	'data:text/javascript;base64,' + Buffer.from(source + '\nexport { transformHtml };').toString('base64')
);

const base = 'https://example.com/dir/page';
const origin = 'https://proxy.example';
const proxy = path => origin + '/' + encodeURIComponent('https://example.com') + path;

/** HTMLRewriter 只在 Workers 运行时存在：记录各选择器的处理器，直接驱动元素回调。 */
function collectHandlers(contentType = 'text/html', sourceCharset = null) {
	const handlers = {};
	globalThis.HTMLRewriter = class {
		on(selector, handler) { (handlers[selector] ||= []).push(handler); return this; }
		transform(response) { return response; }
	};
	try {
		transformHtml(new Response('', { headers: { 'content-type': contentType } }), base, origin, null, sourceCharset);
	} finally {
		delete globalThis.HTMLRewriter;
	}
	return handlers;
}

test('html: external scripts keep the source document encoding after transcoding to UTF-8', () => {
	const run = (handlers, attrs) => {
		const el = element('script', attrs);
		for (const h of handlers.script) h.element(el);
		return el.getAttribute('charset');
	};
	const legacy = collectHandlers('text/html', 'gbk');
	assert.equal(run(legacy, { src: 'a.js' }), 'gbk');
	assert.equal(run(legacy, { src: 'a.js', charset: 'utf-8' }), 'utf-8', 'an explicit charset wins');
	assert.equal(run(legacy, {}), null, 'inline scripts are not fetched');
	assert.equal(run(collectHandlers('application/xhtml+xml', 'windows-1252'), { src: 'a.js' }), 'windows-1252');
	for (const charset of [null, 'utf-8']) {
		assert.equal(run(collectHandlers('text/html', charset), { src: 'a.js' }), null, String(charset));
	}
});

function element(tag, attrs) {
	const map = new Map(Object.entries(attrs));
	const writes = [];
	return {
		tagName: tag,
		namespaceURI: 'http://www.w3.org/1999/xhtml',
		writes,
		get attributes() { return map.entries(); },
		getAttribute: name => (map.has(name) ? map.get(name) : null),
		hasAttribute: name => map.has(name),
		setAttribute(name, value) { writes.push(name); map.set(name, value); },
		removeAttribute(name) { writes.push('-' + name); map.delete(name); },
	};
}

test('html: URL attributes are only written back when the rewrite changes them', () => {
	const handlers = collectHandlers();
	const run = (tag, attrs) => {
		const el = element(tag, attrs);
		for (const h of handlers[tag]) h.element(el);
		return el;
	};

	for (const href of ['#top', 'javascript:void(0)', 'mailto:a@example.com', 'data:,x']) {
		assert.deepEqual(run('a', { href }).writes, [], href);
	}
	assert.deepEqual(run('img', { src: 'data:image/gif;base64,R0lGOD', srcset: 'data:image/gif;base64,R0lGOD 1x' }).writes, []);
	assert.deepEqual(run('a', { href: '  #top  ' }).writes, ['href'], 'trimming is still persisted');

	const link = run('a', { href: '/x', ping: '/p' });
	assert.equal(link.getAttribute('href'), proxy('/x'));
	assert.equal(link.getAttribute('ping'), proxy('/p'));
	assert.equal(run('form', { action: '' }).getAttribute('action'), '');
	assert.equal(run('button', { formaction: '', formmethod: 'dialog' }).getAttribute('formaction'), '');
	assert.equal(run('button', { formaction: '' }).getAttribute('formaction'), '');
});

test('HTML base affects anchor fragments, but not absent or empty form actions', () => {
	const handlers = collectHandlers();
	handlers.base[0].element(element('base', { href: '/other/' }));
	for (const [tag, attrs, key, expected] of [
		['a', { href: '#heading' }, 'href', proxy('/other/#heading')],
		['a', { href: '' }, 'href', proxy('/other/')],
		['form', {}, 'action', null],
		['form', { action: '' }, 'action', ''],
		['form', { action: 'finish' }, 'action', proxy('/other/finish')],
		['button', { formaction: '' }, 'formaction', ''],
	]) {
		const el = element(tag, attrs);
		for (const h of handlers[tag]) h.element(el);
		assert.equal(el.getAttribute(key), expected);
	}
});

test('HTML base ignores inert template contents and foreign namespaces', () => {
	const handlers = collectHandlers();
	let endOuter = null;
	let endInner = null;
	const outerTpl = Object.assign(element('template', {}), { onEndTag(fn) { endOuter = fn; } });
	const innerTpl = Object.assign(element('template', {}), { onEndTag(fn) { endInner = fn; } });
	handlers.template[0].element(outerTpl);
	handlers.template[0].element(innerTpl);
	handlers.base[0].element(element('base', { href: '/nested/' }));
	endInner();
	handlers.base[0].element(element('base', { href: '/inert/' }));
	endOuter();

	const svgBase = Object.assign(element('base', { href: '/foreign/' }), { namespaceURI: 'http://www.w3.org/2000/svg' });
	handlers.base[0].element(svgBase);
	assert.equal(svgBase.getAttribute('href'), '/foreign/');

	const firstImg = element('img', { src: 'first.png' });
	handlers.img[0].element(firstImg);
	assert.equal(firstImg.getAttribute('src'), proxy('/dir/first.png'));

	handlers.base[0].element(element('base', { href: '/assets/' }));
	const secondImg = element('img', { src: 'second.png' });
	handlers.img[0].element(secondImg);
	assert.equal(secondImg.getAttribute('src'), proxy('/assets/second.png'));
});

test('HTML base freezes at the first base element with href even when disallowed', () => {
	const handlers = collectHandlers();
	const first = element('base', { href: 'javascript:void(0)' });
	const second = element('base', { href: 'https://other.example/sub/' });
	handlers.base[0].element(first);
	handlers.base[0].element(second);
	assert.equal(first.getAttribute('data-pe-base'), '');
	assert.equal(second.getAttribute('data-pe-base'), 'https://other.example/sub/');
	const link = element('a', { href: 'rel.html' });
	handlers.a[0].element(link);
	assert.equal(link.getAttribute('href'), proxy('/dir/rel.html'));
});
