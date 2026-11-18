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
const proxy = path => origin + '/~' + encodeURIComponent('https://example.com') + path;

/** HTMLRewriter 只在 Workers 运行时存在：记录各选择器的处理器，直接驱动元素回调。 */
function collectHandlers(contentType = 'text/html') {
	const handlers = {};
	globalThis.HTMLRewriter = class {
		on(selector, handler) { (handlers[selector] ||= []).push(handler); return this; }
		transform(response) { return response; }
	};
	try {
		transformHtml(new Response('', { headers: { 'content-type': contentType } }), base, origin, null);
	} finally {
		delete globalThis.HTMLRewriter;
	}
	return handlers;
}

function element(tag, attrs) {
	const map = new Map(Object.entries(attrs));
	const writes = [];
	return {
		tagName: tag,
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

test('HTMLRewriter URL and style attributes decode references once and escape serialization', () => {
	const handlers = collectHandlers();
	const image = element('img', { src: 'a&#47;b&sol;c.png?x=1&amp;y=2&copy=raw' });
	handlers.img[0].element(image);
	assert.equal(image.getAttribute('src'), proxy('/dir/a/b/c.png?x=1&amp;y=2&amp;copy=raw'));

	const link = element('a', { href: '&#35;anchor' });
	handlers.a[0].element(link);
	assert.deepEqual(link.writes, []);

	const panel = element('div', { style: 'background:url(&quot;tile.png?a=1&amp;b=2&quot;)' });
	panel.before = () => {};
	handlers['*'][0].element(panel);
	assert.equal(panel.getAttribute('style'), `background:url(&quot;${proxy('/dir/tile.png?a=1&amp;b=2')}&quot;)`);
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

test('XHTML style uses XML escaping while ordinary HTML uses raw text', () => {
	const input = 'a{background:url(pic.png?a=1&amp;b=2)}';
	const xhtml = collectHandlers('application/xhtml+xml').style[0];
	xhtml.element({});
	let out;
	xhtml.text({ text: input, lastInTextNode: true, replace(value) { out = value; } });
	assert.equal(out, `a{background:url("${proxy('/dir/pic.png?a=1&amp;b=2')}")}`);
});

test('SVG presentation attributes in HTML recognize escaped CSS url functions', () => {
	const handlers = collectHandlers();
	const path = element('path', { fill: String.raw`\75 rl(pattern.svg#paint)` });
	path.before = () => {};
	handlers['*'][0].element(path);
	assert.equal(path.getAttribute('fill'), `url(&quot;${proxy('/dir/pattern.svg#paint')}&quot;)`);
});

test('srcset preserves internal commas, data URLs and candidate separators', () => {
	const image = element('img', { srcset: 'first,a.png 1x, data:image/gif;base64,token 2x, last.png,, ' });
	collectHandlers().img[0].element(image);
	assert.equal(image.getAttribute('srcset'), `${proxy('/dir/first,a.png')} 1x, data:image/gif;base64,token 2x, ${proxy('/dir/last.png')},, `);
});
