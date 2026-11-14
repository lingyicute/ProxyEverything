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
function collectHandlers() {
	const handlers = {};
	globalThis.HTMLRewriter = class {
		on(selector, handler) { (handlers[selector] ||= []).push(handler); return this; }
		transform(response) { return response; }
	};
	try {
		transformHtml(new Response('', { headers: { 'content-type': 'text/html' } }), base, origin, null);
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
	assert.equal(run('form', { action: '' }).getAttribute('action'), proxy('/dir/page'));
	assert.equal(run('button', { formaction: '', formmethod: 'dialog' }).getAttribute('formaction'), '');
	assert.equal(run('button', { formaction: '' }).getAttribute('formaction'), proxy('/dir/page'));
});
