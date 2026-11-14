import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

// Load the standalone Worker as an ES module without changing its deployment exports.
const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { getShimScript } = await import(
	'data:text/javascript;base64,' + Buffer.from(source + '\nexport { getShimScript };').toString('base64')
);

const origin = 'https://proxy.example';
const proxy = path => origin + '/' + encodeURIComponent('https://example.com') + path;

/** 只提供 shim 安装钩子所需的最小浏览器环境；shim 内部异常记入 errors。 */
function createBrowser() {
	class Element {
		constructor(tag) {
			this.localName = tag.toLowerCase();
			this.tagName = tag.toUpperCase();
			this.attrs = new Map();
		}
		setAttribute(name, value) { this.attrs.set(String(name).toLowerCase(), String(value)); }
		setAttributeNS(ns, name, value) { this.attrs.set(String(name).toLowerCase(), String(value)); }
		getAttribute(name) { return this.attrs.has(name) ? this.attrs.get(name) : null; }
		removeAttribute(name) { this.attrs.delete(name); }
		removeAttributeNS(ns, name) { this.attrs.delete(name); }
	}
	class XMLHttpRequest { open() {} }
	const errors = [];
	const ctx = {
		URL,
		Element,
		XMLHttpRequest,
		console: { error: (...args) => errors.push(args) },
		history: {},
		navigator: {},
		location: {
			href: proxy('/dir/page'), origin, protocol: 'https:', hostname: 'proxy.example', port: '',
			pathname: '/' + encodeURIComponent('https://example.com') + '/dir/page', search: '',
		},
		document: {
			addEventListener() {},
			querySelector() { return null; },
			querySelectorAll() { return []; },
		},
	};
	ctx.window = ctx;
	vm.createContext(ctx);
	const code = getShimScript(origin, '').replace(/^<script>/, '').replace(/<\/script>$/, '');
	const run = () => vm.runInContext(code, ctx);
	run();
	assert.deepEqual(errors, []);
	return { ctx, errors, run };
}

test('shim: data/action/formaction are only rewritten on elements that load them', () => {
	const { ctx } = createBrowser();
	const el = tag => new ctx.Element(tag);

	const chart = el('x-chart');
	chart.setAttribute('data', '{"points":[1,2,3]}');
	chart.setAttribute('action', 'save');
	chart.setAttribute('formaction', 'next');
	assert.equal(chart.getAttribute('data'), '{"points":[1,2,3]}');
	assert.equal(chart.getAttribute('action'), 'save');
	assert.equal(chart.getAttribute('formaction'), 'next');

	const object = el('object');
	object.setAttribute('data', 'movie.swf');
	assert.equal(object.getAttribute('data'), proxy('/dir/movie.swf'));
	const form = el('form');
	form.setAttribute('action', '/login');
	assert.equal(form.getAttribute('action'), proxy('/login'));
	const button = el('button');
	button.setAttributeNS(null, 'formaction', 'next');
	assert.equal(button.getAttribute('formaction'), proxy('/dir/next'));

	// 通用 src 与 SVG xlink:href 行为保持不变
	const widget = el('model-viewer');
	widget.setAttribute('src', 'a.glb');
	assert.equal(widget.getAttribute('src'), proxy('/dir/a.glb'));
	const use = el('use');
	use.setAttributeNS('http://www.w3.org/1999/xlink', 'xlink:href', '/s.svg#i');
	assert.equal(use.getAttribute('xlink:href'), proxy('/s.svg#i'));
	const div = el('div');
	div.setAttribute('xlink:href', 'x');
	assert.equal(div.getAttribute('xlink:href'), 'x');
});

test('shim: inherited Object.prototype names are not treated as URL attributes', () => {
	const { ctx } = createBrowser();
	const div = new ctx.Element('div');
	for (const name of ['constructor', '__proto__']) {
		div.setAttributeNS(null, name, 'value');
		div.setAttributeNS('urn:x', 'p:' + name, 'value');
		assert.equal(div.getAttribute(name), 'value', name);
		assert.equal(div.getAttribute('p:' + name), 'value', 'p:' + name);
	}
});
