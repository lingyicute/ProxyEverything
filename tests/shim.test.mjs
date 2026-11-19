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
function createBrowser(globals = {}) {
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
		...globals,
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

test('shim: re-executing an injected copy keeps the hooks installed once', () => {
	const { ctx, errors, run } = createBrowser();
	const hooks = () => [
		ctx.XMLHttpRequest.prototype.open,
		ctx.Element.prototype.setAttribute,
		ctx.Element.prototype.setAttributeNS,
		ctx.Element.prototype.removeAttribute,
	];
	const first = hooks();
	run();
	run();
	assert.deepEqual(errors, []);
	assert.deepEqual(hooks(), first);
	const img = new ctx.Element('img');
	img.setAttribute('src', 'a.png');
	assert.equal(img.getAttribute('src'), proxy('/dir/a.png'));
});

test('shim: an empty action keeps the current document even when a base is present', () => {
	const { ctx } = createBrowser();
	ctx.document.querySelectorAll = () => [{ getAttribute: () => 'https://example.com/other/' }];
	const form = new ctx.Element('form');
	const button = new ctx.Element('button');
	const link = new ctx.Element('a');
	form.setAttribute('action', '');
	button.setAttribute('formaction', '');
	link.setAttribute('href', '#heading');
	assert.equal(form.getAttribute('action'), '');
	assert.equal(button.getAttribute('formaction'), '');
	assert.equal(link.getAttribute('href'), proxy('/other/#heading'));
});

test('shim: wrapped constructors keep subclass prototypes and native call semantics', () => {
	class WebSocket {
		constructor(url, protocols) { this.url = String(url); this.protocols = protocols; this.argc = arguments.length; }
		static get OPEN() { return 1; }
	}
	class Worker { constructor(url, options) { this.url = url; this.options = options; this.argc = arguments.length; } }
	class EventSource { constructor(url) { this.url = String(url); } }
	class Audio { constructor(src) { this.src = src; this.argc = arguments.length; } }
	const { ctx } = createBrowser({ WebSocket, Worker, EventSource, Audio });
	const run = code => vm.runInContext(code, ctx);

	const sub = run(`class Live extends window.WebSocket { ping() { return 'pong'; } }
		new Live('wss://example.com/ws', ['chat'])`);
	assert.ok(sub instanceof WebSocket, 'still an instance of the native class');
	assert.equal(Object.getPrototypeOf(sub), run('Live.prototype'), 'subclass prototype survives construction');
	assert.equal(sub.ping(), 'pong');
	assert.equal(sub.url, 'wss://proxy.example/wss%3A%2F%2Fexample.com/ws');
	assert.equal(JSON.stringify(sub.protocols), '["chat"]');
	assert.equal(sub.argc, 2, 'the arity of the forwarded arguments is preserved');

	assert.equal(run(`new window.WebSocket('/relative').url`), 'wss://proxy.example/https%3A%2F%2Fexample.com/relative');
	assert.equal(run(`new window.WebSocket('wss://example.com/one').argc`), 1);
	assert.equal(run('window.WebSocket.OPEN'), 1, 'static constants resolve through the native constructor');
	assert.ok(run('new window.WebSocket("wss://example.com/x") instanceof window.WebSocket'));
	// 异常来自 vm 上下文的 realm，按名称判断而不是跨 realm 比较构造器。
	assert.throws(() => run(`window.WebSocket('wss://example.com/x')`), error => error.name === 'TypeError' && /new/.test(error.message),
		'calling without new fails like the native constructor');

	const worker = run(`class ModuleWorker extends window.Worker {}; new ModuleWorker(new URL('https://example.com/w.js'), { type: 'module' })`);
	assert.equal(Object.getPrototypeOf(worker), run('ModuleWorker.prototype'));
	assert.ok(worker.url instanceof URL);
	assert.equal(worker.url.href, 'https://proxy.example/https%3A%2F%2Fexample.com/w.js');
	assert.equal(JSON.stringify(worker.options), '{"type":"module"}');

	assert.equal(run(`new window.EventSource('events').url`), 'https://proxy.example/https%3A%2F%2Fexample.com/dir/events');
	assert.equal(run(`new window.Audio().argc`), 0, 'Audio() without a source stays argument-free');
	assert.equal(run(`new window.Audio('clip.mp3').src`), 'https://proxy.example/https%3A%2F%2Fexample.com/dir/clip.mp3');
	assert.ok(run(`new window.Audio() instanceof window.Audio`));
});
