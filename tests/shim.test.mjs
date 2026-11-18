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
const proxy = path => origin + '/~' + encodeURIComponent('https://example.com') + path;

/** 只提供 shim 安装钩子所需的最小浏览器环境；shim 内部异常记入 errors。 */
function createBrowser(globals = {}, cookieNs = '') {
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
			pathname: '/~' + encodeURIComponent('https://example.com') + '/dir/page', search: '',
		},
		document: {
			addEventListener() {},
			querySelector() { return null; },
			querySelectorAll() { return []; },
		},
	};
	Object.assign(ctx, globals);
	ctx.window = ctx;
	vm.createContext(ctx);
	const code = getShimScript(origin, cookieNs).replace(/^<script>/, '').replace(/<\/script>$/, '');
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

test('shim: Request retains native cloning, validation and subclass behavior', async () => {
	const calls = [];
	const { ctx } = createBrowser({ Request, fetch: async (...args) => { calls.push(args); } });
	const input = new Request(proxy('/submit'), { method: 'POST', body: 'sample' });
	const clone = new ctx.Request(input);
	assert.notEqual(clone, input);
	assert.equal(await clone.text(), 'sample');
	assert.equal(input.bodyUsed, true);
	const Subclass = class extends ctx.Request {};
	assert.ok(new Subclass(new Request('https://example.com/asset')) instanceof Subclass);
	assert.throws(() => new ctx.Request('/bad', { method: 'GET', body: 'invalid' }), TypeError);

	const options = Object.create({ credentials: 'omit' });
	Object.defineProperty(options, 'integrity', { value: 'sha256-marker' });
	Object.freeze(options);
	const request = new ctx.Request('/asset', options);
	assert.equal(request.url, proxy('/asset'));
	assert.equal(request.credentials, 'omit');
	assert.equal(request.integrity, '');
	assert.equal(new ctx.Request('data:,plain', options).integrity, 'sha256-marker');
	await ctx.fetch({ url: '/unrelated-field', toString: () => '/actual' });
	assert.equal(calls[0][0], proxy('/actual'));
});

test('shim srcset uses the same URL boundaries and leaves data candidates alone', () => {
	const { ctx } = createBrowser();
	const image = new ctx.Element('img');
	image.setAttribute('srcset', 'first,a.png 1x, data:image/gif;base64,token 2x, last.png,, ');
	assert.equal(image.getAttribute('srcset'), `${proxy('/dir/first,a.png')} 1x, data:image/gif;base64,token 2x, ${proxy('/dir/last.png')},, `);
});

test('document.cookie shares protected cookie names without accepting HTTP-only writes', () => {
	const ns = '__pe_fixture_';
	let last = '';
	class Document {
		get cookie() { return `__Host-${ns}pref=one; ${ns}__Host-old=stale; other=unrelated`; }
		set cookie(value) { last = value; }
	}
	const { ctx } = createBrowser({ Document }, ns);
	assert.equal(ctx.document.cookie, '__Host-pref=one');
	ctx.document.cookie = '__Http-server=2; HttpOnly; Secure';
	assert.equal(last, '');
	ctx.document.cookie = '__Host-pref=two; Secure; Path=/';
	assert.equal(last, `__Host-${ns}pref=two; Secure; Path=/`);
});

test('namespaced metadata is not mistaken for a native loading attribute', () => {
	const { ctx } = createBrowser();
	const a = new ctx.Element('a');
	a.setAttributeNS('urn:metadata', 'meta:href', '/label');
	assert.equal(a.getAttribute('meta:href'), '/label');
	const base = new ctx.Element('base');
	base.setAttribute('href', '/assets/');
	base.setAttributeNS('urn:metadata', 'meta:href', 'title');
	base.removeAttributeNS('urn:metadata', 'href');
	assert.equal(base.getAttribute('data-pe-base'), 'https://example.com/assets/');
	const link = new ctx.Element('use');
	link.setAttributeNS('http://www.w3.org/1999/xlink', 'ref:href', 'sprite.svg');
	assert.equal(link.getAttribute('ref:href'), proxy('/dir/sprite.svg'));
});

test('history updates cannot switch the document to a different target origin', () => {
	const calls = [];
	const save = (...args) => calls.push(args[2]);
	const { ctx } = createBrowser({ DOMException, history: { pushState: save, replaceState: save } });
	for (const method of ['pushState', 'replaceState']) {
		ctx.history[method](null, '', './next');
		assert.throws(() => ctx.history[method](null, '', 'https://other.example/'), { name: 'SecurityError' });
	}
	assert.deepEqual(calls, [proxy('/dir/next'), proxy('/dir/next')]);
});
