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

test('shim: every spelling of a proxy-host URL is rebound to the target like on the server', () => {
	const { ctx } = createBrowser();
	const rp = ctx.window.__PE__.rp;
	for (const input of [
		'https://proxy.example/api?x=1', '//proxy.example/api?x=1', '/\\proxy.example/api?x=1',
		'\\\\proxy.example/api?x=1', 'https:\\\\proxy.example\\api?x=1', 'http:proxy.example/api?x=1',
	]) {
		assert.equal(rp(input), proxy('/api?x=1'), input);
	}
	assert.equal(rp('wss://proxy.example/live'), origin + '/~' + encodeURIComponent('wss://example.com') + '/live');
	// 其它协议即使主机名相同也不是代理地址。
	assert.equal(rp('ftp://proxy.example/file'), 'ftp://proxy.example/file');
	assert.equal(rp('app://proxy.example/open'), 'app://proxy.example/open');
});

test('shim: Navigation API reroutes script-initiated navigations that would leave the proxy', () => {
	let listener = null;
	const navigated = [];
	const { ctx } = createBrowser({
		location: {
			href: proxy('/dir/page'), origin, protocol: 'https:', hostname: 'proxy.example', port: '',
			pathname: '/~' + encodeURIComponent('https://example.com') + '/dir/page', search: '',
			assign(url) { navigated.push(['assign', url]); },
			replace(url) { navigated.push(['replace', url]); },
		},
		navigation: { addEventListener(type, fn) { if (type === 'navigate') listener = fn; } },
		setTimeout: fn => fn(),
	});
	assert.equal(typeof ctx.navigation.addEventListener, 'function');
	const fire = (url, extra = {}) => {
		const ev = {
			cancelable: true, hashChange: false, formData: null, downloadRequest: null, navigationType: 'push',
			destination: { url, sameDocument: false }, prevented: false, preventDefault() { this.prevented = true; }, ...extra,
		};
		listener(ev);
		return ev.prevented;
	};
	assert.equal(fire('https://example.com/next?x=1#h'), true);
	assert.equal(fire('https://other.example/p', { navigationType: 'replace' }), true);
	assert.equal(fire(origin + '/leaked/path'), true);
	assert.deepEqual(navigated, [
		['assign', proxy('/next?x=1#h')],
		['replace', origin + '/~' + encodeURIComponent('https://other.example') + '/p'],
		['assign', proxy('/leaked/path')],
	]);
	// 已代理的导航、同文档导航、POST 表单、下载、历史遍历、非 HTTP(S) 目标和不可取消的事件都不干预。
	for (const [url, extra] of [
		[proxy('/already'), {}],
		['https://example.com/a', { cancelable: false }],
		['https://example.com/a', { formData: {} }],
		['https://example.com/a', { downloadRequest: '' }],
		['https://example.com/a', { navigationType: 'traverse' }],
		['https://example.com/a', { destination: { url: 'https://example.com/a', sameDocument: true } }],
		['https://example.com/a#x', { hashChange: true }],
		['mailto:a@b.c', {}],
	]) assert.equal(fire(url, extra), false, url + JSON.stringify(extra));
	assert.equal(navigated.length, 3);
});

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
	ctx.document.cookie = 'pref=two; SameSite=None';
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
	assert.equal(sub.url, 'wss://proxy.example/~wss%3A%2F%2Fexample.com/ws');
	assert.equal(JSON.stringify(sub.protocols), '["chat"]');
	assert.equal(sub.argc, 2, 'the arity of the forwarded arguments is preserved');

	assert.equal(run(`new window.WebSocket('/relative').url`), 'wss://proxy.example/~https%3A%2F%2Fexample.com/relative');
	assert.equal(run(`new window.WebSocket('wss://example.com/one').argc`), 1);
	assert.equal(run('window.WebSocket.OPEN'), 1, 'static constants resolve through the native constructor');
	assert.ok(run('new window.WebSocket("wss://example.com/x") instanceof window.WebSocket'));
	// 异常来自 vm 上下文的 realm，按名称判断而不是跨 realm 比较构造器。
	assert.throws(() => run(`window.WebSocket('wss://example.com/x')`), error => error.name === 'TypeError' && /new/.test(error.message),
		'calling without new fails like the native constructor');

	const worker = run(`class ModuleWorker extends window.Worker {}; new ModuleWorker(new URL('https://example.com/w.js'), { type: 'module' })`);
	assert.equal(Object.getPrototypeOf(worker), run('ModuleWorker.prototype'));
	assert.ok(worker.url instanceof URL);
	assert.equal(worker.url.href, 'https://proxy.example/~https%3A%2F%2Fexample.com/w.js');
	assert.equal(JSON.stringify(worker.options), '{"type":"module"}');

	assert.equal(run(`new window.EventSource('events').url`), 'https://proxy.example/~https%3A%2F%2Fexample.com/dir/events');
	assert.equal(run(`new window.Audio().argc`), 0, 'Audio() without a source stays argument-free');
	assert.equal(run(`new window.Audio('clip.mp3').src`), 'https://proxy.example/~https%3A%2F%2Fexample.com/dir/clip.mp3');
	assert.ok(run(`new window.Audio() instanceof window.Audio`));
});

test('navigation property setters follow the same base and empty URL rules as attributes', () => {
	class HTMLAnchorElement { set href(value) { this.value = String(value); } }
	class HTMLAreaElement { set href(value) { this.value = String(value); } }
	class HTMLFormElement { set action(value) { this.value = String(value); } }
	class HTMLButtonElement { set formAction(value) { this.value = String(value); } }
	const { ctx } = createBrowser({ HTMLAnchorElement, HTMLAreaElement, HTMLFormElement, HTMLButtonElement });
	ctx.document.querySelectorAll = () => [{ getAttribute: () => 'https://example.com/other/' }];
	for (const Link of [ctx.HTMLAnchorElement, ctx.HTMLAreaElement]) {
		const link = new Link();
		link.href = '';
		assert.equal(link.value, proxy('/other/'));
		link.href = '#section';
		assert.equal(link.value, proxy('/other/#section'));
	}
	for (const [Control, prop] of [[ctx.HTMLFormElement, 'action'], [ctx.HTMLButtonElement, 'formAction']]) {
		const control = new Control();
		control[prop] = '';
		assert.equal(control.value, '');
		control[prop] = '#section';
		assert.equal(control.value, proxy('/other/#section'));
	}
});

test('DOM ping lists retain Unicode URL characters and ASCII separators', () => {
	const { ctx } = createBrowser();
	const a = new ctx.Element('a');
	a.setAttribute('ping', ' /a\u00a0b\t/next ');
	assert.equal(a.getAttribute('ping'), ` ${proxy('/a%C2%A0b')}\t${proxy('/next')} `);
});

test('history state updates resolve empty URLs against base and block dot-segment escapes', () => {
	const calls = [];
	const save = (...args) => calls.push(args[2]);
	const { ctx } = createBrowser({ DOMException, history: { pushState: save, replaceState: save } });
	ctx.document.querySelectorAll = () => [{ getAttribute: name => name === 'data-pe-base' ? 'https://example.com/sub/index.html' : null }];
	ctx.history.pushState(null, '', '');
	assert.equal(calls[0], proxy('/sub/index.html'));
	ctx.history.replaceState(null, '', '/~https%3A%2F%2Fexample.com./sub/next');
	assert.equal(calls[1], '/~https%3A%2F%2Fexample.com./sub/next');
	ctx.history.pushState(null, '', '/~https%3A%2F%2Fexample.com/../other.example/inside');
	assert.equal(calls[2], '/~https%3A%2F%2Fexample.com/other.example/inside');
	ctx.history.pushState(null, '', '/~https%3A%2F%2Fexample.com/../~https%3A%2F%2Fother.example/inside');
	assert.equal(calls[3], '/~https%3A%2F%2Fexample.com/~https%3A%2F%2Fother.example/inside');
	ctx.history.pushState(null, '', '/~https%3A%2F%2Fexample.com/sub/%2e%2e/inside');
	assert.equal(calls[4], '/~https%3A%2F%2Fexample.com/inside');
	assert.throws(() => ctx.history.pushState(null, '', '/~https%3A%2F%2Fother.example/x'), { name: 'SecurityError' });
});

test('shim ignores foreign base elements and freezes at the first HTML base with href', () => {
	const { ctx } = createBrowser();
	const svgBase = Object.assign(new ctx.Element('base'), { namespaceURI: 'http://www.w3.org/2000/svg' });
	svgBase.setAttribute('href', '/foreign/');
	assert.equal(svgBase.getAttribute('href'), '/foreign/');
	assert.equal(svgBase.getAttribute('data-pe-base'), null);

	const firstBase = Object.assign(new ctx.Element('base'), { namespaceURI: 'http://www.w3.org/1999/xhtml' });
	firstBase.setAttribute('href', 'javascript:void(0)');
	const secondBase = Object.assign(new ctx.Element('base'), { namespaceURI: 'http://www.w3.org/1999/xhtml' });
	secondBase.setAttribute('href', 'https://other.example/sub/');
	ctx.document.querySelectorAll = () => [svgBase, firstBase, secondBase];
	assert.equal(ctx.window.__PE__.rp('rel.js'), proxy('/dir/rel.js'));
	firstBase.removeAttribute('href');
	assert.equal(ctx.window.__PE__.rp('rel.js'), origin + '/~' + encodeURIComponent('https://other.example') + '/sub/rel.js');
});

test('shim coerces non-string URL objects, WebSocket empty base, and null attribute values', () => {
	let beaconUrl = null, assignedUrl = null;
	class WebSocket { constructor(u) { this.url = u; } }
	class XMLHttpRequest { open(m, u) { this.url = u; } }
	const { ctx } = createBrowser({
		WebSocket,
		XMLHttpRequest,
		navigator: { sendBeacon(u) { beaconUrl = u; return true; } },
		location: {
			href: proxy('/dir/page'), origin, protocol: 'https:', hostname: 'proxy.example', port: '',
			pathname: '/~' + encodeURIComponent('https://example.com') + '/dir/page', search: '',
			assign(u) { assignedUrl = u; },
			replace() {},
		},
	});
	ctx.document.querySelectorAll = () => [{ getAttribute: name => name === 'data-pe-base' ? 'https://example.com/sub/' : null }];

	assert.equal(new ctx.WebSocket('').url, 'wss://proxy.example/~https%3A%2F%2Fexample.com/sub/');
	const urlLike = { toString: () => '/api/v1' };
	const xhr = new ctx.XMLHttpRequest();
	xhr.open('GET', urlLike);
	assert.equal(xhr.url, proxy('/api/v1'));
	ctx.navigator.sendBeacon(urlLike);
	assert.equal(beaconUrl, proxy('/api/v1'));
	ctx.location.assign(urlLike);
	assert.equal(assignedUrl, proxy('/api/v1'));

	const script = new ctx.Element('script');
	script.setAttribute('integrity', 'sha256-x');
	script.setAttribute('integrity', null);
	assert.equal(script.getAttribute('integrity'), null);
	const img = new ctx.Element('img');
	img.setAttribute('src', null);
	assert.equal(img.getAttribute('src'), proxy('/sub/null'));
});
