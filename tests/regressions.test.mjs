import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const {
	default: worker,
	getRootHtml,
	getShimScript,
	MD3_JS,
	quoteCssString,
	rewriteCss,
	rewriteJsModuleSpecifiers,
	rewriteRefreshContent,
	rewriteStyleAttr,
	rewriteSvg, rewriteXmlText,
	rewriteUrl,
	sniffHtmlCharset,
	stringifyInlineJson,
} = await import(
	'data:text/javascript;base64,' + Buffer.from(source + `
export {
	getRootHtml, getShimScript, MD3_JS, quoteCssString, rewriteCss,
	rewriteJsModuleSpecifiers, rewriteRefreshContent, rewriteStyleAttr,
	rewriteSvg, rewriteXmlText, rewriteUrl, sniffHtmlCharset, stringifyInlineJson
};`).toString('base64')
);

const base = 'https://example.com/dir/page';
const origin = 'https://proxy.example';
const proxy = (url) => {
	const u = new URL(url, base);
	return origin + '/~' + encodeURIComponent(u.origin) + u.pathname + u.search + u.hash;
};

test('already-proxied URLs and inline CSS/JS/JSON never break out of raw-text or CDATA', () => {
	const relOut = rewriteUrl('  /https%3A%2F%2Fexample.com/a?</style>', base, origin);
	assert.equal(relOut, '/https%3A%2F%2Fexample.com/a?%3C/style%3E');
	const absOut = rewriteUrl('https://proxy.example/https%3A%2F%2Fexample.com/a?</script>', base, origin);
	assert.equal(absOut, 'https://proxy.example/https%3A%2F%2Fexample.com/a?%3C/script%3E');

	assert.equal(quoteCssString('a<b>'), '"a\\3c b\\3e "');
	const cssOut = rewriteCss('body{background:url("  /https%3A%2F%2Fexample.com/a?\\3c /style><script>alert(1)</script>")}', base, origin);
	assert.ok(!cssOut.includes('<') && !cssOut.includes('>'));

	const jsOut = rewriteJsModuleSpecifiers('import "/https%3A%2F%2Fexample.com/a.js?\\u003c/script><script>alert(1)</script> ";', base, origin);
	assert.ok(!jsOut.includes('<') && !jsOut.includes('</script>'));

	const jsonOut = stringifyInlineJson({ cdata: ']]>' });
	assert.ok(!jsonOut.includes(']]>'));
	assert.deepEqual(JSON.parse(jsonOut), { cdata: ']]>' });
});

test('css: nested parentheses in quoted url() keep image-set depth intact', () => {
	assert.equal(
		rewriteCss('a{background:image-set(url("a.png" foo(1)) 1x, "b.png" 2x)}', base, origin),
		`a{background:image-set(url("a.png" foo(1)) 1x, "${proxy('b.png')}" 2x)}`
	);
});

test('meta refresh: preserves trailing quotes on unquoted URLs and trims quoted URLs', () => {
	assert.equal(
		rewriteRefreshContent("0; url=https://example.com/page?q='hello'", base, origin),
		`0; url=${proxy("https://example.com/page?q='hello'")}`
	);
	assert.equal(
		rewriteRefreshContent("0; url='https://example.com/a' ; ignored", base, origin),
		`0; url=${proxy('https://example.com/a')}`
	);
	assert.equal(
		rewriteRefreshContent("0; url='https://example.com/a", base, origin),
		`0; url=${proxy('https://example.com/a')}`
	);
});

test('svg: preserves CDATA end-tags, comments, ]]> escapes, namespaces, and quoted script attrs', () => {
	const cdataScript = '<svg><script type="module"><![CDATA[import "./a.js"; const s = "</script>"; import "./b.js";]]></script></svg>';
	assert.equal(
		rewriteSvg(cdataScript, base, origin),
		`<svg><script type="module"><![CDATA[import "${proxy('./a.js')}"; const s = "</script>"; import "${proxy('./b.js')}";]]></script></svg>`
	);

	const cdataStyle = '<svg><style><![CDATA[/* </style> */ .a{background:url(a.png)}]]></style></svg>';
	assert.equal(
		rewriteSvg(cdataStyle, base, origin),
		`<svg><style><![CDATA[/* </style> */ .a{background:url("${proxy('a.png')}")}]]></style></svg>`
	);

	const gtStyle = '<svg><style>/* ]]&gt; */ .a{background:url(a.png)}</style></svg>';
	const gtOut = rewriteSvg(gtStyle, base, origin);
	assert.ok(gtOut.includes(']]&gt;') && !gtOut.includes(']]>'));
	assert.ok(gtOut.includes(proxy('a.png')));

	const commentStyle = '<svg><style><!-- </style> -->.a{background:url(a.png)}</style></svg>';
	assert.equal(
		rewriteSvg(commentStyle, base, origin),
		`<svg><style><!-- </style> -->.a{background:url("${proxy('a.png')}")}</style></svg>`
	);

	const nsSvg = '<svg:svg xmlns:svg="http://www.w3.org/2000/svg"><svg:style>.a{background:url(a.png)}</svg:style><svg:script type="module">import "./a.js";</svg:script></svg:svg>';
	assert.equal(
		rewriteSvg(nsSvg, base, origin),
		`<svg:svg xmlns:svg="http://www.w3.org/2000/svg"><svg:style>.a{background:url("${proxy('a.png')}")}</svg:style><svg:script type="module">import "${proxy('./a.js')}";</svg:script></svg:svg>`
	);

	const quotedSrc = `<svg><script data-note=" src='x'" type="module">import "./a.js";</script></svg>`;
	assert.equal(
		rewriteSvg(quotedSrc, base, origin),
		`<svg><script data-note=" src='x'" type="module">import "${proxy('./a.js')}";</script></svg>`
	);

	const quotedType = `<svg><script data-note=" type='module'">import "./a.js";</script></svg>`;
	assert.equal(rewriteSvg(quotedType, base, origin), quotedType);
});

test('homepage submit preserves percent-encoded plain URLs and rejects ws://', () => {
	const html = getRootHtml();
	const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
	const formScript = scripts[scripts.length - 1];

	let submitHandler = null;
	const input = { value: '', focus() {} };
	const form = { addEventListener(type, fn) { if (type === 'submit') submitHandler = fn; } };
	const location = { hostname: 'proxy.example', port: '', href: origin + '/' };
	const snackEl = { textContent: '', classList: { add() {}, remove() {} } };
	const window = { addEventListener() {}, matchMedia: () => ({ addEventListener() {} }) };

	runInNewContext(formScript, {
		window,
		location,
		URL,
		clearTimeout() {},
		setTimeout(fn, delay) { if (delay < 1000) fn(); },
		getComputedStyle: () => ({ getPropertyValue: () => '' }),
		document: {
			documentElement: { getAttribute: () => 'light', setAttribute() {}, style: { setProperty() {} } },
			getElementById(id) {
				if (id === 'targetUrl') return input;
				if (id === 'urlForm') return form;
				if (id === 'clearBtn') return { addEventListener() {} };
				if (id === 'snack') return snackEl;
				return null;
			},
			querySelectorAll: () => [],
			addEventListener() {},
		},
	});

	const submit = (val) => {
		snackEl.textContent = '';
		location.href = origin + '/';
		input.value = val;
		submitHandler({ preventDefault() {} });
		return { href: location.href, snack: snackEl.textContent || null };
	};

	assert.equal(submit('https://en.wikipedia.org/wiki/C%23').href, '/~https%3A%2F%2Fen.wikipedia.org/wiki/C%23');
	assert.equal(submit('https://example.com/files/a%2Fb?x=1').href, '/~https%3A%2F%2Fexample.com/files/a%2Fb?x=1');
	assert.equal(submit(origin + '/https%3A%2F%2Fen.wikipedia.org/wiki/C%2523').href, '/~https%3A%2F%2Fen.wikipedia.org/wiki/C%23');
	const wsRes = submit('ws://example.com/ws');
	assert.equal(wsRes.href, origin + '/');
	assert.equal(wsRes.snack, '仅支持 http:// 或 https:// 网址');
});

test('Referer lookups enforce ALLOWED_TARGET_ORIGINS and rewrite Sec-Fetch-Site', async () => {
	const originalFetch = globalThis.fetch;
	let forwarded = null;
	globalThis.fetch = async (url, init) => {
		forwarded = { url: String(url), headers: new Headers(init.headers) };
		return new Response('ok', { headers: { 'content-type': 'text/plain' } });
	};
	const send = (url, headers = {}, env = { ALLOWED_TARGET_ORIGINS: 'https://example.com,https://other.example' }) => {
		forwarded = null;
		return worker.fetch({ url, method: 'GET', headers: new Headers(headers), body: null }, env);
	};
	try {
		const env = { ALLOWED_TARGET_ORIGINS: 'https://allowed.example' };
		const disallowedRef = proxy('https://disallowed.example/page');
		const allowedRef = proxy('https://allowed.example/page');

		let resp = await send(origin + '/static/app.js', { referer: disallowedRef }, env);
		assert.equal(resp.status, 400);
		assert.equal(forwarded, null);

		resp = await send(origin + '/static/app.js', { referer: allowedRef }, env);
		assert.equal(resp.status, 307);
		assert.equal(resp.headers.get('location'), proxy('https://allowed.example/static/app.js'));

		await send(proxy('https://allowed.example/api'), { origin, referer: disallowedRef, 'sec-fetch-site': 'same-origin' }, env);
		assert.equal(forwarded.headers.get('referer'), null);
		assert.equal(forwarded.headers.get('origin'), 'null');
		assert.equal(forwarded.headers.get('sec-fetch-site'), 'cross-site');

		await send(proxy('https://allowed.example/api'), { referer: allowedRef, 'sec-fetch-site': 'same-origin' }, env);
		assert.equal(forwarded.headers.get('sec-fetch-site'), 'same-origin');

		await send(proxy('https://example.com/api'), { referer: proxy('https://other.example/p'), 'sec-fetch-site': 'same-origin' });
		assert.equal(forwarded.headers.get('sec-fetch-site'), 'cross-site');

		await send(proxy('https://example.com/api'), { 'sec-fetch-site': 'none' });
		assert.equal(forwarded.headers.get('sec-fetch-site'), 'none');

		await send(proxy('https://example.com/api'));
		assert.equal(forwarded.headers.get('sec-fetch-site'), null);
	} finally {
		globalThis.fetch = originalFetch;
	}
});

test('shim: null-prototype attr lookup, stripped fetch/Request integrity, and xlink namespace click', () => {
	const setCalls = [];
	const setNsCalls = [];
	const fetchCalls = [];
	const reqCalls = [];
	let clickHandler = null;

	class MockElement {
		setAttribute(n, v) { setCalls.push([n, v]); }
		setAttributeNS(ns, n, v) { setNsCalls.push([ns, n, v]); }
		removeAttribute() {}
		removeAttributeNS() {}
	}
	class MockRequest {
		constructor(input, init) {
			reqCalls.push([input, init]);
			this.url = typeof input === 'string' ? input : input.url;
			this.method = (init && init.method) || 'GET';
			this.integrity = (init && init.integrity) || '';
		}
	}
	const window = {
		Element: MockElement,
		Request: MockRequest,
		fetch(input, init) { fetchCalls.push([input, init]); return Promise.resolve(); },
	};
	const location = {
		pathname: '/' + encodeURIComponent(base), search: '', hostname: 'proxy.example',
		port: '', protocol: 'https:', href: origin + '/' + encodeURIComponent(base),
	};
	const script = getShimScript(origin, '').replace(/^<script>/, '').replace(/<\/script>$/, '');
	runInNewContext(script, {
		window, Element: MockElement, location, URL, navigator: {}, history: {},
		document: {
			querySelectorAll: () => [],
			addEventListener(type, fn) { if (type === 'click') clickHandler = fn; },
		},
		XMLHttpRequest: { prototype: { open() {} } },
	});

	const el = new MockElement();
	el.tagName = 'a';
	el.setAttributeNS(null, 'constructor', '/keep');
	el.setAttributeNS('http://www.w3.org/1999/xlink', 'xlink:href', '/next');
	assert.deepEqual(setNsCalls[0], [null, 'constructor', '/keep']);
	assert.deepEqual(setNsCalls[1], ['http://www.w3.org/1999/xlink', 'xlink:href', proxy('/next')]);

	new window.Request('/app.js', { integrity: 'sha256-bad' });
	assert.equal(reqCalls[0][0], proxy('/app.js'));
	assert.equal(reqCalls[0][1].integrity, '');

	window.fetch('/app.js', { integrity: 'sha256-bad' });
	assert.equal(fetchCalls[0][0], proxy('/app.js'));
	assert.equal(fetchCalls[0][1].integrity, '');

	const nsUpdates = [];
	const attrUpdates = [];
	const svgLink = {
		closest: () => svgLink,
		getAttribute: () => null,
		hasAttributeNS: (ns, name) => ns === 'http://www.w3.org/1999/xlink' && name === 'href',
		getAttributeNS: () => '/svg-next',
		setAttribute: (...args) => attrUpdates.push(args),
		setAttributeNS: (...args) => nsUpdates.push(args),
	};
	clickHandler({ target: svgLink });
	assert.deepEqual(attrUpdates, []);
	assert.deepEqual(nsUpdates, [['http://www.w3.org/1999/xlink', 'xlink:href', proxy('/svg-next')]]);
});

test('sniffHtmlCharset handles HTML5 abrupt comments <!--> and <!--->', async () => {
	for (const html of ['<!--><meta charset="gbk">', '<!---><meta charset="gbk">']) {
		const stream = new ReadableStream({
			start(controller) {
				controller.enqueue(Buffer.from(html, 'latin1'));
				controller.close();
			},
		});
		const { charset, body } = await sniffHtmlCharset(stream, null);
		await body.cancel();
		assert.equal(charset, 'gbk');
	}
});

test('fast paths preserve untouched JS/CSS while still rewriting escaped style URLs', () => {
	const plainJs = 'const a = 1 + 2; console.log(a);';
	assert.equal(rewriteJsModuleSpecifiers(plainJs, base, origin), plainJs);
	const plainCss = 'body{color:red;margin:0}';
	assert.equal(rewriteCss(plainCss, base, origin), plainCss);
	assert.equal(rewriteStyleAttr('color: rgba(0, 0, 0, 0.5)', base, origin), 'color: rgba(0, 0, 0, 0.5)');
	assert.equal(
		rewriteStyleAttr('background: \\75 rl(a.png)', base, origin),
		`background: url("${proxy('a.png')}")`
	);
});

test('upstream access requires a valid explicit origin allowlist', async () => {
	const originalFetch = globalThis.fetch;
	const seen = [];
	globalThis.fetch = async url => { seen.push(url); return new Response('ok'); };
	try {
		const request = new Request(proxy('https://example.com/page'));
		for (const value of [undefined, '', ' , ,\n', '*', 'https://example.com/path', 'not a URL',
			'https:example.com', 'https://example.com/path/..', 'https://example.com?',
			'https://example.com/#', 'https://@example.com', 'https://example.com,https://*.example.com']) {
			const response = await worker.fetch(request, { ALLOWED_TARGET_ORIGINS: value });
			assert.equal(response.status, 503);
		}
		assert.equal((await worker.fetch(request, { ALLOWED_TARGET_ORIGINS: 'https://example.com:9443' })).status, 403);
		assert.deepEqual(seen, []);
		assert.equal((await worker.fetch(request, { ALLOWED_TARGET_ORIGINS: 'https://example.com' })).status, 200);
		assert.deepEqual(seen, ['https://example.com/page']);
		// 多行配置的尾随逗号和空行不是来源，不应让整个列表失效。
		assert.equal((await worker.fetch(request, { ALLOWED_TARGET_ORIGINS: 'https://example.com,\n\nhttps://static.example.com,\n' })).status, 200);
		assert.equal(seen.length, 2);
	} finally {
		globalThis.fetch = originalFetch;
	}
});

test('SVG scanner keeps declarations and exact XML element names intact', () => {
	const prolog = `<?xml version="1.0" encoding="iso-8859-1"?>`;
	const internalSubset = `<!DOCTYPE svg [<!-- ] > --> <!ENTITY icon 'sprite.svg'>]>`;
	const nested = `<svg><style-note>url(label.txt)</style-note><image href="&icon;"/><image href="a&amp;b.png"/></svg>`;
	const input = prolog + internalSubset + nested;
	const expected = prolog.replace('iso-8859-1', 'UTF-8') + internalSubset +
		nested.replace('href="a&amp;b.png"', `href="${proxy('a&b.png').replace('&', '&amp;')}"`);
	assert.equal(rewriteSvg(input, base, origin), expected);
	assert.equal(rewriteSvg(`<svg><style>/* unfinished */`, base, origin), `<svg><style>/* unfinished */`);
});

test('HTML charset prescan recognizes only complete metadata declarations', async () => {
	const fragments = [
		'<div title="<meta charset=gbk>"></div>',
		'<meta-description charset="gbk">',
		'<meta data:charset="gbk">',
		'<!-- <meta charset=gbk> --!>',
		'<meta charset="utf-8" charset="gbk">',
	];
	const text = fragments.join('') + '<meta charset="windows-1252">';
	for (const [input, expected] of [[text, 'utf-8'], [fragments.slice(0, 4).join('') + '<meta charset="windows-1252">', 'windows-1252']]) {
		const stream = new Response(input).body;
		const sniffed = await sniffHtmlCharset(stream);
		assert.equal(sniffed.charset, expected);
		assert.equal(await new Response(sniffed.body).text(), input);
	}
	const xhtml = '<?xml version="1.0" encoding="windows-1252"?><html><meta charset="gbk" /></html>';
	const sniffed = await sniffHtmlCharset(new Response(xhtml).body, null, true);
	assert.equal(sniffed.charset, 'windows-1252');
	await sniffed.body.cancel();
});

test('XML raw text leaves incomplete CDATA and comments intact', () => {
	for (const input of ['body <![CDATA[unfinished', 'text <!-- open <!-- still open']) {
		assert.equal(rewriteXmlText(input, value => value.toUpperCase()), input);
	}
	assert.equal(rewriteXmlText('a<!--keep--><![CDATA[b]]>c', s => s.toUpperCase()),
		'A<!--keep--><![CDATA[B]]>C');
});

test('upstream HTTP and opening WebSocket handshakes use the request cancellation signal', async t => {
	const pending = [];
	t.mock.method(globalThis, 'fetch', async (_, init) => { pending.push(init.signal); return new Response('fixture'); });
	for (const headers of [{}, { Upgrade: 'websocket' }]) {
		const controller = new AbortController();
		const request = new Request(proxy(base), { headers, signal: controller.signal });
		await worker.fetch(request, { ALLOWED_TARGET_ORIGINS: 'https://example.com' });
		assert.equal(pending.at(-1), request.signal);
		controller.abort();
		assert.equal(pending.at(-1).aborted, true);
	}
});

test('rejected WebSocket handshakes report the upstream status instead of a generic 502', async t => {
	let upstream;
	t.mock.method(globalThis, 'fetch', async () => upstream);
	const request = new Request('https://proxy.example/~wss%3A%2F%2Fexample.com/socket', { headers: { Upgrade: 'websocket' } });
	for (const [status, expected] of [[401, 401], [403, 403], [503, 503], [302, 502], [200, 502]]) {
		upstream = new Response('handshake body', { status, headers: status === 302 ? { location: 'wss://example.com/elsewhere' } : {} });
		const response = await worker.fetch(request, { ALLOWED_TARGET_ORIGINS: 'https://example.com' });
		assert.equal(response.status, expected, String(status));
		assert.equal(response.headers.get('cache-control'), 'no-store');
		assert.ok(upstream.bodyUsed, 'the rejected handshake body is drained');
	}
});

test('XHTML charset sniffing stops once no XML declaration can still supply an encoding', async () => {
	for (const head of ['<html xmlns="http://www.w3.org/1999/xhtml">', '<?xml version="1.0"?><html>']) {
		// 上游仍在流式输出：嗅探不能等到 4096 字节或 EOF。
		const stream = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(head)); } });
		const sniffed = await Promise.race([
			sniffHtmlCharset(stream, null, true),
			new Promise(resolve => setTimeout(() => resolve('timeout'), 200)),
		]);
		assert.notEqual(sniffed, 'timeout', head);
		assert.equal(sniffed.charset, null, head);
		await sniffed.body.cancel();
	}
});

test('leaked relative WebSocket handshakes are forwarded instead of redirected', async t => {
	const seen = [];
	t.mock.method(globalThis, 'fetch', async url => { seen.push(String(url)); return new Response('refused', { status: 403 }); });
	const request = new Request('https://proxy.example/live/socket?room=1', {
		headers: { Upgrade: 'websocket', Referer: proxy('https://example.com/app/worker.js') },
	});
	const response = await worker.fetch(request, { ALLOWED_TARGET_ORIGINS: 'https://example.com' });
	assert.equal(response.status, 403);
	assert.deepEqual(seen, ['https://example.com/live/socket?room=1']);
	const plain = await worker.fetch(new Request('https://proxy.example/live/data', {
		headers: { Referer: proxy('https://example.com/app/') },
	}), { ALLOWED_TARGET_ORIGINS: 'https://example.com' });
	assert.equal(plain.status, 307);
});

test('XML charset detection does not depend on the upstream chunk boundaries', async () => {
	for (const charset of ['windows-1252', 'utf-16le', 'utf-16be']) {
		const declaration = `<?xml version="1.0" encoding="${charset}"?>`;
		const input = declaration + '<html>Café</html>';
		const bytes = Buffer.from(input, charset === 'windows-1252' ? 'latin1' : 'utf16le');
		if (charset === 'utf-16be') bytes.swap16();
		const size = charset === 'windows-1252' ? declaration.length : 4;
		for (let split = 1; split <= size; split++) {
			const stream = new ReadableStream({ start(controller) {
				controller.enqueue(bytes.subarray(0, split));
				controller.enqueue(bytes.subarray(split));
				controller.close();
			} });
			const result = await sniffHtmlCharset(stream, null, true);
			assert.equal(result.charset, charset, `split after byte ${split}`);
			assert.deepEqual(Buffer.from(await new Response(result.body).arrayBuffer()), bytes);
		}
	}
});

test('failed subrequests return non-cacheable errors without internal exception text', async t => {
	const diagnostic = 'private runtime diagnostic';
	t.mock.method(globalThis, 'fetch', async () => { throw new Error(diagnostic); });
	for (const headers of [{}, { Upgrade: 'websocket' }]) {
		const response = await worker.fetch(new Request(proxy(base), { headers }), {
			ALLOWED_TARGET_ORIGINS: 'https://example.com',
		});
		assert.equal(response.status, 502);
		assert.equal(response.headers.get('Cache-Control'), 'no-store');
		assert.ok(!(await response.text()).includes(diagnostic));
	}
});

test('homepage hue radios have one tab stop and wrap on arrow keys', () => {
	const buttons = [], storage = new Map();
	let keydown, focused;
	const row = {
		appendChild: button => buttons.push(button),
		addEventListener: (type, callback) => { if (type === 'keydown') keydown = callback; },
	};
	runInNewContext(MD3_JS, {
		window: { addEventListener() {} },
		localStorage: { setItem: (...args) => storage.set(...args) },
		getComputedStyle: () => ({ getPropertyValue: () => '285' }),
		document: {
			documentElement: { style: { setProperty() {} } },
			addEventListener() {}, getElementById: id => id === 'hueRow' ? row : null,
			createElement() {
				const attrs = new Map(), listeners = new Map();
				return {
					attrs, style: { setProperty() {} }, focus() { focused = this; },
					setAttribute: (...args) => attrs.set(...args),
					addEventListener: (...args) => listeners.set(...args), click() { listeners.get('click')(); },
				};
			},
		},
	});
	assert.deepEqual(buttons.filter(b => b.tabIndex === 0), [buttons[0]]);
	let prevented = false;
	keydown({ key: 'ArrowLeft', target: buttons[0], preventDefault() { prevented = true; } });
	assert.equal(prevented, true);
	assert.equal(focused, buttons.at(-1));
	assert.deepEqual(buttons.filter(b => b.tabIndex === 0), [focused]);
	assert.deepEqual(buttons.filter(b => b.attrs.get('aria-checked') === 'true'), [focused]);
	assert.equal(storage.get('pe-hue'), '330');
});

test('dot segments in already-proxied URLs stay clamped within their target origin', () => {
	assert.equal(
		rewriteUrl('/~https%3A%2F%2Fexample.com/../other.example/secret?q=1#h', base, origin),
		'/~https%3A%2F%2Fexample.com/other.example/secret?q=1#h'
	);
	assert.equal(
		rewriteUrl('https://proxy.example/~https%3A%2F%2Fexample.com/../../other.example/secret', base, origin),
		'https://proxy.example/~https%3A%2F%2Fexample.com/other.example/secret'
	);
	assert.equal(
		rewriteUrl('//proxy.example/~https%3A%2F%2Fcdn.example/../asset.js', base, origin),
		'https://proxy.example/~https%3A%2F%2Fcdn.example/asset.js'
	);
});

test('HTML meta charset prescan follows WHATWG pragma and attribute precedence rules', async () => {
	for (const [html, expected] of [
		['<meta http-equiv="Content-Type" content="charset=gbk">', 'gbk'],
		['<meta charset="" http-equiv="content-type" content="text/html; charset=gbk">', 'gbk'],
		['<meta charset="invalid-label" http-equiv="content-type" content="text/html; charset=gbk">', 'gbk'],
		['<meta content="text/html; charset=gbk" http-equiv="Content-Type">', 'gbk'],
		['<meta content="text/html; charset=gbk"><meta charset="windows-1252">', 'windows-1252'],
		['<meta content="text/html; charset=gbk" charset="windows-1252"><meta charset="utf-8">', 'utf-8'],
	]) {
		const sniffed = await sniffHtmlCharset(new Response(html).body);
		assert.equal(sniffed.charset, expected, html);
		await sniffed.body.cancel();
	}
});

test('XML scripts and styles rewrite across comment-guarded CDATA and bare query ampersands', () => {
	const cdataModule = '<svg><script type="module">/*<![CDATA[*/ import "./a.js?x=1&y=2"; /*]]>*/</script></svg>';
	const out = rewriteSvg(cdataModule, base, origin);
	assert.ok(out.includes(proxy('./a.js?x=1&y=2')));
	assert.equal(
		rewriteXmlText('import "./a.js?x=1&amp;y=2";', js => rewriteJsModuleSpecifiers(js, base, origin)),
		`import "${proxy('./a.js?x=1&amp;y=2')}";`
	);
});
