import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const {
	default: worker,
	getRootHtml,
	getShimScript,
	quoteCssString,
	rewriteCss,
	rewriteJsModuleSpecifiers,
	rewriteRefreshContent,
	rewriteStyleAttr,
	rewriteSvg,
	rewriteUrl,
	sniffHtmlCharset,
	stringifyInlineJson,
} = await import(
	'data:text/javascript;base64,' + Buffer.from(source + `
export {
	getRootHtml, getShimScript, quoteCssString, rewriteCss,
	rewriteJsModuleSpecifiers, rewriteRefreshContent, rewriteStyleAttr,
	rewriteSvg, rewriteUrl, sniffHtmlCharset, stringifyInlineJson
};`).toString('base64')
);

const base = 'https://example.com/dir/page';
const origin = 'https://proxy.example';
const proxy = (url) => {
	const u = new URL(url, base);
	return origin + '/' + encodeURIComponent(u.origin) + u.pathname.split('/').map(encodeURIComponent).join('/') + u.search + u.hash;
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

	assert.equal(submit('https://en.wikipedia.org/wiki/C%23').href, '/https%3A%2F%2Fen.wikipedia.org/wiki/C%2523');
	assert.equal(submit('https://example.com/files/a%2Fb?x=1').href, '/https%3A%2F%2Fexample.com/files/a%252Fb?x=1');
	assert.equal(submit(origin + '/https%3A%2F%2Fen.wikipedia.org/wiki/C%2523').href, '/https%3A%2F%2Fen.wikipedia.org/wiki/C%2523');
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
	const send = (url, headers = {}, env = undefined) => {
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
