import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

// The Worker is a standalone Cloudflare module. Load its helpers without adding
// test-only exports to the deployed script or requiring a package.json.
const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { default: worker, getShimScript, parseTarget, rewriteImportMap, rewriteUrl } = await import(
	'data:text/javascript;base64,' + Buffer.from(
		source + '\nexport { getShimScript, parseTarget, rewriteImportMap, rewriteUrl };'
	).toString('base64')
);
const base = 'https://site.example/app/index.html';
const proxy = 'https://proxy.example';

function mappedUrl(specifier, prefix) {
	return parseTarget(new URL(new URL(specifier, prefix).href)).href;
}

test('import map package prefixes keep a literal slash and resolve submodules', () => {
	const map = JSON.parse(rewriteImportMap(JSON.stringify({
		imports: {
			'pkg/': './lib/',
			'./src/': 'https://cdn.example/dist/',
			'pkg': './index.js',
		},
	}), base, proxy));

	assert.equal(map.imports['pkg/'].endsWith('/'), true);
	assert.equal(mappedUrl('widget.js', map.imports['pkg/']), 'https://site.example/app/lib/widget.js');
	const srcPrefix = rewriteUrl('./src/', base, proxy);
	assert.equal(map.imports[srcPrefix].endsWith('/'), true);
	assert.equal(rewriteUrl('./src/widget.js', base, proxy).startsWith(srcPrefix), true);
	assert.equal(mappedUrl('widget.js', map.imports[srcPrefix]), 'https://cdn.example/dist/widget.js');
	assert.equal(map.imports.pkg, rewriteUrl('./index.js', base, proxy));
});

test('import map scope prefixes match proxied module URLs', () => {
	const map = JSON.parse(rewriteImportMap(JSON.stringify({
		scopes: { './admin/': { 'pkg/': './v2/' } },
	}), base, proxy));
	const scope = Object.keys(map.scopes)[0];

	assert.equal(scope.endsWith('/'), true);
	assert.equal(rewriteUrl('./admin/main.js', base, proxy).startsWith(scope), true);
	assert.equal(mappedUrl('nested/widget.js', map.scopes[scope]['pkg/']),
		'https://site.example/app/v2/nested/widget.js');
});

test('import map keeps special bare specifier keys and drops invalid integrity', () => {
	const map = JSON.parse(rewriteImportMap(
		'{"imports":{"__proto__":"./prototype.js","data":"data:text/javascript,ok"},"integrity":{"./prototype.js":"sha256-invalid"}}',
		base, proxy
	));

	assert.equal(Object.hasOwn(map.imports, '__proto__'), true);
	assert.equal(map.imports.__proto__, rewriteUrl('./prototype.js', base, proxy));
	assert.equal(map.imports.data, 'data:text/javascript,ok');
	assert.equal(Object.hasOwn(map, 'integrity'), false);
});

test('path separators survive while encoded slashes and legacy links round-trip', () => {
	const target = 'https://site.example/a%2Fb/%E6%B5%8B%E8%AF%95%20a.js?x=1#section';
	const rewritten = rewriteUrl(target, base, proxy);

	assert.equal(rewritten,
		'https://proxy.example/https%3A%2F%2Fsite.example/a%252Fb/%25E6%25B5%258B%25E8%25AF%2595%2520a.js?x=1#section');
	assert.equal(parseTarget(new URL(rewritten)).href,
		'https://site.example/a%2Fb/%E6%B5%8B%E8%AF%95%20a.js?x=1');
	const oldLink = proxy + '/' + encodeURIComponent('https://site.example/old/a%2Fb');
	assert.equal(parseTarget(new URL(oldLink)).href, 'https://site.example/old/a%2Fb');
});

test('browser shim generates the same proxy paths as the server', () => {
	const window = {};
	const location = {
		pathname: '/' + encodeURIComponent(base), search: '', hostname: 'proxy.example',
		port: '', protocol: 'https:', href: proxy + '/' + encodeURIComponent(base),
	};
	const script = getShimScript(proxy, '').replace(/^<script>/, '').replace(/<\/script>$/, '');
	runInNewContext(script, {
		window, location, URL, navigator: {}, history: {},
		document: { querySelectorAll: () => [], addEventListener() {} },
		XMLHttpRequest: { prototype: { open() {} } },
	});

	for (const path of ['./admin/main.js', './a%2Fb/file%20name.js', '/assets/logo.svg']) {
		assert.equal(window.__PE__.rp(path), rewriteUrl(path, base, proxy));
	}
});

test('Worker fetch accepts both new and previously encoded proxy paths', async () => {
	const target = 'https://site.example/dir/a%2Fb.js';
	const paths = [rewriteUrl(target, base, proxy), proxy + '/' + encodeURIComponent(target)];
	const originalFetch = globalThis.fetch;
	const fetched = [];
	globalThis.fetch = async url => {
		fetched.push(String(url));
		return new Response('ok', { headers: { 'Content-Type': 'text/plain' } });
	};
	try {
		for (const path of paths) {
			const response = await worker.fetch(new Request(path), {});
			assert.equal(response.status, 200);
			assert.equal(await response.text(), 'ok');
		}
		assert.deepEqual(fetched, [target, target]);
	} finally {
		globalThis.fetch = originalFetch;
	}
});
