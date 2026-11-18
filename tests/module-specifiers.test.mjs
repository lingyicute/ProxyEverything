import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { rewriteJsModuleSpecifiers, rewriteImportMap } = await import(
	'data:text/javascript;base64,' + Buffer.from(source +
		'\nexport { rewriteJsModuleSpecifiers, rewriteImportMap };').toString('base64')
);

const base = 'https://site.example/app/index.html';
const origin = 'https://proxy.example';
const proxy = target => {
	const url = new URL(target);
	return origin + '/~' + encodeURIComponent(url.origin) + url.pathname + url.search + url.hash;
};

test('module imports resolve absolute HTTP specifiers without a base URL', () => {
	const input = [
		'import "https:cdn.example/one.js";',
		'export { value } from "https:/cdn.example/two.js";',
		'const later = import("http:cdn.example/three.js");',
		'import "./local.js";',
		'import "  https:cdn.example/four.js  ";',
	].join('\n');
	const expected = [
		`import "${proxy('https://cdn.example/one.js')}";`,
		`export { value } from "${proxy('https://cdn.example/two.js')}";`,
		`const later = import("${proxy('http://cdn.example/three.js')}");`,
		`import "${proxy('https://site.example/app/local.js')}";`,
		`import "${proxy('https://cdn.example/four.js')}";`,
	].join('\n');
	assert.equal(rewriteJsModuleSpecifiers(input, base, origin), expected);
});

test('import map keys and values use module resolution, not ordinary relative URL resolution', () => {
	const input = {
		imports: {
			'https:cdn.example/one.js': 'https:cdn.example/v2.js',
			'https:/cdn.example/pkg/': 'https:/cdn.example/assets/',
			'./local.js': 'https:cdn.example/other.js',
			named: 'https:cdn.example/named.js',
			bare: 'not-a-url',
			invalid: 'https:',
			data: 'data:text/javascript,export default 1',
		},
		scopes: { 'https:cdn.example/scope/': { named: 'https:cdn.example/scoped.js' } },
	};
	const result = JSON.parse(rewriteImportMap(JSON.stringify(input), base, origin));
	assert.deepEqual(result.imports, {
		[proxy('https://cdn.example/one.js')]: proxy('https://cdn.example/v2.js'),
		[proxy('https://cdn.example/pkg/')]: proxy('https://cdn.example/assets/'),
		[proxy('https://site.example/app/local.js')]: proxy('https://cdn.example/other.js'),
		named: proxy('https://cdn.example/named.js'),
		bare: 'not-a-url',
		invalid: 'https:',
		data: 'data:text/javascript,export default 1',
	});
	// Unlike specifiers, scope prefixes are always URL-parsed with the document base.
	assert.deepEqual(result.scopes, {
		[proxy('https://site.example/app/cdn.example/scope/')]: { named: proxy('https://cdn.example/scoped.js') },
	});
});

test('bare, malformed and non-HTTP module specifiers remain unchanged', () => {
	const input = 'import "package/name"; import "https:"; import "data:text/javascript,export default 1";';
	assert.equal(rewriteJsModuleSpecifiers(input, base, origin), input);
});

test('already proxied paths are not double-proxied', () => {
	const path = '/~https%3A%2F%2Fcdn.example/one.js';
	const input = `import "${path}";`;
	assert.equal(rewriteJsModuleSpecifiers(input, base, origin), input);
	const map = { imports: { [path]: path } };
	assert.deepEqual(JSON.parse(rewriteImportMap(JSON.stringify(map), base, origin)), map);
});
