import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

// Load the standalone Worker as an ES module without changing its deployment exports.
const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { rewriteImportMap, rewriteSpeculationRules, bufferedTextHandler } = await import(
	'data:text/javascript;base64,' + Buffer.from(source +
		'\nexport { rewriteImportMap, rewriteSpeculationRules, bufferedTextHandler };').toString('base64')
);

const base = 'https://example.com/assets/';
const origin = 'https://proxy.example';
const proxy = path => origin + '/' + encodeURIComponent('https://example.com' + path);
const inlineJson = value => JSON.stringify(value).replace(/</g, '\\u003c');
const payloads = [
	['end tag', '</script><img src=x onerror=alert(1)>'],
	['mixed-case end tag', '</ScRiPt ><script>alert(1)</script>'],
	['double-escaped script state', '<!--<script>'],
];

for (const [name, rewrite] of Object.entries({ importmap: rewriteImportMap, speculationrules: rewriteSpeculationRules })) {
	for (const [label, payload] of payloads) {
		test(`${name}: safely serializes ${label} in keys and nested values`, () => {
			const value = { [payload]: { text: payload }, literalEscape: '\\u003c', unicode: '中文😀\u2028\u2029', symbols: '&<>' };
			const input = inlineJson(value);
			assert.ok(!input.includes('<'), 'the original inline JSON is safe');
			const output = rewrite(input, base, origin);
			assert.ok(!output.includes('<'), 'rewriting must not introduce HTML tokenizer control characters');
			assert.deepEqual(JSON.parse(output), value, 'JSON data must remain unchanged');
		});
	}

	test(`${name}: preserves escaped solidus protection`, () => {
		const input = String.raw`{"note":"<\/script><script>alert(1)<\/script>"}`;
		const output = rewrite(input, base, origin);
		assert.ok(!output.includes('<'));
		assert.deepEqual(JSON.parse(output), JSON.parse(input));
	});

	test(`${name}: leaves malformed and non-object JSON unchanged`, () => {
		for (const input of ['', '{', 'null', '[]', '42', '"\\u003c/script>"']) {
			assert.equal(rewrite(input, base, origin), input);
		}
	});

	test(`${name}: safely rewrites across every text chunk boundary`, () => {
		const input = inlineJson({ note: payloads[0][1] });
		for (let split = 0; split <= input.length; split++) {
			const handler = bufferedTextHandler(text => rewrite(text, base, origin));
			handler.element({});
			const output = [];
			let removed = 0;
			const chunks = [input.slice(0, split), input.slice(split), ''];
			chunks.forEach((text, index) => handler.text({
				text,
				lastInTextNode: index === chunks.length - 1,
				remove() { removed++; },
				replace(value, options) {
					assert.equal(options.html, true);
					output.push(value);
				},
			}));
			assert.equal(removed, 2);
			assert.equal(output.length, 1);
			assert.ok(!output[0].includes('<'), `unsafe output at split ${split}`);
			assert.deepEqual(JSON.parse(output[0]), JSON.parse(input));
		}
	});
}

test('importmap: keeps module keys and data URLs safe while rewriting target URLs', () => {
	const key = payloads[0][1];
	const dataUrl = 'data:text/javascript,' + payloads[2][1];
	const value = {
		imports: { [key]: './entry.js', data: dataUrl, blocked: null, 'pkg/': './pkg/' },
		scopes: { './page.html': { [key]: './scoped.js' } },
		integrity: { './entry.js': 'sha256-obsolete' },
	};
	const output = rewriteImportMap(inlineJson(value), base, origin);
	assert.ok(!output.includes('<'));
	assert.deepEqual(JSON.parse(output), {
		imports: { [key]: proxy('/assets/entry.js'), data: dataUrl, blocked: null, 'pkg/': './pkg/' },
		scopes: { [proxy('/assets/page.html')]: { [key]: proxy('/assets/scoped.js') } },
	});
});

test('speculationrules: preserves selectors and both URL resolution bases', () => {
	const selector = 'a[data-label="' + payloads[0][1] + '"]';
	const documentUrl = 'https://example.com/page/index.html';
	const value = {
		prefetch: [
			{ source: 'list', urls: ['./next.html'] },
			{ source: 'list', relative_to: 'document', urls: ['./next.html'] },
		],
		prerender: [{ source: 'document', where: { selector_matches: selector } }],
	};
	const output = rewriteSpeculationRules(inlineJson(value), base, origin, documentUrl);
	assert.ok(!output.includes('<'));
	assert.deepEqual(JSON.parse(output), {
		prefetch: [
			{ source: 'list', urls: [proxy('/assets/next.html')] },
			{ source: 'list', relative_to: 'document', urls: [proxy('/page/next.html')] },
		],
		prerender: value.prerender,
	});
});
