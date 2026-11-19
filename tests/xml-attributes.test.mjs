import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { getHtmlAttribute, rewriteSvg } = await import(
	'data:text/javascript;base64,' + Buffer.from(source + '\nexport { getHtmlAttribute, rewriteSvg };').toString('base64')
);
const element = raw => ({ getAttribute: () => raw });
const origin = 'https://proxy.example';
const proxy = path => origin + '/~https%3A%2F%2Fsite.example' + path;

test('XHTML numeric references follow XML rather than HTML C1 replacement rules', () => {
	assert.equal(getHtmlAttribute(element('tile&#128;.png'), 'src', true), 'tile\u0080.png');
	assert.equal(getHtmlAttribute(element('tile&#128;.png'), 'src'), 'tile€.png');
	assert.equal(getHtmlAttribute(element('a&amp;b&#x1F600;.png'), 'src', true), 'a&b😀.png');
});

test('XML literal attribute whitespace is normalized before character references are decoded', () => {
	assert.equal(getHtmlAttribute(element('a\r\nb\rc\td\ne&#9;f'), 'src', true), 'a b c d e\tf');
	assert.equal(getHtmlAttribute(element(null), 'src', true), null);
});

test('unknown XML entities are not replaced by HTML named entities or escaped into literal text', () => {
	assert.equal(getHtmlAttribute(element('&copy;/asset.png'), 'src', true), null);
	assert.equal(getHtmlAttribute(element('&assets;/asset.png'), 'src', true), null);
	assert.equal(getHtmlAttribute(element('&copy;/asset.png'), 'src'), '©/asset.png');
});

test('standalone SVG applies XML whitespace rules to both xml:base and resource attributes', () => {
	const input = '<svg xml:base="/my\tassets/"><image href="tile\r\nname.png"/></svg>';
	assert.equal(rewriteSvg(input, 'https://site.example/dir/doc.svg', origin),
		`<svg xml:base="${proxy('/my%20assets/')}"><image href="${proxy('/my%20assets/tile%20name.png')}"/></svg>`);
});

const miniflare = process.env.PE_MINIFLARE;
test('real Workerd: XHTML resource and style attributes retain XML character semantics', {
	skip: miniflare ? false : 'Set PE_MINIFLARE to an installed Miniflare 4 module path',
	timeout: 20_000,
}, async t => {
	const { Miniflare } = createRequire(import.meta.url)(miniflare);
	const xml = '<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body><img src="tile&#128;.png"/><a href="line\nbreak?x=1&amp;y=2">link</a><div style="background:url(p&#128;.png)"></div></body></html>';
	const runtime = new Miniflare({ cf: false, workers: [
		{ name: 'proxy', modules: true, compatibilityDate: '2026-07-30', outboundService: 'fixture',
			scriptPath: fileURLToPath(new URL('../worker.js', import.meta.url)), bindings: { ALLOWED_TARGET_ORIGINS: 'https://site.example' } },
		{ name: 'fixture', modules: true, compatibilityDate: '2026-07-30',
			script: `export default { fetch() { return new Response(${JSON.stringify(xml)}, { headers: { 'Content-Type': 'application/xhtml+xml' } }); } };` },
	] });
	t.after(() => runtime.dispose());
	const response = await runtime.dispatchFetch(proxy('/dir/page.xhtml'));
	assert.equal(response.status, 200);
	const output = await response.text();
	assert.ok(output.includes(proxy('/dir/tile%C2%80.png')));
	assert.ok(output.includes(proxy('/dir/line%20break?x=1&amp;y=2')));
	assert.ok(output.includes(proxy('/dir/p%C2%80.png')));
});
