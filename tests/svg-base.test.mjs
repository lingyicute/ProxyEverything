import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const source = await readFile(new URL('../worker.js', import.meta.url), 'utf8');
const { rewriteSvg } = await import(
	'data:text/javascript;base64,' + Buffer.from(source + '\nexport { rewriteSvg };').toString('base64')
);
const base = 'https://site.example/dir/doc.svg';
const origin = 'https://proxy.example';
const proxy = path => origin + '/~https%3A%2F%2Fsite.example' + path;
const rewrite = svg => rewriteSvg(svg, base, origin);

test('SVG xml:base scopes references and restores the parent base after closing tags', () => {
	const input = '<svg xml:base="/assets/"><g xml:base="icons/"><image href="one.png"/></g><image href="two.png"/></svg>';
	assert.equal(rewrite(input), `<svg xml:base="${proxy('/assets/')}"><g xml:base="${proxy('/assets/icons/')}"><image href="${proxy('/assets/icons/one.png')}"/></g><image href="${proxy('/assets/two.png')}"/></svg>`);
});

test('SVG xml:base on a self-closing element cannot affect its siblings', () => {
	const input = '<svg><image xml:base="../photos/" href="a.png"/><image href="b.png"/></svg>';
	assert.equal(rewrite(input), `<svg><image xml:base="${proxy('/photos/')}" href="${proxy('/photos/a.png')}"/><image href="${proxy('/dir/b.png')}"/></svg>`);
});

test('SVG styles and modules inherit xml:base without leaking their own scope', () => {
	const input = '<svg xml:base="/assets/"><style xml:base="paint/">a{fill:url(p.svg#x)}</style><script type="module" xml:base="js/">import "./entry.js";</script><image href="last.png"/></svg>';
	assert.equal(rewrite(input), `<svg xml:base="${proxy('/assets/')}"><style xml:base="${proxy('/assets/paint/')}">a{fill:url("${proxy('/assets/paint/p.svg#x')}")}</style><script type="module" xml:base="${proxy('/assets/js/')}">import "${proxy('/assets/js/entry.js')}";</script><image href="${proxy('/assets/last.png')}"/></svg>`);
});

test('SVG preserves fragment semantics and uses exact qualified names for base scopes', () => {
	const input = '<?xml-stylesheet href="sheet.css"?><s:svg xmlns:s="http://www.w3.org/2000/svg" xml:base="/a&amp;b/"><s:g xml:base="nested/"><s:use href="#paint"/></s:g><s:image href="logo.png"/></s:svg>';
	assert.equal(rewrite(input), `<?xml-stylesheet href="${proxy('/dir/sheet.css')}"?><s:svg xmlns:s="http://www.w3.org/2000/svg" xml:base="${proxy('/a&amp;b/')}"><s:g xml:base="${proxy('/a&amp;b/nested/')}"><s:use href="#paint"/></s:g><s:image href="${proxy('/a&amp;b/logo.png')}"/></s:svg>`);
});

test('SVG does not invent a base when a custom XML entity cannot be resolved', () => {
	const input = '<!DOCTYPE svg [<!ENTITY assets "/images/">]><svg xml:base="&assets;"><image href="logo.png"/></svg>';
	assert.equal(rewrite(input), input);
});

const miniflare = process.env.PE_MINIFLARE;
test('real Workerd: standalone SVG inherits and rewrites xml:base', {
	skip: miniflare ? false : 'Set PE_MINIFLARE to an installed Miniflare 4 module path',
	timeout: 20_000,
}, async t => {
	const { Miniflare } = createRequire(import.meta.url)(miniflare);
	const svg = '<svg xmlns="http://www.w3.org/2000/svg" xml:base="/images/"><image href="logo.png"/></svg>';
	const runtime = new Miniflare({ cf: false, workers: [
		{ name: 'proxy', modules: true, compatibilityDate: '2026-07-30', outboundService: 'fixture',
			scriptPath: fileURLToPath(new URL('../worker.js', import.meta.url)), bindings: { ALLOWED_TARGET_ORIGINS: 'https://site.example' } },
		{ name: 'fixture', modules: true, compatibilityDate: '2026-07-30',
			script: `export default { fetch() { return new Response(${JSON.stringify(svg)}, { headers: { 'Content-Type': 'image/svg+xml' } }); } };` },
	] });
	t.after(() => runtime.dispose());
	const response = await runtime.dispatchFetch(proxy('/dir/doc.svg'));
	assert.equal(response.status, 200);
	assert.equal(await response.text(), `<svg xmlns="http://www.w3.org/2000/svg" xml:base="${proxy('/images/')}"><image href="${proxy('/images/logo.png')}"/></svg>`);
});

test('SVG resolves XLink href by namespace URI rather than a fixed prefix', () => {
	const input = '<svg xmlns:ref="http://www.w3.org/1999/xlink" xmlns:xlink="urn:metadata">' +
		'<image ref:href="first.png" xlink:href="label"/>' +
		'<g xmlns:ref="urn:other"><image ref:href="label"/></g>' +
		'<image ref:href="label" xmlns:ref="urn:other"/><image ref:href="last.png"/></svg>';
	assert.equal(rewrite(input), input.replace('ref:href="first.png"', `ref:href="${proxy('/dir/first.png')}"`)
		.replace('ref:href="last.png"', `ref:href="${proxy('/dir/last.png')}"`));
});

test('SVG rewrites object data attributes without touching custom data attributes', () => {
	const input = '<svg><g data="raw" action="save" formaction="next"/><foreignObject><object xmlns="http://www.w3.org/1999/xhtml" data="embed.html"/><form xmlns="http://www.w3.org/1999/xhtml" action="submit"><button formaction="go"/></form></foreignObject></svg>';
	assert.equal(
		rewrite(input),
		`<svg><g data="raw" action="save" formaction="next"/><foreignObject><object xmlns="http://www.w3.org/1999/xhtml" data="${proxy('/dir/embed.html')}"/><form xmlns="http://www.w3.org/1999/xhtml" action="${proxy('/dir/submit')}"><button formaction="${proxy('/dir/go')}"/></form></foreignObject></svg>`
	);
});
