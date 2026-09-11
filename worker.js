/**
 * ProxyEverything — 通用网页反向代理 Cloudflare Worker
 *
 * URL 方案：
 *   https://<你的worker域名>/<encodeURIComponent(目标URL的路径部分)>?目标查询串
 *   例：https://example.com/page?a=1
 *     → https://<worker>/https%3A%2F%2Fexample.com%2Fpage?a=1
 *
 * 架构：单文件、ES Module 语法，无外部依赖，可直接粘贴到 Cloudflare Dashboard，
 * 或 `wrangler deploy` 部署。
 */

// ============================================================
// 常量与工具函数
// ============================================================

const HOP_BY_HOP = new Set([
	'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
	'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

// 这些响应头会破坏代理后的显示效果，全部剥掉
const STRIP_RESPONSE_HEADERS = [
	'content-security-policy',
	'content-security-policy-report-only',
	'x-frame-options',
	'x-content-type-options',
	'cross-origin-opener-policy',
	'cross-origin-embedder-policy',
	'cross-origin-resource-policy',
	'content-encoding',   // body 已被 Worker 解压/改写，必须移除
	'content-length',     // 改写后长度会变，交给运行时重算
	'link',               // preload/preconnect 指向原站，无意义
	'alt-svc',
	'report-to',
	'nel',
	'permissions-policy',
	'timing-allow-origin',
	'content-location',
	'refresh',
	'expect-ct',
	'server',
	'strict-transport-security',
];

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

// 常见懒加载 data-* 属性（按需扩充）
const LAZY_ATTRS = [
	'data-src', 'data-srcset', 'data-original', 'data-original-src',
	'data-original-set', 'data-lazy-src', 'data-lazy-srcset', 'data-lazy',
	'data-bg', 'data-bg-src', 'data-background', 'data-background-image',
	'data-url', 'data-href', 'data-link', 'data-uri', 'data-image',
	'data-image-src', 'data-img', 'data-thumb', 'data-thumbnail',
	'data-poster', 'data-video', 'data-video-src', 'data-audio',
	'data-audio-src', 'data-iframe', 'data-iframe-src', 'data-src-small',
	'data-src-medium', 'data-src-large', 'data-fallback-src', 'data-high-res-src',
	'data-low-res-src',
];

/** 安全 decodeURIComponent：源串含非法 % 序列时原样返回 */
function safeDecode(s) {
	try { return decodeURIComponent(s); } catch { return s; }
}

/**
 * 目标绝对 URL → 代理 URL（同源相对地址，可安全写入 href/src）
 * 查询串保持明文（与原实现兼容），哈希原样保留。
 */
function toProxyUrl(targetUrl, workerOrigin) {
	const u = new URL(targetUrl);
	if (u.protocol !== 'http:' && u.protocol !== 'https:' &&
		u.protocol !== 'ws:' && u.protocol !== 'wss:') return targetUrl;
	return `${workerOrigin}/${encodeURIComponent(u.protocol + '//' + u.host + u.pathname)}${u.search}${u.hash}`;
}

/**
 * 任意形式的 URL（绝对/协议相对/根相对/相对/已代理）→ 代理 URL。
 * 解析失败或不可代理的 scheme（data:、javascript:、mailto: 等）原样返回。
 */
function rewriteUrl(value, baseUrl, workerOrigin) {
	if (value == null) return value;
	let v = String(value).trim();
	if (!v) return v;
	// 页内锚点（#foo、url(#gradient)）保持原样
	if (v.startsWith('#')) return v;
	// 已经是本站代理 URL
	if (v.startsWith(workerOrigin + '/')) return v;
	if (/^\/(https?|wss?)%3A%2F%2F/i.test(v)) return v;
	try {
		const abs = new URL(v, baseUrl);
		// 已代理（同源且路径是编码后的目标 URL）
		if (abs.origin === workerOrigin && /^\/(https?|wss?)%3A%2F%2F/i.test(abs.pathname)) {
			return abs.pathname + abs.search + abs.hash;
		}
		return toProxyUrl(abs.href, workerOrigin);
	} catch {
		return v;
	}
}

/** 重写 srcset："url 1x, url 2x" / "url 320w, ..." */
function rewriteSrcset(value, baseUrl, workerOrigin) {
	return String(value)
		.split(',')
		.map(part => {
			const seg = part.trim().split(/\s+/);
			if (!seg.length || !seg[0]) return part;
			seg[0] = rewriteUrl(seg[0], baseUrl, workerOrigin);
			return seg.join(' ');
		})
		.join(', ');
}

/** 重写 CSS 文本：url(...) 与 @import */
function rewriteCss(css, baseUrl, workerOrigin) {
	let out = String(css).replace(
		/url\(\s*(?:"([^"]*)"|'([^']*)'|([^'"()]*(?:\([^'"()]*\)[^'"()]*)*))\s*\)/gi,
		(m, dq, sq, bare) => {
			if (dq !== undefined) return `url("${rewriteUrl(dq, baseUrl, workerOrigin)}")`;
			if (sq !== undefined) return `url('${rewriteUrl(sq, baseUrl, workerOrigin)}')`;
			const t = (bare || '').trim();
			if (!t) return m;
			return `url(${rewriteUrl(t, baseUrl, workerOrigin)})`;
		}
	);
	out = out.replace(/@import\s+("([^"]*)"|'([^']*)')/gi, (m, _all, dq, sq) => {
		const v = dq !== undefined ? dq : sq;
		const q = dq !== undefined ? '"' : "'";
		return `@import ${q}${rewriteUrl(v, baseUrl, workerOrigin)}${q}`;
	});
	return out;
}

/** 重写内联 style / CSS 字符串中的 url() */
function rewriteStyleAttr(style, baseUrl, workerOrigin) {
	return rewriteCss(style, baseUrl, workerOrigin);
}

/** 重写 <meta http-equiv="refresh" content="0; url=..."> */
function rewriteRefreshContent(content, baseUrl, workerOrigin) {
	return String(content).replace(/url\s*=\s*(.*)$/i, (m, u) =>
		'url=' + rewriteUrl(u.trim().replace(/^["']|["']$/g, ''), baseUrl, workerOrigin));
}

/** 清洗 Set-Cookie：去掉 Domain/Path，使其落在 Worker 域名根路径上 */
function cleanSetCookie(c) {
	return c
		.split(';')
		.filter((part, i) => {
			if (i === 0) return true;
			const name = part.trim().split('=')[0].toLowerCase();
			return name !== 'domain' && name !== 'path';
		})
		.join(';');
}

/** 从 Content-Type 中提取 charset 标签 */
function getCharset(contentType) {
	const m = /charset\s*=\s*"?([\w\-:.]+)"?/i.exec(contentType || '');
	return m ? m[1].toLowerCase() : null;
}

function isUtf8Charset(cs) {
	return !cs || cs === 'utf-8' || cs === 'utf8' || cs === 'unicode-1-1-utf-8';
}

/**
 * HTTP 头未声明 charset 时，嗅探 HTML 开头的 <meta charset>。
 * 使用 tee() 分流，不影响原始 body 消费。meta 标签均为 ASCII，
 * 即使实际编码是 GBK 等非 UTF-8，用 UTF-8 宽松解码也能匹配到。
 */
async function sniffHtmlCharset(body) {
	const [a, b] = body.tee();
	const reader = a.getReader();
	const chunks = [];
	let total = 0;
	try {
		while (total < 4096) {
			const { done, value } = await reader.read();
			if (done) break;
			chunks.push(value);
			total += value.length;
		}
	} catch { /* ignore */ } finally {
		try { reader.cancel(); } catch {}
	}
	const head = new Uint8Array(total);
	let off = 0;
	for (const c of chunks) { head.set(c, off); off += c.length; }
	const text = new TextDecoder().decode(head).toLowerCase();
	const m = /<meta[^>]{0,300}?charset\s*=\s*["']?\s*([a-z0-9_\-:.]+)/.exec(text) ||
		/<meta[^>]{0,300}?content\s*=\s*["'][^"']*?charset=([a-z0-9_\-:.]+)/.exec(text);
	return { charset: m ? m[1] : null, body: b };
}

/** 构造透传 Response（headers 可变），并做统一清洗 */
function buildResponse(upstream, request) {
	const resp = new Response(upstream.body, upstream);
	for (const h of STRIP_RESPONSE_HEADERS) resp.headers.delete(h);
	for (const [name] of upstream.headers) {
		if (HOP_BY_HOP.has(name.toLowerCase())) resp.headers.delete(name);
	}
	resp.headers.set('X-Robots-Tag', 'noindex, nofollow');
	// 统一放开 CORS，方便被改写的脚本跨域读取
	resp.headers.set('Access-Control-Allow-Origin', '*');
	resp.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS');
	resp.headers.set('Access-Control-Allow-Headers', '*');
	resp.headers.set('Access-Control-Allow-Credentials', 'true');
	// Set-Cookie 清洗
	const cookies = resp.headers.getSetCookie ? resp.headers.getSetCookie() : [];
	if (cookies.length) {
		resp.headers.delete('set-cookie');
		for (const c of cookies) resp.headers.append('Set-Cookie', cleanSetCookie(c));
	}
	// 防止缓存中间层缓存错误页
	if (upstream.status >= 500) {
		resp.headers.set('Cache-Control', 'no-store');
	} else if (request && !isCacheableMethod(request.method)) {
		resp.headers.set('Cache-Control', 'no-store');
	}
	return resp;
}

function isCacheableMethod(m) { return m === 'GET' || m === 'HEAD'; }

// ============================================================
// 运行时注入脚本（浏览器端 shim）
// 让 JS 动态发起的请求（fetch/XHR/WebSocket/img.src 等）也走代理
// ============================================================

function getShimScript(workerOrigin) {
	return `<script>(function(){
try{
var WO=${JSON.stringify(workerOrigin)};
var RAW=location.pathname.substring(1);
var DEC;try{DEC=decodeURIComponent(RAW);}catch(e){DEC=RAW;}
if(!/^[a-z][a-z0-9+.-]*:\\/\\//i.test(DEC))DEC='https://'+DEC.replace(/^\\/+/,'');
var hIdx=DEC.indexOf('#');if(hIdx>=0)DEC=DEC.substring(0,hIdx);
var TARGET=DEC+location.search;
var ABS_RE=/^[a-z][a-z0-9+.-]*:\\/\\//i;
var SKIP_RE=/^(data:|blob:|javascript:|mailto:|tel:|sms:|about:|#|\\?)/i;
function base(){
  var b=document.querySelector('base');
  if(b){var h=b.getAttribute('href');if(h){try{return new URL(h,TARGET).href;}catch(e){}}}
  return TARGET;
}
function rp(v){
  if(v==null)return v;
  if(typeof v==='object'){
    if(v instanceof URL)return rp(v.href);
    return v;
  }
  var s=String(v).trim();
  if(!s||SKIP_RE.test(s))return s;
  if(s.indexOf(WO+'/')===0)return s;
  if(/^\\/(https?|wss?)%3A%2F%2F/i.test(s))return s;
  if(/^\\/(https?|wss?):\\/\\//i.test(s))return s;
  var abs;try{abs=new URL(s,base()).href;}catch(e){return s;}
  if(abs.indexOf(WO+'/')===0)return abs;
  if(ABS_RE.test(abs)){
    var u;try{u=new URL(abs);}catch(e){return s;}
    var p=u.protocol;
    if(p!=='http:'&&p!=='https:'&&p!=='ws:'&&p!=='wss:')return s;
    return WO+'/'+encodeURIComponent(p+'//'+u.host+u.pathname)+u.search+u.hash;
  }
  return abs;
}
function rwUrlArg(a){
  if(typeof a==='string')return rp(a);
  if(a instanceof URL)return new URL(rp(a.href));
  return a;
}
window.__PE__={target:TARGET,rp:rp};
/* ---- fetch ---- */
var of_=window.fetch;
if(of_)window.fetch=function(input,init){
  try{
    if(typeof input==='string')input=rp(input);
    else if(input instanceof URL)input=rp(input.href);
    else if(input&&typeof input==='object'&&'url'in input){
      var nu=rp(input.url);
      if(nu&&nu!==input.url)input=new Request(nu,input);
    }
  }catch(e){}
  return of_.call(this,input,init);
};
/* ---- XMLHttpRequest ---- */
var oOpen=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){
  try{arguments[1]=rwUrlArg(u);}catch(e){}
  return oOpen.apply(this,arguments);
};
/* ---- EventSource / sendBeacon / WebSocket ---- */
if(window.EventSource){var oES=window.EventSource;window.EventSource=function(u,c){return new oES(rwUrlArg(u),c);};window.EventSource.prototype=oES.prototype;}
if(navigator.sendBeacon){var oSB=navigator.sendBeacon.bind(navigator);navigator.sendBeacon=function(u,d){try{u=rp(u);}catch(e){}return oSB(u,d);};}
if(window.Worker){var oWk=window.Worker;window.Worker=function(u,o){return new oWk(rp(u),o);};window.Worker.prototype=oWk.prototype;}
try{if(window.SharedWorker){var oSW=window.SharedWorker;window.SharedWorker=function(u,o){return new oSW(rp(u),o);};window.SharedWorker.prototype=oSW.prototype;}}catch(e){}
/* Service Worker 无法在代理路径下正确工作，直接禁用注册以免站点异常 */
try{if(navigator.serviceWorker)navigator.serviceWorker.register=function(){return Promise.reject(new Error('[ProxyEverything] service worker disabled'));};}catch(e){}
/* ---- WebSocket：URL 改写 + 查询串携带 token（鉴权用） ---- */
if(window.WebSocket){
  var oWS=window.WebSocket;
  var WS=function(u,protos){
    var nu=u;
    try{
      if(typeof u==='string')nu=rp(u);
      else if(u instanceof URL)nu=rp(u.href);
      if(typeof nu==='string'&&!/^wss?:\\/\\//i.test(nu)){
        var au=new URL(nu,location.href);
        if(au.origin===location.origin)au.protocol=location.protocol==='https:'?'wss:':'ws:';
        au.searchParams.set('__pe',RAW);
        nu=au.href;
      }
    }catch(e){}
    return protos===undefined?new oWS(nu):new oWS(nu,protos);
  };
  WS.prototype=oWS.prototype;
  ['CONNECTING','OPEN','CLOSING','CLOSED'].forEach(function(k,i){try{WS[k]=i;}catch(e){}});
  window.WebSocket=WS;
}
/* ---- history / window.open / location.assign ---- */
function wrapHistory(fn){return function(st,t,u){try{if(u!=null)arguments[2]=rp(u);}catch(e){}return fn.apply(this,arguments);};}
if(history.pushState)history.pushState=wrapHistory(history.pushState);
if(history.replaceState)history.replaceState=wrapHistory(history.replaceState);
var oWo=window.open;
if(oWo)window.open=function(u){try{arguments[0]=rwUrlArg(u);}catch(e){}return oWo.apply(this,arguments);};
try{var oAs=location.assign.bind(location);location.assign=function(u){return oAs(rp(u));};}catch(e){}
try{var oRe=location.replace.bind(location);location.replace=function(u){return oRe(rp(u));};}catch(e){}
/* ---- DOM 属性 setter 拦截：img.src = "..." 等动态赋值 ---- */
function patchSetter(ctor,prop,ss){
  try{
    if(!ctor||!ctor.prototype)return;
    var d=Object.getOwnPropertyDescriptor(ctor.prototype,prop);
    if(!d||!d.set||!d.configurable)return;
    var orig=d.set;
    Object.defineProperty(ctor.prototype,prop,{
      configurable:true,enumerable:d.enumerable,get:d.get,
      set:function(v){try{v=ss?rwSrcset(v):rwUrlArg(v);}catch(e){}return orig.call(this,v);}
    });
  }catch(e){}
}
function rwSrcset(v){
  if(typeof v!=='string')return v;
  return v.split(',').map(function(p){
    var s=p.trim().split(/\\s+/);
    if(s.length&&s[0])s[0]=rp(s[0]);
    return s.join(' ');
  }).join(', ');
}
var I=window.HTMLImageElement;
patchSetter(I,'src');patchSetter(I,'srcset',1);
patchSetter(window.HTMLScriptElement,'src');
patchSetter(window.HTMLIFrameElement,'src');
patchSetter(window.HTMLLinkElement,'href');
patchSetter(window.HTMLAnchorElement,'href');
patchSetter(window.HTMLSourceElement,'src');patchSetter(window.HTMLSourceElement,'srcset',1);
patchSetter(window.HTMLMediaElement,'src');
patchSetter(window.HTMLVideoElement,'poster');
patchSetter(window.HTMLFormElement,'action');
patchSetter(window.HTMLObjectElement,'data');
patchSetter(window.HTMLEmbedElement,'src');
patchSetter(window.HTMLInputElement,'src');
patchSetter(window.HTMLTrackElement,'src');
/* setAttribute 兜底（src/srcset/action/href/poster/data） */
var ATTRS={src:0,srcset:1,action:0,poster:0,data:0,href:0};
if(window.Element){
  var oSA=Element.prototype.setAttribute;
  Element.prototype.setAttribute=function(n,v){
    try{
      if(typeof n==='string'&&typeof v==='string'){
        var ln=n.toLowerCase();
        if(Object.prototype.hasOwnProperty.call(ATTRS,ln)){
          var tag=this.tagName;
          if(ln!=='href'||tag==='A'||tag==='LINK'||tag==='AREA'||tag==='BASE'){
            arguments[1]=ATTRS[ln]?rwSrcset(v):rp(v);
          }
        }
      }
    }catch(e){}
    return oSA.apply(this,arguments);
  };
}
/* ---- 表单提交兜底 ---- */
document.addEventListener('submit',function(ev){
  try{
    var f=ev.target;
    if(!f||f.tagName!=='FORM')return;
    var a=f.getAttribute('action');
    if(a){var p=rp(a);if(p&&p!==a)f.setAttribute('action',p);}
  }catch(e){}
},true);
}catch(e){try{console.error('[ProxyEverything] shim error',e);}catch(_){}}
})();</script>`;
}

// ============================================================
// HTML 重写（基于 HTMLRewriter，流式处理）
// ============================================================

const HANDLERS = {
	a:            { href: 'url' },
	area:         { href: 'url' },
	link:         { href: 'url' },
	script:       { src: 'url' },
	img:          { src: 'url', srcset: 'srcset' },
	image:        { href: 'url', 'xlink:href': 'url' },
	iframe:       { src: 'url' },
	frame:        { src: 'url' },
	source:       { src: 'url', srcset: 'srcset' },
	video:        { src: 'url', poster: 'url' },
	audio:        { src: 'url' },
	track:        { src: 'url' },
	embed:        { src: 'url' },
	object:       { data: 'url' },
	input:        { src: 'url' },
	form:         { action: 'url' },
	use:          { href: 'url', 'xlink:href': 'url' },
};

function transformHtml(response, baseUrl, workerOrigin) {
	const rewriter = new HTMLRewriter();
	let baseHref = baseUrl;
	let injected = false;
	const shim = getShimScript(workerOrigin);
	const rw = (v) => rewriteUrl(v, baseHref, workerOrigin);

	// 注入运行时 shim（head 优先，无 head 则 body 兜底）
	rewriter.on('head', {
		element(el) {
			if (!injected) { injected = true; el.prepend(shim, { html: true }); }
		},
	});
	rewriter.on('body', {
		element(el) {
			if (!injected) { injected = true; el.prepend(shim, { html: true }); }
		},
	});

	// <base href="...">：记录后移除，避免浏览器用错误的 base 解析相对地址
	rewriter.on('base', {
		element(el) {
			const h = el.getAttribute('href');
			if (h) {
				try { baseHref = new URL(h, baseHref).href; } catch {}
			}
			el.remove();
		},
	});

	// CSP meta 标签直接移除；refresh meta 重写目标；charset meta 对齐为 UTF-8
	rewriter.on('meta', {
		element(el) {
			const he = (el.getAttribute('http-equiv') || '').toLowerCase();
			if (he === 'content-security-policy' || he === 'content-security-policy-report-only') {
				el.remove();
				return;
			}
			if (he === 'refresh') {
				const c = el.getAttribute('content');
				if (c) el.setAttribute('content', rewriteRefreshContent(c, baseHref, workerOrigin));
			}
			if (he === 'content-type') {
				const c = el.getAttribute('content');
				if (c) el.setAttribute('content', c.replace(/charset=[^;]*/i, 'charset=UTF-8'));
			}
			if (el.getAttribute('charset') != null) {
				el.setAttribute('charset', 'UTF-8');
			}
		},
	});

	// <style> 内容重写（缓冲所有分片，最后一片时整体替换）
	let styleBuf = '';
	rewriter.on('style', {
		element() { styleBuf = ''; },
		text(chunk) {
			styleBuf += chunk.text;
			if (chunk.lastInTextNode) {
				chunk.replace(rewriteCss(styleBuf, baseHref, workerOrigin), { html: false });
				styleBuf = '';
			} else {
				chunk.remove();
			}
		},
	});

	// 具体标签的 URL 属性
	for (const [tag, attrs] of Object.entries(HANDLERS)) {
		rewriter.on(tag, {
			element(el) {
				// 内容被我们改写过的资源必须去掉 SRI，否则哈希校验失败被浏览器拦截
				if (tag === 'script' || tag === 'link') el.removeAttribute('integrity');
				for (const [attr, kind] of Object.entries(attrs)) {
					const v = el.getAttribute(attr);
					if (v == null) continue;
					el.setAttribute(attr, kind === 'srcset' ? rewriteSrcset(v, baseHref, workerOrigin) : rw(v));
				}
				// script 标签上的内联 srcset 不存在；但懒加载属性可能出现在任意标签上（下面统一处理）
			},
		});
	}

	// 通配：style 属性、懒加载 data-* 属性
	rewriter.on('*', {
		element(el) {
			const st = el.getAttribute('style');
			if (st && /url\s*\(/i.test(st)) {
				el.setAttribute('style', rewriteStyleAttr(st, baseHref, workerOrigin));
			}
			for (const attr of LAZY_ATTRS) {
				const v = el.getAttribute(attr);
				if (v == null) continue;
				el.setAttribute(attr, /srcset$/.test(attr) ? rewriteSrcset(v, baseHref, workerOrigin) : rw(v));
			}
		},
	});

	const out = rewriter.transform(response);
	// HTMLRewriter 输出统一为 UTF-8
	const ct = out.headers.get('content-type') || 'text/html';
	out.headers.set('content-type', ct.split(';')[0] + '; charset=UTF-8');
	return out;
}

// ============================================================
// CSS / JS / SVG / JSON / Manifest 文本重写（整体缓冲）
// ============================================================

async function transformText(response, baseUrl, workerOrigin, kind) {
	let text = await response.text();
	try {
		if (kind === 'css') {
			text = rewriteCss(text, baseUrl, workerOrigin);
		} else if (kind === 'js') {
			text = rewriteJsModuleSpecifiers(text, baseUrl, workerOrigin);
		} else if (kind === 'svg') {
			text = rewriteSvg(text, baseUrl, workerOrigin);
		} else if (kind === 'json' || kind === 'manifest') {
			text = rewriteJsonUrls(text, baseUrl, workerOrigin);
		}
	} catch { /* 重写失败则回退原文 */ }

	const resp = new Response(text, response);
	for (const h of STRIP_RESPONSE_HEADERS) resp.headers.delete(h);
	resp.headers.delete('content-length');
	resp.headers.delete('content-encoding');
	const ct = (response.headers.get('content-type') || '').split(';')[0];
	resp.headers.set('content-type', (ct || 'text/plain') + '; charset=UTF-8');
	resp.headers.set('X-Robots-Tag', 'noindex, nofollow');
	resp.headers.set('Access-Control-Allow-Origin', '*');
	return resp;
}

/**
 * 重写 ES 模块的 import/export 说明符，让 Vite/Webpack 等打包产物的
 * 相对 chunk、相对 import 也能走代理。
 * 只重写“看起来像 URL”的说明符（./ ../ / scheme://），最大限度避免误伤字符串。
 * 该操作是幂等的：重写结果（本站绝对 URL）不满足再次重写的条件。
 */
function rewriteJsModuleSpecifiers(js, baseUrl, workerOrigin) {
	const ABS_SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
	const tryRewrite = (spec) => {
		const t = spec.trim();
		if (!t) return null;
		if (!(t.startsWith('./') || t.startsWith('../') || t.startsWith('/') || ABS_SCHEME_RE.test(t))) return null;
		if (t.startsWith(workerOrigin)) return null; // 已代理，保证幂等
		const r = rewriteUrl(t, baseUrl, workerOrigin);
		return r === t ? null : r;
	};

	let out = String(js);
	// import x from "..." / export * from '...'
	out = out.replace(
		/\bfrom\s*(['"])((?:[^'"\\]|\\.)*)\1/g,
		(m, q, spec) => {
			const r = tryRewrite(spec);
			return r ? `from ${q}${r}${q}` : m;
		}
	);
	// import("...") / import(`...`) 动态导入（模板字符串仅在无插值时处理）
	out = out.replace(
		/\bimport\s*\(\s*(['"`])((?:(?!\1)[^\\${]|\\.)*)\1\s*\)/g,
		(m, q, spec) => {
			const r = tryRewrite(spec);
			return r ? `import(${q}${r}${q})` : m;
		}
	);
	// import "..." 副作用导入
	out = out.replace(
		/\bimport\s+(['"])((?:[^'"\\]|\\.)*)\1/g,
		(m, q, spec) => {
			const r = tryRewrite(spec);
			return r ? `import ${q}${r}${q}` : m;
		}
	);
	return out;
}

/** 独立 SVG 文档：正则重写引用属性与内嵌样式 */
function rewriteSvg(svg, baseUrl, workerOrigin) {
	const rw = (v) => rewriteUrl(v, baseUrl, workerOrigin);
	let out = String(svg).replace(
		/\b(href|xlink:href|src)\s*=\s*("([^"]*)"|'([^']*)')/gi,
		(m, attr, _q, dq, sq) => {
			const v = dq !== undefined ? dq : sq;
			const r = rw(v);
			return `${attr}="${r.replace(/"/g, '&quot;')}"`;
		}
	);
	out = out.replace(/(<style[^>]*>)([\s\S]*?)(<\/style>)/gi,
		(m, open, css, close) => open + rewriteCss(css, baseUrl, workerOrigin) + close);
	out = out.replace(/\bstyle\s*=\s*("([^"]*)"|'([^']*)')/gi, (m, _q, dq, sq) => {
		const v = dq !== undefined ? dq : sq;
		if (!/url\s*\(/i.test(v)) return m;
		return `style="${rewriteStyleAttr(v, baseUrl, workerOrigin).replace(/"/g, '&quot;')}"`;
	});
	return out;
}

/**
 * JSON / Web App Manifest：重写字符串值里的同源绝对 URL 与根路径。
 * 只重写完整字符串值，不碰字符串内部片段，风险极低。
 */
function rewriteJsonUrls(text, baseUrl, workerOrigin) {
	const baseOrigin = new URL(baseUrl).origin;
	return String(text).replace(
		/"((?:https?:)?\/\/[^"\s\\]*(?:\\.[^"\s\\]*)*|\/[^"\s\\]*(?:\\.[^"\s\\]*)*)"/g,
		(m, v) => {
			if (v.includes(workerOrigin)) return m;
			// 协议相对 URL
			let candidate = v;
			if (candidate.startsWith('//')) candidate = 'https:' + candidate;
			let abs;
			try { abs = new URL(candidate, baseUrl); } catch { return m; }
			const isSameOrigin = abs.origin === baseOrigin;
			const isRootPath = v.startsWith('/') && !v.startsWith('//');
			if (!isSameOrigin && !isRootPath) return m;
			// 跳过明显的 API 路径参数值（带查询的仍重写，交给服务端处理）
			const r = toProxyUrl(abs.href, workerOrigin);
			return `"${r}"`;
		}
	);
}

// ============================================================
// 请求解析
// ============================================================

/** 去掉我们内部的 __pe 查询参数，其余查询串原样保留（不破坏签名 URL） */
function stripInternalParams(search) {
	if (!search || !search.includes('__pe=')) return search;
	const qs = search.startsWith('?') ? search.slice(1) : search;
	const kept = qs.split('&').filter(p => p && !p.startsWith('__pe='));
	return kept.length ? '?' + kept.join('&') : '';
}

/** 从代理 URL 解析出目标绝对 URL；非法时返回 null */
function parseTarget(url) {
	if (url.pathname === '/' || url.pathname === '') return null;
	const raw = safeDecode(url.pathname.substring(1));
	if (!raw) return null;
	let target;
	if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
		target = raw;
	} else {
		target = 'https://' + raw.replace(/^\/+/, '');
	}
	// 合并查询串（排除内部参数）
	const search = stripInternalParams(url.search);
	if (search) {
		target += (target.includes('?') ? '&' : '?') + search.slice(1);
	}
	let u;
	try { u = new URL(target); } catch { return null; }
	if (!['http:', 'https:', 'ws:', 'wss:'].includes(u.protocol)) return null;
	if (!u.hostname.includes('.') && u.hostname !== 'localhost') return null;
	u.username = ''; u.password = '';
	u.hash = '';
	return u;
}

/** 目标 URL → 页面“文档基地址”（用于解析相对 URL） */
function documentBase(targetUrl) {
	return targetUrl.href;
}

// ============================================================
// WebSocket 代理
// ============================================================

async function handleWebSocket(request, targetUrl) {
	// ws/wss → http/https 供 fetch 建立上游连接
	const upstreamUrl = new URL(targetUrl.href);
	upstreamUrl.protocol = upstreamUrl.protocol === 'ws:' ? 'http:' : 'https:';

	// 构造转发请求：带上原始头（去掉宿主相关）
	const headers = new Headers();
	for (const [k, v] of request.headers) {
		const lk = k.toLowerCase();
		if (lk.startsWith('cf-') || HOP_BY_HOP.has(lk)) continue;
		headers.set(k, v);
	}
	headers.delete('host');
	headers.set('Origin', upstreamUrl.origin);
	headers.set('Upgrade', 'websocket');

	const resp = await fetch(upstreamUrl.href, { headers, redirect: 'follow' });
	const upstream = resp.webSocket;
	if (!upstream) {
		return new Response('上游不支持 WebSocket', { status: 502 });
	}
	upstream.accept();

	const pair = new WebSocketPair();
	const client = pair[0];
	client.accept();

	const pipe = (from, to) => {
		from.addEventListener('message', ev => {
			try { to.send(ev.data); } catch {}
		});
		from.addEventListener('close', ev => {
			try { to.close(ev.code, ev.reason); } catch {}
		});
		from.addEventListener('error', () => {
			try { to.close(1011, 'upstream error'); } catch {}
		});
	};
	pipe(upstream, client);
	pipe(client, upstream);

	return new Response(null, { status: 101, webSocket: pair[1] });
}

// ============================================================
// 主入口
// ============================================================

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const workerOrigin = url.origin;

		// ---- CORS 预检 ----
		if (request.method === 'OPTIONS' && request.headers.has('access-control-request-method')) {
			return new Response(null, {
				status: 204,
				headers: {
					'Access-Control-Allow-Origin': '*',
					'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS',
					'Access-Control-Allow-Headers': '*',
					'Access-Control-Allow-Credentials': 'true',
					'Access-Control-Max-Age': '86400',
				},
			});
		}

		// ---- 首页 ----
		if (url.pathname === '/' || url.pathname === '') {
			return new Response(getRootHtml(), {
				headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
			});
		}

		// ---- favicon 等杂项，避免被当成目标域名 ----
		if (/^\/(favicon\.ico|robots\.txt|sitemap\.xml|apple-touch-icon.*\.png|\.well-known\/.*)$/i.test(url.pathname)) {
			return new Response(null, { status: 404 });
		}

		// ---- 解析目标 URL ----
		const targetUrl = parseTarget(url);
		if (!targetUrl) {
			return invalidTargetPage(url);
		}
		// 防环：不允许代理 Worker 自身（比较 host 含端口）
		if (targetUrl.host === url.host) {
			return invalidTargetPage(url, '不允许代理本站自身');
		}

		// WebSocket 请求走独立通道
		if (request.headers.get('Upgrade') === 'websocket') {
			try {
				return await handleWebSocket(request, targetUrl);
			} catch (e) {
				return new Response('WebSocket 代理失败: ' + e.message, { status: 502 });
			}
		}

		// ---- 构造转发请求 ----
		if (targetUrl.protocol === 'ws:' || targetUrl.protocol === 'wss:') {
			targetUrl.protocol = targetUrl.protocol === 'ws:' ? 'http:' : 'https:';
		}
		const fetchUrl = targetUrl.href;

		const fwdHeaders = new Headers();
		for (const [k, v] of request.headers) {
			const lk = k.toLowerCase();
			if (lk.startsWith('cf-') || HOP_BY_HOP.has(lk)) continue;
			fwdHeaders.set(k, v);
		}
		// 伪装成直连访问：重写 Origin / Referer
		fwdHeaders.set('Origin', targetUrl.origin);
		const referer = request.headers.get('referer');
		if (referer) {
			try {
				const rUrl = new URL(referer);
				if (rUrl.origin === workerOrigin) {
					const rTarget = parseTarget(rUrl);
					fwdHeaders.set('Referer', rTarget ? rTarget.href : fetchUrl);
				}
			} catch {}
		} else {
			fwdHeaders.set('Referer', fetchUrl);
		}
		fwdHeaders.delete('host');

		let upstream;
		try {
			upstream = await fetch(fetchUrl, {
				method: request.method,
				headers: fwdHeaders,
				body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
				redirect: 'manual',
			});
		} catch (e) {
			return errorPage(targetUrl.href, e);
		}

		// ---- 重定向 ----
		if (REDIRECT_STATUS.has(upstream.status)) {
			const resp = buildResponse(upstream, request);
			const loc = upstream.headers.get('location');
			if (loc) {
				try {
					const abs = new URL(loc, fetchUrl);
					resp.headers.set('Location', toProxyUrl(abs.href, workerOrigin));
				} catch {
					resp.headers.delete('Location');
				}
			}
			// 303 强制 GET；无 body 的重定向直接返回
			return new Response(null, resp);
		}

		// ---- 204 / 304 无正文 ----
		if (upstream.status === 204 || upstream.status === 304 || request.method === 'HEAD') {
			const resp = buildResponse(upstream, request);
			return new Response(null, resp);
		}

		// ---- 按内容类型处理 ----
		const contentType = (upstream.headers.get('content-type') || '').toLowerCase();
		const baseUrl = documentBase(targetUrl);
		const isHtml = contentType.includes('text/html') || contentType.includes('application/xhtml+xml');
		const isTextual = isHtml || contentType.includes('text/') || contentType.includes('javascript') ||
			contentType.includes('ecmascript') || contentType.includes('json') ||
			contentType.includes('svg') || contentType.includes('xml');

		let bodySource = upstream.body;
		let charset = getCharset(contentType);

		// HTML 且头部未声明 charset：嗅探正文开头的 <meta charset>
		if (isHtml && !charset) {
			const sniffed = await sniffHtmlCharset(upstream.body);
			charset = sniffed.charset;
			bodySource = sniffed.body;
		}

		// 非 UTF-8 的文本先转码为 UTF-8，避免 HTMLRewriter/正则处理时乱码
		if (isTextual && charset && !isUtf8Charset(charset)) {
			try {
				bodySource = bodySource
					.pipeThrough(new TextDecoderStream(charset))
					.pipeThrough(new TextEncoderStream());
			} catch {
				bodySource = upstream.body; // 非法 charset 标签则按原样处理
			}
		}

		/**
		 * 构造中间 Response：携带上游全部响应头（剔除会破坏代理的头），
		 * 以便缓存/ETag 等语义保留；正文换成（可能已转码的）流。
		 */
		const makeInterim = (ctOverride) => {
			const interim = new Response(bodySource, upstream);
			for (const h of STRIP_RESPONSE_HEADERS) interim.headers.delete(h);
			for (const [name] of upstream.headers) {
				if (HOP_BY_HOP.has(name.toLowerCase())) interim.headers.delete(name);
			}
			if (ctOverride) interim.headers.set('content-type', ctOverride);
			return interim;
		};

		// HTML：流式重写（输入统一为 UTF-8，Content-Type 同步覆盖，
		// 避免 HTMLRewriter 按 meta 里的旧 charset 重新编码输出）
		if (isHtml) {
			const interim = makeInterim((contentType.split(';')[0] || 'text/html') + '; charset=UTF-8');
			const result = transformHtml(interim, baseUrl, workerOrigin);
			// 补一遍统一头处理
			result.headers.set('X-Robots-Tag', 'noindex, nofollow');
			result.headers.set('Access-Control-Allow-Origin', '*');
			if (!isCacheableMethod(request.method) || upstream.status >= 500) {
				result.headers.set('Cache-Control', 'no-store');
			}
			const cookies = result.headers.getSetCookie ? result.headers.getSetCookie() : [];
			if (cookies.length) {
				result.headers.delete('set-cookie');
				for (const c of cookies) result.headers.append('Set-Cookie', cleanSetCookie(c));
			}
			return result;
		}

		// CSS
		if (contentType.includes('text/css')) {
			return applyCommon(await transformText(makeInterim(), baseUrl, workerOrigin, 'css'), upstream, request);
		}

		// JS（仅重写 ES 模块说明符，幂等且只碰“像 URL”的字符串）
		if (contentType.includes('javascript') || contentType.includes('ecmascript')) {
			return applyCommon(await transformText(makeInterim(), baseUrl, workerOrigin, 'js'), upstream, request);
		}

		// SVG
		if (contentType.includes('image/svg+xml')) {
			return applyCommon(await transformText(makeInterim(), baseUrl, workerOrigin, 'svg'), upstream, request);
		}

		// Web App Manifest（图标、start_url 等）
		if (contentType.includes('manifest+json')) {
			return applyCommon(await transformText(makeInterim(), baseUrl, workerOrigin, 'json'), upstream, request);
		}

		// 其它（JSON API/图片/字体/媒体/下载等）：流式透传
		// 说明：JSON 内容不重写 —— 动态场景已由浏览器端 shim（fetch/XHR/属性 setter）覆盖，
		// 直接改写 API 数据反而可能破坏业务逻辑。
		const resp = buildResponse(upstream, request);
		return resp;
	},
};

/** transformText 的产物再补一遍统一头处理 */
function applyCommon(resp, upstream, request) {
	for (const [name] of upstream.headers) {
		if (HOP_BY_HOP.has(name.toLowerCase())) resp.headers.delete(name);
	}
	const cookies = upstream.headers.getSetCookie ? upstream.headers.getSetCookie() : [];
	if (cookies.length) {
		resp.headers.delete('set-cookie');
		for (const c of cookies) resp.headers.append('Set-Cookie', cleanSetCookie(c));
	}
	resp.headers.set('X-Robots-Tag', 'noindex, nofollow');
	if (!isCacheableMethod(request.method) || upstream.status >= 500) {
		resp.headers.set('Cache-Control', 'no-store');
	}
	return resp;
}

// ============================================================
// 页面：错误页 / 首页 —— Material Design 3 (Material You)
// 纯原生实现：CSS 自定义属性令牌 + oklch 动态色调调色板，无框架
// ============================================================

function escapeHtml(s) {
	return String(s).replace(/[&<>"']/g, c =>
		({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function invalidTargetPage(url, reason) {
	return new Response(renderErrorPage(
		'无效的目标地址',
		reason || `无法从路径 "${escapeHtml(url.pathname.slice(0, 120))}" 解析出合法的目标 URL。请通过首页表单访问，或确保地址已正确编码。`
	), { status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}

function errorPage(targetHref, err) {
	return new Response(renderErrorPage(
		'请求上游失败',
		`代理请求 ${escapeHtml(targetHref)} 时出错：${escapeHtml(err && err.message ? err.message : String(err))}。<br>目标站点可能拒绝了来自 Cloudflare 的请求，或暂时不可用。`
	), { status: 502, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}

// ---- 内联图标（MD symbols 风格，24dp，stroke 绘制） ----
const ICON = {
	globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.7 3.8 9S14.5 18.4 12 21c-2.5-2.6-3.8-5.7-3.8-9S9.5 5.6 12 3z"/></svg>',
	link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/></svg>',
	arrow: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 12h15M13 6l6 6-6 6"/></svg>',
	moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z"/></svg>',
	sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M19.1 4.9l-1.8 1.8M6.7 17.3l-1.8 1.8"/></svg>',
	github: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2C6.48 2 2 6.58 2 12.25c0 4.53 2.87 8.37 6.84 9.73.5.1.68-.22.68-.49 0-.24-.01-.87-.01-1.7-2.78.62-3.37-1.37-3.37-1.37-.45-1.18-1.11-1.5-1.11-1.5-.91-.63.07-.62.07-.62 1 .07 1.53 1.06 1.53 1.06.89 1.57 2.34 1.12 2.91.85.09-.66.35-1.11.63-1.37-2.22-.26-4.56-1.14-4.56-5.07 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.7 0 0 .84-.28 2.75 1.05a9.36 9.36 0 0 1 5 0c1.91-1.33 2.75-1.05 2.75-1.05.55 1.4.2 2.44.1 2.7.64.72 1.03 1.63 1.03 2.75 0 3.94-2.34 4.8-4.57 5.06.36.32.68.94.68 1.9 0 1.37-.01 2.47-.01 2.81 0 .27.18.6.69.49A10.25 10.25 0 0 0 22 12.25C22 6.58 17.52 2 12 2z"/></svg>',
	warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3.5 1.8 20.5h20.4L12 3.5z"/><path d="M12 10v4.5M12 17.8v.2"/></svg>',
};

// ---- MD3 设计令牌与组件样式（light/dark 双主题，oklch 动态色） ----
const MD3_CSS = `
/* ---------- 形状 / 动效 /  elevation 令牌 ---------- */
:root{
  --shape-xs:4px; --shape-sm:8px; --shape-md:12px; --shape-lg:16px; --shape-xl:28px; --shape-full:9999px;
  --ease-standard:cubic-bezier(.2,0,0,1);
  --ease-decel:cubic-bezier(.05,.7,.1,1);
  --ease-accel:cubic-bezier(.3,0,.8,.15);
  --dur-short:200ms; --dur-med:350ms; --dur-long:500ms;
  --elev-1:0 1px 2px rgba(0,0,0,.30),0 1px 3px 1px rgba(0,0,0,.15);
  --elev-2:0 1px 2px rgba(0,0,0,.30),0 2px 6px 2px rgba(0,0,0,.15);
  --elev-3:0 1px 3px rgba(0,0,0,.30),0 4px 8px 3px rgba(0,0,0,.15);
  --font:Roboto,"Segoe UI",system-ui,-apple-system,"PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  --hue:285; --hue3:345;
}
/* ---------- 色彩令牌：hex 回退（MD3 baseline） ---------- */
:root,html[data-theme=light]{
  --primary:#6750A4; --on-primary:#FFF; --primary-container:#EADDFF; --on-primary-container:#21005D;
  --secondary:#625B71; --on-secondary:#FFF; --secondary-container:#E8DEF8; --on-secondary-container:#1D192B;
  --tertiary:#7D5260; --tertiary-container:#FFD8E4; --on-tertiary-container:#31111D;
  --error:#B3261E; --on-error:#FFF; --error-container:#F9DEDC; --on-error-container:#410002;
  --surface:#FEF7FF; --on-surface:#1D1B20; --surface-variant:#E7E0EC; --on-surface-variant:#49454F;
  --surface-lowest:#FFF; --surface-low:#F7F2FA; --surface-container:#F3EDF7; --surface-high:#ECE6F0; --surface-highest:#E6E0E9;
  --outline:#79747E; --outline-variant:#CAC4D0;
  --inverse-surface:#322F35; --inverse-on-surface:#F5EFF7; --inverse-primary:#D0BCFF;
  color-scheme:light;
}
html[data-theme=dark]{
  --primary:#D0BCFF; --on-primary:#381E72; --primary-container:#4F378B; --on-primary-container:#EADDFF;
  --secondary:#CCC2DC; --on-secondary:#332D41; --secondary-container:#4A4458; --on-secondary-container:#E8DEF8;
  --tertiary:#EFB8C3; --tertiary-container:#633B48; --on-tertiary-container:#FFD8E4;
  --error:#F2B8B5; --on-error:#601410; --error-container:#8C1D18; --on-error-container:#FFDAD6;
  --surface:#141218; --on-surface:#E6E0E9; --surface-variant:#49454F; --on-surface-variant:#CAC4D0;
  --surface-lowest:#0F0D13; --surface-low:#1D1B20; --surface-container:#211F26; --surface-high:#2B2930; --surface-highest:#36343B;
  --outline:#938F99; --outline-variant:#49454F;
  --inverse-surface:#E6E0E9; --inverse-on-surface:#322F35; --inverse-primary:#6750A4;
  color-scheme:dark;
}
/* ---------- 色彩令牌：oklch 动态色调调色板（Material You） ----------
   tone T 的感知亮度 ≈ (T+16)/116，色相由 --hue 种子决定 */
@supports (color:oklch(50% .1 264)){
  :root,html[data-theme=light]{
    --primary:oklch(48.3% .14 var(--hue)); --on-primary:oklch(100% 0 var(--hue));
    --primary-container:oklch(91.4% .06 var(--hue)); --on-primary-container:oklch(22.4% .06 var(--hue));
    --secondary:oklch(48.3% .045 var(--hue)); --on-secondary:oklch(100% 0 var(--hue));
    --secondary-container:oklch(91.4% .04 var(--hue)); --on-secondary-container:oklch(22.4% .035 var(--hue));
    --tertiary:oklch(48.3% .10 var(--hue3)); --tertiary-container:oklch(91.4% .05 var(--hue3)); --on-tertiary-container:oklch(22.4% .05 var(--hue3));
    --surface:oklch(98.3% .008 var(--hue)); --on-surface:oklch(22.4% .02 var(--hue));
    --surface-variant:oklch(91.4% .022 var(--hue)); --on-surface-variant:oklch(39.7% .022 var(--hue));
    --surface-lowest:oklch(100% 0 var(--hue)); --surface-low:oklch(96.6% .008 var(--hue));
    --surface-container:oklch(94.8% .009 var(--hue)); --surface-high:oklch(93.1% .01 var(--hue)); --surface-highest:oklch(91.4% .012 var(--hue));
    --outline:oklch(56.9% .02 var(--hue)); --outline-variant:oklch(82.8% .016 var(--hue));
    --inverse-surface:oklch(31% .02 var(--hue)); --inverse-on-surface:oklch(95.7% .01 var(--hue)); --inverse-primary:oklch(82.8% .10 var(--hue));
  }
  html[data-theme=dark]{
    --primary:oklch(82.8% .10 var(--hue)); --on-primary:oklch(31% .08 var(--hue));
    --primary-container:oklch(39.7% .11 var(--hue)); --on-primary-container:oklch(91.4% .05 var(--hue));
    --secondary:oklch(82.8% .04 var(--hue)); --on-secondary:oklch(31% .04 var(--hue));
    --secondary-container:oklch(39.7% .04 var(--hue)); --on-secondary-container:oklch(91.4% .03 var(--hue));
    --tertiary:oklch(82.8% .08 var(--hue3)); --tertiary-container:oklch(39.7% .08 var(--hue3)); --on-tertiary-container:oklch(91.4% .04 var(--hue3));
    --surface:oklch(19% .01 var(--hue)); --on-surface:oklch(91.4% .015 var(--hue));
    --surface-variant:oklch(39.7% .022 var(--hue)); --on-surface-variant:oklch(82.8% .018 var(--hue));
    --surface-lowest:oklch(14% .01 var(--hue)); --surface-low:oklch(22.4% .012 var(--hue));
    --surface-container:oklch(24.1% .013 var(--hue)); --surface-high:oklch(28.4% .014 var(--hue)); --surface-highest:oklch(32.8% .015 var(--hue));
    --outline:oklch(65.5% .018 var(--hue)); --outline-variant:oklch(39.7% .016 var(--hue));
    --inverse-surface:oklch(91.4% .015 var(--hue)); --inverse-on-surface:oklch(31% .02 var(--hue)); --inverse-primary:oklch(48.3% .13 var(--hue));
  }
}
/* ---------- 基础与排版令牌 ---------- */
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
body{
  font-family:var(--font); background:var(--surface); color:var(--on-surface);
  -webkit-font-smoothing:antialiased; text-rendering:optimizeLegibility;
}
.t-headline-md{font-size:28px;line-height:36px;font-weight:400;letter-spacing:0;margin:0}
.t-headline-sm{font-size:24px;line-height:32px;font-weight:400;margin:0}
.t-title-lg{font-size:22px;line-height:28px;font-weight:500;margin:0}
.t-body-lg{font-size:16px;line-height:24px;font-weight:400;letter-spacing:.5px;margin:0}
.t-body-md{font-size:14px;line-height:20px;font-weight:400;letter-spacing:.25px;margin:0}
.t-body-sm{font-size:12px;line-height:16px;font-weight:400;letter-spacing:.4px;margin:0}
.t-label-lg{font-size:14px;line-height:20px;font-weight:500;letter-spacing:.1px}
.muted{color:var(--on-surface-variant)}
svg{display:block}
/* ---------- 涟漪与状态层 ---------- */
.md-ripple{position:relative;overflow:hidden;isolation:isolate}
.md-ripple::before{content:"";position:absolute;inset:0;background:currentColor;opacity:0;transition:opacity var(--dur-short) var(--ease-standard);pointer-events:none}
.md-ripple:hover::before{opacity:.08}
.md-ripple:focus-visible::before{opacity:.12}
.md-ripple:active::before{opacity:.12}
.ripple{position:absolute;border-radius:50%;background:currentColor;opacity:.18;transform:scale(0);animation:md-ripple 550ms var(--ease-standard) forwards;pointer-events:none}
@keyframes md-ripple{to{transform:scale(1);opacity:0}}
/* ---------- 顶栏 ---------- */
.topbar{
  position:sticky;top:0;z-index:5;height:64px;display:flex;align-items:center;justify-content:space-between;
  padding:0 16px; background:var(--surface); transition:box-shadow var(--dur-short) var(--ease-standard);
}
.brand{display:flex;align-items:center;gap:12px;color:var(--on-surface)}
.brand-icon{
  width:40px;height:40px;border-radius:var(--shape-full);background:var(--primary-container);
  color:var(--on-primary-container);display:grid;place-items:center;
}
.brand-icon svg{width:22px;height:22px}
.topbar-actions{display:flex;gap:4px}
.icon-btn{
  width:40px;height:40px;border:0;border-radius:var(--shape-full);background:transparent;
  color:var(--on-surface-variant);display:grid;place-items:center;cursor:pointer;text-decoration:none;
  transition:background var(--dur-short) var(--ease-standard);
}
.icon-btn svg{width:22px;height:22px}
html[data-theme=light] .icon-sun{display:none}
html[data-theme=dark] .icon-moon{display:none}
/* ---------- 主体布局 ---------- */
.hero{max-width:600px;margin:0 auto;padding:24px 20px 48px;display:flex;flex-direction:column;gap:24px}
.hero-head{display:flex;flex-direction:column;align-items:center;text-align:center;gap:8px;padding-top:16px}
.hero-badge{
  width:64px;height:64px;border-radius:var(--shape-lg);background:var(--primary-container);
  color:var(--on-primary-container);display:grid;place-items:center;margin-bottom:8px;
}
.hero-badge svg{width:36px;height:36px}
/* ---------- 卡片（elevated card） ---------- */
.card{
  background:var(--surface-low); border-radius:var(--shape-xl); padding:24px;
  box-shadow:var(--elev-1); display:flex;flex-direction:column;gap:20px;
}
/* ---------- Outlined text field ---------- */
form{display:flex;flex-direction:column;gap:16px;margin:0}
.field-wrap{display:flex;flex-direction:column;gap:4px}
.field{position:relative;height:56px}
.field input{
  width:100%;height:56px;padding:0 16px 0 48px;font:400 16px/24px var(--font);letter-spacing:.5px;
  color:var(--on-surface);background:transparent;border:1px solid var(--outline);
  border-radius:var(--shape-xs);outline:none;caret-color:var(--primary);
  transition:border-color var(--dur-short) var(--ease-standard),box-shadow var(--dur-short) var(--ease-standard);
}
.field input:hover{border-color:var(--on-surface)}
.field input:focus{border-color:var(--primary);box-shadow:inset 0 0 0 1px var(--primary)}
.field label{
  position:absolute;left:48px;top:16px;padding:0 4px;color:var(--on-surface-variant);
  font:400 16px/24px var(--font);letter-spacing:.5px;pointer-events:none;background:transparent;
  transition:all var(--dur-short) var(--ease-standard);
}
.field input:focus+label,
.field input:not(:placeholder-shown)+label{
  top:-9px;left:44px;font-size:12px;line-height:16px;background:var(--surface-low);color:var(--primary);
}
.field input:not(:focus):not(:placeholder-shown)+label{color:var(--on-surface-variant)}
.field-icon{position:absolute;left:12px;top:16px;width:24px;height:24px;color:var(--on-surface-variant);pointer-events:none}
.support{margin:0 0 0 16px;color:var(--on-surface-variant)}
/* ---------- Assist chips ---------- */
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{
  height:32px;display:inline-flex;align-items:center;gap:8px;padding:0 16px 0 12px;
  border:1px solid var(--outline-variant);border-radius:var(--shape-sm);background:transparent;
  color:var(--on-surface-variant);cursor:pointer;
}
.chip svg{width:18px;height:18px}
.chip .t-label-lg{font-size:13px;line-height:18px}
/* ---------- 按钮 ---------- */
.actions{display:flex;justify-content:flex-end;align-items:center;gap:8px}
.filled-btn{
  height:40px;display:inline-flex;align-items:center;gap:8px;padding:0 24px;border:0;cursor:pointer;
  border-radius:var(--shape-full);background:var(--primary);color:var(--on-primary);
  box-shadow:none;transition:box-shadow var(--dur-short) var(--ease-standard),transform var(--dur-short) var(--ease-standard);
}
.filled-btn:hover{box-shadow:var(--elev-1)}
.filled-btn:active{transform:scale(.98)}
.filled-btn svg{width:18px;height:18px}
.tonal-btn{
  height:40px;display:inline-flex;align-items:center;gap:8px;padding:0 24px;border:0;cursor:pointer;text-decoration:none;
  border-radius:var(--shape-full);background:var(--secondary-container);color:var(--on-secondary-container);
  transition:box-shadow var(--dur-short) var(--ease-standard);
}
.tonal-btn:hover{box-shadow:var(--elev-1)}
.text-btn{
  height:40px;display:inline-flex;align-items:center;padding:0 12px;border:0;cursor:pointer;text-decoration:none;
  border-radius:var(--shape-full);background:transparent;color:var(--primary);
}
/* ---------- 种子色（Material You 动态色） ---------- */
.hues{display:flex;align-items:center;justify-content:center;gap:12px}
.hue-row{display:flex;gap:10px}
.hue-dot{
  width:26px;height:26px;border-radius:var(--shape-full);border:0;cursor:pointer;
  background:oklch(48.3% .14 var(--h)); box-shadow:inset 0 0 0 1px rgba(0,0,0,.08);
  transition:transform var(--dur-short) var(--ease-decel),box-shadow var(--dur-short) var(--ease-standard);
}
@supports (color:oklch(50% .1 264)){ html[data-theme=dark] .hue-dot{background:oklch(72% .09 var(--h))} }
@supports not (color:oklch(50% .1 264)){ .hue-dot{background:var(--primary)} }
.hue-dot:hover{transform:scale(1.12)}
.hue-dot[aria-checked=true]{box-shadow:inset 0 0 0 2px var(--surface),inset 0 0 0 4px var(--on-surface);transform:scale(1.08)}
/* ---------- Snackbar ---------- */
.snack{
  position:fixed;left:16px;bottom:16px;z-index:40;max-width:min(560px,calc(100vw - 32px));
  background:var(--inverse-surface);color:var(--inverse-on-surface);border-radius:var(--shape-xs);
  padding:14px 16px;font:400 14px/20px var(--font);letter-spacing:.25px;box-shadow:var(--elev-3);
  transform:translateY(calc(100% + 24px));opacity:0;
  transition:transform var(--dur-med) var(--ease-decel),opacity var(--dur-med) var(--ease-decel);
}
.snack.show{transform:translateY(0);opacity:1}
/* ---------- 加载遮罩 + circular progress ---------- */
.busy{position:fixed;inset:0;z-index:50;display:grid;place-items:center;visibility:hidden;opacity:0;transition:opacity var(--dur-short) var(--ease-standard)}
.busy.show{visibility:visible;opacity:1}
.busy .scrim{position:absolute;inset:0;background:rgba(0,0,0,.32)}
.progress{width:48px;height:48px;position:relative;animation:md-rot 2s linear infinite}
.progress circle{fill:none;stroke-width:4;stroke-linecap:round}
.progress .track{stroke:rgba(255,255,255,.28)}
.progress .arc{stroke:var(--inverse-primary);stroke-dasharray:1 125.6;stroke-dashoffset:0;animation:md-dash 1.6s var(--ease-standard) infinite}
@keyframes md-rot{to{transform:rotate(360deg)}}
@keyframes md-dash{
  0%{stroke-dasharray:1 125.6;stroke-dashoffset:0}
  50%{stroke-dasharray:80 125.6;stroke-dashoffset:-22}
  100%{stroke-dasharray:1 125.6;stroke-dashoffset:-125.6}
}
/* ---------- 入场动效 ---------- */
.enter{opacity:0;transform:translateY(16px);animation:md-enter var(--dur-long) var(--ease-decel) forwards}
.d1{animation-delay:80ms}.d2{animation-delay:160ms}
@keyframes md-enter{to{opacity:1;transform:none}}
/* ---------- 错误页 ---------- */
.err-wrap{min-height:100vh;display:grid;place-items:center;padding:24px}
.dialog{max-width:560px;width:100%;align-items:flex-start;gap:16px}
.err-icon{width:48px;height:48px;border-radius:var(--shape-full);background:var(--error-container);color:var(--on-error-container);display:grid;place-items:center}
.err-icon svg{width:26px;height:26px}
.footer{ text-align:center;padding-top:4px }
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.01ms !important;animation-iteration-count:1 !important;transition-duration:.01ms !important}
  .enter{opacity:1;transform:none}
}
@media (max-width:480px){
  .hero{padding:16px 12px 40px}
  .card{padding:20px 16px;border-radius:var(--shape-lg)}
  .actions{flex-direction:column-reverse;align-items:stretch}
  .filled-btn,.tonal-btn{justify-content:center}
  .text-btn{justify-content:center}
}
`;

// ---- 主题初始化（置于 <head>，避免闪烁） ----
const MD3_THEME_EARLY = `(function(){
try{
  var root=document.documentElement;
  var saved=null;
  try{saved=localStorage.getItem('pe-theme');}catch(e){}
  var dark=saved?saved==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;
  root.setAttribute('data-theme',dark?'dark':'light');
  var h=null;
  try{h=localStorage.getItem('pe-hue');}catch(e){}
  if(h){root.style.setProperty('--hue',h);root.style.setProperty('--hue3',String((parseFloat(h)+60)%360));}
}catch(e){}
})();`;

// ---- 交互：主题切换 / 涟漪 / snackbar / 加载态 / 种子色 ----
const MD3_JS = `(function(){
function $(id){return document.getElementById(id);}
/* 主题切换 */
var themeBtn=$('themeBtn');
if(themeBtn)themeBtn.addEventListener('click',function(){
  var root=document.documentElement;
  var next=root.getAttribute('data-theme')==='dark'?'light':'dark';
  root.setAttribute('data-theme',next);
  try{localStorage.setItem('pe-theme',next);}catch(e){}
});
/* 系统主题跟随（未手动选择时） */
try{
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change',function(e){
    var saved=null;try{saved=localStorage.getItem('pe-theme');}catch(_){}
    if(!saved)document.documentElement.setAttribute('data-theme',e.matches?'dark':'light');
  });
}catch(e){}
/* 涟漪 */
document.addEventListener('pointerdown',function(e){
  var el=e.target.closest?e.target.closest('.md-ripple'):null;
  if(!el)return;
  var r=el.getBoundingClientRect();
  var d=Math.max(r.width,r.height)*2.2;
  var s=document.createElement('span');
  s.className='ripple';
  s.style.width=s.style.height=d+'px';
  s.style.left=(e.clientX-r.left-d/2)+'px';
  s.style.top=(e.clientY-r.top-d/2)+'px';
  el.appendChild(s);
  setTimeout(function(){s.remove();},650);
});
/* Snackbar */
var snackT=null;
window.__peSnack=function(msg){
  var el=$('snack');if(!el)return;
  el.textContent=msg;el.classList.add('show');
  clearTimeout(snackT);
  snackT=setTimeout(function(){el.classList.remove('show');},4000);
};
/* 加载态 */
window.__peBusy=function(on){
  var el=$('busy');if(el)el.classList.toggle('show',!!on);
};
/* 种子色（Material You 动态色） */
var HUES=[285,250,200,155,35,330];
var row=$('hueRow');
if(row){
  var cur=getComputedStyle(document.documentElement).getPropertyValue('--hue').trim()||'285';
  HUES.forEach(function(h){
    var b=document.createElement('button');
    b.type='button';b.className='hue-dot';b.style.setProperty('--h',h);
    b.setAttribute('role','radio');
    b.setAttribute('aria-checked',String(Math.abs(parseFloat(cur)-h)<1));
    b.setAttribute('aria-label','主题色 '+h);
    b.addEventListener('click',function(){
      var root=document.documentElement;
      root.style.setProperty('--hue',String(h));
      root.style.setProperty('--hue3',String((h+60)%360));
      try{localStorage.setItem('pe-hue',String(h));}catch(e){}
      row.querySelectorAll('.hue-dot').forEach(function(x){x.setAttribute('aria-checked','false');});
      b.setAttribute('aria-checked','true');
    });
    row.appendChild(b);
  });
}
})();`;

// ---- 页面骨架公共部分 ----
function md3Head(title, desc) {
	return `<!DOCTYPE html>
<html lang="zh-CN" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<meta name="description" content="${escapeHtml(desc)}">
<meta name="robots" content="noindex,nofollow">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌐</text></svg>">
<script>${MD3_THEME_EARLY}</script>
<style>${MD3_CSS}</style>
</head>`;
}

function md3Topbar() {
	return `<header class="topbar">
  <div class="brand">
    <span class="brand-icon">${ICON.globe}</span>
    <span class="t-title-lg">ProxyEverything</span>
  </div>
  <div class="topbar-actions">
    <a class="icon-btn md-ripple" href="https://github.com/lingyicute/ProxyEverything" target="_blank" rel="noopener" aria-label="GitHub 仓库">${ICON.github}</a>
    <button class="icon-btn md-ripple" type="button" id="themeBtn" aria-label="切换深浅色主题">
      <span class="icon-moon">${ICON.moon}</span><span class="icon-sun">${ICON.sun}</span>
    </button>
  </div>
</header>`;
}

function md3Overlays() {
	return `<div id="snack" class="snack" role="status" aria-live="polite"></div>
<div id="busy" class="busy" aria-hidden="true">
  <div class="scrim"></div>
  <svg class="progress" viewBox="0 0 48 48" aria-label="加载中">
    <circle class="track" cx="24" cy="24" r="20"></circle>
    <circle class="arc" cx="24" cy="24" r="20"></circle>
  </svg>
</div>`;
}

// ---- 首页 ----
function getRootHtml() {
	return md3Head('Proxy Everything', 'Proxy Everything — 基于 Cloudflare Workers 的实验性网页代理') + `
<body>
${md3Topbar()}
<main class="hero">
  <div class="hero-head enter">
    <div class="hero-badge">${ICON.globe}</div>
    <h1 class="t-headline-md">Proxy Everything</h1>
    <p class="t-body-lg muted">实验性通用网页反向代理 · 基于 Cloudflare Workers</p>
  </div>

  <section class="card enter d1" aria-label="输入目标地址">
    <form id="urlForm" novalidate>
      <div class="field-wrap">
        <div class="field">
          <span class="field-icon">${ICON.link}</span>
          <input id="targetUrl" type="text" placeholder=" " autocomplete="off" autocapitalize="off"
            spellcheck="false" enterkeyhint="go">
          <label for="targetUrl">目标地址</label>
        </div>
        <p class="t-body-sm support">可省略协议头（默认 https）；路径与查询串原样保留</p>
      </div>

      <div class="chips" aria-label="示例站点">
        <button type="button" class="chip md-ripple" data-url="https://92li.uk">${ICON.link}<span class="t-label-lg">梨's Home</span></button>
        <button type="button" class="chip md-ripple" data-url="https://news.ycombinator.com">${ICON.link}<span class="t-label-lg">Hacker News</span></button>
        <button type="button" class="chip md-ripple" data-url="https://en.wikipedia.org/wiki/Main_Page">${ICON.link}<span class="t-label-lg">Wikipedia</span></button>
        <button type="button" class="chip md-ripple" data-url="https://zh.wikipedia.org/wiki/Wikipedia:%E9%A6%96%E9%A1%B5">${ICON.link}<span class="t-label-lg">中文 Wikipedia</span></button>
      </div>

      <div class="actions">
        <button type="button" class="text-btn md-ripple" id="clearBtn"><span class="t-label-lg">清空</span></button>
        <button type="submit" class="filled-btn md-ripple" id="goBtn">${ICON.arrow}<span class="t-label-lg">进入代理</span></button>
      </div>
    </form>
  </section>

  <div class="hues enter d2">
    <span class="t-body-sm muted">主题色</span>
    <div class="hue-row" id="hueRow" role="radiogroup" aria-label="主题色"></div>
  </div>

  <p class="t-body-sm muted footer enter d2">仅供学习与个人研究使用 · 请勿用于违反目标网站服务条款的用途</p>
</main>
${md3Overlays()}
<script>${MD3_JS}
(function(){
  var input=document.getElementById('targetUrl');
  var form=document.getElementById('urlForm');
  document.querySelectorAll('.chip').forEach(function(c){
    c.addEventListener('click',function(){
      input.value=c.getAttribute('data-url');
      input.focus();
    });
  });
  document.getElementById('clearBtn').addEventListener('click',function(){
    input.value='';input.focus();
  });
  form.addEventListener('submit',function(e){
    e.preventDefault();
    var v=input.value.trim();
    if(!/^(https?:\\/\\/)/i.test(v))v='https://'+v.replace(/^\\/+/,'');
    var u=null;
    try{u=new URL(v);}catch(_){}
    if(!u||!u.hostname||u.hostname.indexOf('.')<0&&u.hostname!=='localhost'){
      window.__peSnack('请输入有效的网址，例如 example.com');
      input.focus();
      return;
    }
    window.__peBusy(true);
    setTimeout(function(){
      location.href='/'+encodeURIComponent(u.protocol+'//'+u.host+u.pathname)+u.search+u.hash;
    },260);
  });
})();
</script>
</body>
</html>`;
}

// ---- 错误页 ----
function renderErrorPage(title, message) {
	return md3Head(title + ' · ProxyEverything', 'ProxyEverything 错误提示') + `
<body>
<div class="err-wrap">
  <section class="card dialog enter" role="alertdialog" aria-labelledby="errTitle">
    <div class="err-icon">${ICON.warn}</div>
    <h1 class="t-headline-sm" id="errTitle">${escapeHtml(title)}</h1>
    <p class="t-body-md muted">${message}</p>
    <div class="actions">
      <button class="text-btn md-ripple" type="button" onclick="location.reload()"><span class="t-label-lg">重试</span></button>
      <a class="tonal-btn md-ripple" href="/"><span class="t-label-lg">返回首页</span></a>
    </div>
  </section>
</div>
<script>${MD3_JS}</script>
</body>
</html>`;
}
