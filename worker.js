/**
 * ProxyEverything — 通用网页反向代理 Cloudflare Worker
 *
 * URL 方案：
 *   https://worker.example/~<encodeURIComponent(协议 + '//' + 主机)>/路径?目标查询串
 *   '~' 版本只编码来源，保留 URL 已规范化的路径和查询串，可供浏览器原生相对解析。
 *   例：https://example.com/page?a=1
 *     → https://worker.example/~https%3A%2F%2Fexample.com/page?a=1
 *   不含 ~ 的逐段编码和旧版整址编码链接仍可解析。
 *
 * 架构：单文件、ES Module 语法，无外部依赖，可直接粘贴到 Cloudflare Dashboard，
 * 或 `wrangler deploy` 部署。
 */

// ============================================================
// 常量与工具函数
// ============================================================

const HOP_BY_HOP = new Set([
	'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
	'proxy-connection', // 非标准旧代理连接控制头，同样不能跨越当前连接
	'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

// 这些响应头会破坏代理后的显示效果，全部剥掉
const STRIP_RESPONSE_HEADERS = [
	'content-security-policy',
	'content-security-policy-report-only',
	'x-frame-options',
	'cross-origin-opener-policy',
	'cross-origin-embedder-policy',
	'cross-origin-resource-policy',
	'link',               // preload/preconnect 指向原站，无意义
	'alt-svc',
	'report-to',
	'nel',
	'permissions-policy',
	'feature-policy',     // Permissions-Policy 的旧名，同样按原站来源声明
	'integrity-policy',   // 要求脚本带 SRI；代理已移除改写后失效的 integrity，保留会拦截全部脚本
	'integrity-policy-report-only',
	'timing-allow-origin',
	'content-location',
	'refresh',            // 由 stripResponseHeaders 改写目标后重新写入
	'expect-ct',
	'server',
	'strict-transport-security',
	'clear-site-data',    // 上游不能清空整个代理域的 Cookie/存储/缓存
	'service-worker-allowed', // 上游不能扩大代理域上的 Service Worker 作用域
	'speculation-rules',  // 预取/预渲染规则头指向原站路径，剥除以防绕过代理
	'www-authenticate',   // 原生 HTTP 认证会把不同目标折叠进代理域同一个保护空间
	'authentication-info',
	'referrer-policy',    // 防止上游策略剥除同源代理路径导致回源 Referer 丢失目标地址
	'reporting-endpoints',
	// 以下作用于整个代理源并被浏览器持久化，会串到其它目标站点
	'accept-ch',          // Client Hints 偏好按源保存，其它目标也会收到高熵 UA 提示
	'critical-ch',        // 配合 Accept-CH 触发导航重试
	'origin-agent-cluster', // 首个目标的选择会锁定整个代理源的 agent cluster 键
	'set-login',          // FedCM 登录状态记在代理源上
];

// 仅正文变换时移除；透传响应必须保留其表示元数据。
const REPRESENTATION_HEADERS = [
	'content-length', 'etag', 'last-modified',
	'content-md5', 'digest', 'content-digest', 'repr-digest',
	'content-range', 'accept-ranges',
];
const MAX_TRANSFORM_BYTES = 2 * 1024 * 1024;
const MAX_REWRITE_GROWTH = 2 * MAX_TRANSFORM_BYTES;
const REWRITE_LIMIT = Symbol('rewrite-limit');

/** 多个短引用可能继承同一条很长的基路径。限制每次改写的累计增长，超限时交回完整原文。 */
function capRewriteGrowth(transform) {
	return (source, ...args) => {
		let remaining = MAX_REWRITE_GROWTH;
		const account = (beforeLength, after) => {
			remaining -= Math.max(0, after.length - beforeLength);
			if (remaining < 0) throw REWRITE_LIMIT;
			return after;
		};
		try { return transform(account, source, ...args); }
		catch (error) {
			if (error === REWRITE_LIMIT) return source;
			throw error;
		}
	};
}

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

// 禁止 Connection 头夹带并借机剥除端到端关键语义头（RFC 9110 §7.6.1）
const PROTECTED_END_TO_END = new Set([
	'content-type', 'content-length', 'content-encoding', 'content-range', 'content-language',
	'set-cookie', 'cookie', 'location', 'refresh', 'cache-control', 'vary',
	'host', 'origin', 'referer', 'authorization', 'range',
	'if-none-match', 'if-modified-since', 'if-match', 'if-unmodified-since', 'if-range',
	'etag', 'last-modified', 'accept-ranges', 'content-disposition',
	'accept', 'accept-encoding', 'accept-language', 'user-agent',
	'allow', 'retry-after', 'age', 'expires', 'date', 'pragma',
	'x-robots-tag', 'service-worker', 'sec-fetch-dest', 'sec-fetch-mode',
	'sec-fetch-site', 'sec-fetch-user', 'sec-websocket-protocol', 'sec-websocket-key',
	'sec-websocket-version', 'sec-websocket-extensions', 'sec-websocket-accept',
	'access-control-allow-origin', 'access-control-allow-credentials',
	'access-control-allow-methods', 'access-control-allow-headers',
	'access-control-expose-headers', 'access-control-request-method',
	'access-control-request-headers', 'access-control-max-age',
]);

/** Connection 可以声明额外的逐跳头，不能只删除固定列表。 */
function stripHopByHop(headers) {
	const connection = headers.get('connection') || '';
	for (const name of connection.split(',')) {
		const token = name.trim().toLowerCase();
		if (/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(token) && !PROTECTED_END_TO_END.has(token)) {
			headers.delete(token);
		}
	}
	for (const name of HOP_BY_HOP) headers.delete(name);
}

/**
 * 剥除破坏代理的响应头。Refresh 与 meta refresh 同语义，只丢弃会让依赖它跳转的页面停在原地，
 * 原样保留又会跳出代理，因此按目标地址改写后写回。
 */
function stripResponseHeaders(headers, request, baseUrl) {
	const refresh = headers.get('refresh');
	for (const h of STRIP_RESPONSE_HEADERS) headers.delete(h);
	if (!request || !baseUrl) return;
	const origin = new URL(request.url).origin;
	if (refresh) headers.set('Refresh', rewriteRefreshContent(refresh, baseUrl, origin));
	// Location 也用于 201 等非重定向响应；调用方应看到代理资源地址。
	const location = headers.get('Location');
	if (location) {
		try {
			const target = new URL(location, baseUrl);
			// mailto:、应用深链等交给浏览器的外部协议处理，与 meta refresh 和链接一致；
			// 浏览器本身拒绝跟随指向 javascript:、data: 等的重定向。
			if (['http:', 'https:'].includes(target.protocol)) {
				headers.set('Location', rewriteUrl(target.href, baseUrl, origin));
			}
		} catch { headers.delete('Location'); }
	}
}

function stripTransformedHeaders(headers) {
	headers.delete('Content-Encoding');
	for (const name of REPRESENTATION_HEADERS) headers.delete(name);
}

// 常见懒加载 data-* 属性（按需扩充）
const LAZY_ATTRS = new Set([
	'data-src', 'data-srcset', 'data-original', 'data-original-src',
	'data-original-set', 'data-lazy-src', 'data-lazy-srcset', 'data-lazy',
	'data-bg', 'data-bg-src', 'data-background', 'data-background-image',
	'data-url', 'data-href', 'data-link', 'data-uri', 'data-image',
	'data-image-src', 'data-img', 'data-thumb', 'data-thumbnail',
	'data-poster', 'data-video', 'data-video-src', 'data-audio',
	'data-audio-src', 'data-iframe', 'data-iframe-src', 'data-src-small',
	'data-src-medium', 'data-src-large', 'data-fallback-src', 'data-high-res-src',
	'data-low-res-src',
]);

/**
 * 是否对被代理的目标网页添加 X-Robots-Tag: noindex, nofollow
 * - true（推荐）：仅工具自身首页被搜索引擎收录，代理的外部网页不被收录，
 *   防止搜索引擎爬虫抓取全网导致 Worker 额度耗尽以及域名被判定为镜像站/垃圾站。
 * - false：完全取消被代理网页的 noindex 头。
 */
const ENABLE_PROXY_NOINDEX = true;

/** 安全 decodeURIComponent：源串含散落裸 % 时先补齐为 %25 再尝试解码 */
function safeDecode(s) {
	try {
		return decodeURIComponent(s);
	} catch {
		try {
			return decodeURIComponent(String(s).replace(/%(?![0-9a-f]{2})/gi, '%25'));
		} catch {
			return s;
		}
	}
}

// WHATWG URL 只忽略边缘的 C0 控制字符和 ASCII 空格；其它空白可能是路径的一部分。
function trimUrlSpace(value) {
	let start = 0, end = value.length;
	while (start < end && value.charCodeAt(start) <= 0x20) start++;
	while (end > start && value.charCodeAt(end - 1) <= 0x20) end--;
	return value.slice(start, end);
}

function urlSuffix(u) {
	// URL.search / .hash 会吞掉空的 ? / #；直接从已序列化的地址保留这些分隔符。
	const href = u.href;
	const index = href.search(/[?#]/);
	return index < 0 ? '' : href.slice(index);
}

function encodeProxyPath(u, protocol = u.protocol) {
	return `/~${encodeURIComponent(protocol + '//' + u.host)}${u.pathname}${urlSuffix(u)}`;
}

function toProxyUrl(targetUrl, workerOrigin) {
	const u = new URL(targetUrl);
	if (!['http:', 'https:', 'ws:', 'wss:'].includes(u.protocol)) return targetUrl;
	const host = normalizeHostname(u.hostname);
	if (host) u.hostname = host;
	return workerOrigin + encodeProxyPath(u);
}

function isProxiedPath(pathname) {
	return /^\/(?:~(?:https?|wss?)%3a%2f%2f|(?:https?|wss?)(?:%3a|:)(?:%2f|\/){2})/i.test(pathname);
}

function decodeProxyPath(pathname) {
	const raw = pathname.replace(/^\/+/, '');
	if (!raw.startsWith('~')) return safeDecode(raw);
	const cut = raw.indexOf('/');
	const origin = safeDecode(raw.slice(1, cut === -1 ? raw.length : cut));
	if (!/^(?:https?|wss?):\/\/[^\\/?#\s]+$/i.test(origin)) return '';
	return origin + (cut === -1 ? '/' : raw.slice(cut));
}

// 这些纯函数也供无依赖的浏览器脚本使用，避免引入不同的编解码规则。
function browserPathHelpers() {
	return [safeDecode, trimUrlSpace, urlSuffix, encodeProxyPath, isProxiedPath, decodeProxyPath].map(fn => fn.toString()).join('\n');
}

/** 判断 URL 是否指向代理 Worker 自身主机与端口（忽略协议差异与尾点） */
function isWorkerHost(u, workerOrigin) {
	if (!u || !workerOrigin) return false;
	try {
		const w = new URL(workerOrigin);
		return Boolean(w.hostname) &&
			normalizeHostname(u.hostname) === normalizeHostname(w.hostname) &&
			u.port === w.port;
	} catch {
		return false;
	}
}

/** 已代理 URL 中的 .. 不能越过 /~来源 段逃逸成其它目标主机。 */
function normalizeProxiedUrl(raw, workerOrigin, keepOrigin, parsed = null) {
	const u = parsed || new URL(raw, workerOrigin);
	const prefix = keepOrigin
		? (u.protocol === 'ws:' || u.protocol === 'wss:' ? `${u.protocol}//${new URL(workerOrigin).host}` : workerOrigin)
		: '';
	const cut = raw.search(/[?#]/);
	const rawPath = (cut < 0 ? raw : raw.slice(0, cut))
		.replace(/^(?:[a-z][a-z0-9+.-]*:[\/\\]*|[\/\\]{2,})[^\/\\?#]*/i, '')
		.replace(/\\/g, '/');
	if (!/\/(?:\.|%2e){2}(?:\/|$)/i.test(rawPath) && isProxiedPath(u.pathname)) {
		return `${prefix}${u.pathname}${urlSuffix(u)}`;
	}
	const suffix = cut < 0 ? '' : raw.slice(cut);
	const decoded = decodeProxyPath(rawPath);
	if (!decoded) return `${prefix}${u.pathname}${urlSuffix(u)}`;
	const hashCut = suffix.indexOf('#');
	const query = hashCut < 0 ? suffix : suffix.slice(0, hashCut);
	const hash = hashCut < 0 ? '' : suffix.slice(hashCut);
	const baseTarget = decoded.split('#', 1)[0];
	const target = new URL(baseTarget + (query ? (baseTarget.includes('?') ? '&' : '?') + query.slice(1) : '') + hash);
	const host = normalizeHostname(target.hostname);
	if (host) target.hostname = host;
	return prefix + encodeProxyPath(target);
}

function rewriteUrl(value, baseUrl, workerOrigin, resolveEmptyOrFragment = false) {
	if (value == null) return value;
	const v = trimUrlSpace(String(value));
	// 资源中的页内锚点保持原样；需要完整 URL 的标识符或作用域例外。
	if (!resolveEmptyOrFragment && (!v || v.startsWith('#'))) return v;
	// 已经是本站代理 URL：经 URL 规范化以编码裸 <、> 等字符，避免透传进内联 raw-text
	if (isProxiedPath(v)) {
		try { return normalizeProxiedUrl(v, workerOrigin, false); } catch { return v; }
	}
	if (v.startsWith(workerOrigin + '/') && isProxiedPath(v.slice(workerOrigin.length))) {
		try { return normalizeProxiedUrl(v, workerOrigin, true); } catch { return v; }
	}
	try {
		const abs = new URL(v, baseUrl);
		if (abs.protocol !== 'http:' && abs.protocol !== 'https:' &&
			abs.protocol !== 'ws:' && abs.protocol !== 'wss:') {
			return v;
		}
		if (isWorkerHost(abs, workerOrigin)) {
			const hasOrigin = /^(?:[a-z][a-z0-9+.-]*:[\/\\]*|[\/\\]{2,})/i.test(v);
			const rawSelfPath = hasOrigin
				? v.replace(/^(?:[a-z][a-z0-9+.-]*:[\/\\]*|[\/\\]{2,})[^\/\\?#]*/i, '').replace(/\\/g, '/')
				: '';
			// 已代理（同源主机且路径是编码后的目标 URL）
			if (isProxiedPath(abs.pathname) || isProxiedPath(rawSelfPath)) {
				return hasOrigin ? normalizeProxiedUrl(v, workerOrigin, true, abs) : abs.pathname + urlSuffix(abs);
			}
			// 落到代理域自身的非代理路径：回退按目标基地址解析，避免触发自代理拦截
			const rebound = new URL(new URL(baseUrl).origin + abs.pathname + urlSuffix(abs));
			if (abs.protocol === 'ws:' || abs.protocol === 'wss:') {
				rebound.protocol = rebound.protocol === 'http:' ? 'ws:' : 'wss:';
			}
			return toProxyUrl(rebound.href, workerOrigin);
		}
		return toProxyUrl(abs.href, workerOrigin);
	} catch {
		return v;
	}
}

function isSrcsetSpace(ch) {
	return ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\f';
}

/**
 * 重写 srcset："url 1x, url 2x" / "url 320w, ..." / "url1,url2"
 *
 * ⚠️ 不能简单地按 "," 切分：URL 内部允许出现逗号，最典型的就是
 * 懒加载占位图 `data:image/gif;base64,R0lGODlhAQAB...`。粗暴切分会把
 * base64 载荷切成两半，后半段被当成相对路径改写成代理地址，占位图直接碎图。
 *
 * 这里按 HTML 规范「Parsing a srcset attribute」逐段扫描，只重写 URL 部分，
 * 描述符与空白原样保留：
 *   https://html.spec.whatwg.org/multipage/images.html#parse-a-srcset-attribute
 *   1. 跳过空白与逗号（候选项之间的分隔符）；
 *   2. 取一段「非空白」字符作为 URL，逗号可以出现在其中；
 *   3. 若这一段以逗号结尾，则末尾的逗号是分隔符，不属于 URL，
 *      该候选项到此结束（没有描述符）；
 *   4. 否则其后跟随描述符，直到「括号外的」逗号或字符串结束。
 */
function mapSrcset(s, rewrite) {
	const n = s.length;
	let out = '';
	let i = 0;
	while (i < n) {
		// 1. 分隔符：空白与逗号，原样输出
		const sepStart = i;
		while (i < n && (isSrcsetSpace(s[i]) || s[i] === ',')) i++;
		out += s.slice(sepStart, i);
		if (i >= n) break;

		// 2/3. URL 段
		const urlStart = i;
		while (i < n && !isSrcsetSpace(s[i])) i++;
		let end = i;
		while (end > urlStart && s[end - 1] === ',') end--;
		out += rewrite(s.slice(urlStart, end)) + s.slice(end, i);
		if (end < i) continue; // 该候选项没有描述符，直接进入下一轮

		// 4. 描述符段（括号内的逗号不算分隔符，兼容未来的描述符语法）
		const descStart = i;
		let depth = 0;
		while (i < n) {
			const ch = s[i];
			if (ch === '(') depth++;
			else if (ch === ')') { if (depth > 0) depth--; }
			else if (ch === ',' && depth === 0) break;
			i++;
		}
		out += s.slice(descStart, i);
	}
	return out;
}

const rewriteSrcset = capRewriteGrowth((account, value, baseUrl, workerOrigin) => {
	return mapSrcset(String(value), url => account(url.length, rewriteUrl(url, baseUrl, workerOrigin)));
});

// HTML 的空白分隔 URL 列表只把 ASCII 空白当作分隔符，保留原来的分隔字节。
function mapPingUrls(value, rewrite) {
	return value.replace(/[^ \t\r\n\f]+/g, url => rewrite(url));
}

const rewritePing = capRewriteGrowth((account, value, baseUrl, workerOrigin) =>
	mapPingUrls(value, url => account(url.length, rewriteUrl(url, baseUrl, workerOrigin))));

/** CSS 字符串不能直接沿用源引号：解析相对地址后可能从基地址继承 ' 或括号，并转义 <、> 防逸出。 */
function quoteCssString(value) {
	return '"' + String(value).replace(/["\\<>\x00-\x1f\x7f]/g, ch =>
		ch === '"' || ch === '\\' ? '\\' + ch : '\\' + ch.charCodeAt(0).toString(16) + ' ') + '"';
}

/** CSS 规范：反斜杠后紧跟换行或 EOF 不是有效标识符转义（仅字符串内为续行）。 */
function isValidCssEscape(css, index) {
	return css[index] === '\\' && index + 1 < css.length && !/[\n\r\f]/.test(css[index + 1]);
}

/** CSS escape 的终点；最多读取 6 位十六进制数字和一个空白。 */
function cssEscapeEnd(css, start) {
	let i = start + 1;
	if (/[0-9a-f]/i.test(css[i] || '')) {
		const limit = Math.min(i + 6, css.length);
		while (i < limit && /[0-9a-f]/i.test(css[i])) i++;
		if (css[i] === '\r' && css[i + 1] === '\n') return i + 2;
		return isSrcsetSpace(css[i]) ? i + 1 : i;
	}
	return css[i] === '\r' && css[i + 1] === '\n' ? i + 2 : Math.min(i + 1, css.length);
}

function decodeCssEscapes(value) {
	return value.replace(/\\(?:\r\n|[\n\r\f]|[0-9a-f]{1,6}(?:\r\n|[ \t\n\r\f])?|[^\n\r\f])/gi, escape => {
		const tail = escape.slice(1);
		if (/^[\n\r\f]/.test(tail)) return '';
		if (!/^[0-9a-f]/i.test(tail)) return tail;
		const code = parseInt(tail, 16);
		return String.fromCodePoint(!code || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff) ? 0xfffd : code);
	});
}

function readCssString(css, start) {
	const quote = css[start];
	let i = start + 1;
	while (i < css.length) {
		if (css[i] === quote) return { end: i + 1, value: decodeCssEscapes(css.slice(start + 1, i)) };
		if (/[\n\r\f]/.test(css[i])) return { end: i, value: null }; // bad-string-token
		if (css[i] === '\\') i = cssEscapeEnd(css, i);
		else i++;
	}
	// EOF 也结束字符串 token（CSS Syntax §4.3.5）；末尾落单的反斜杠不计入内容。
	let end = css.length;
	let slashes = 0;
	while (end - slashes - 1 > start && css[end - slashes - 1] === '\\') slashes++;
	if (slashes % 2) end--;
	return { end: css.length, value: decodeCssEscapes(css.slice(start + 1, end)) };
}

function skipCssSpace(css, start, comments = false) {
	let i = start;
	while (i < css.length) {
		if (isSrcsetSpace(css[i])) { i++; continue; }
		if (comments && css.startsWith('/*', i)) {
			const end = css.indexOf('*/', i + 2);
			i = end < 0 ? css.length : end + 2;
			continue;
		}
		break;
	}
	return i;
}

/** url( 的内容；无效 token 也一次跳过，禁止从每个字符重新回溯。 */
function readCssUrl(css, start) {
	let i = skipCssSpace(css, start);
	if (css[i] === '"' || css[i] === "'") {
		const str = readCssString(css, i);
		i = skipCssSpace(css, str.end, true);
		// EOF 同样闭合函数块：浏览器照常加载 url("a.png 与 url("a.png" 中的地址。
		if (str.value !== null && (i >= css.length || css[i] === ')')) return { end: Math.min(i + 1, css.length), value: str.value };
		let depth = 1;
		while (i < css.length && depth > 0) {
			if (css[i] === '"' || css[i] === "'") { i = readCssString(css, i).end; continue; }
			if (css.startsWith('/*', i)) { i = skipCssSpace(css, i, true); continue; }
			if (css[i] === '(') { depth++; i++; continue; }
			if (css[i] === ')') { depth--; i++; continue; }
			i = isValidCssEscape(css, i) ? cssEscapeEnd(css, i) : i + 1;
		}
		return { end: i, value: null };
	} else {
		const valueStart = i;
		for (;;) {
			// EOF 也结束 url token（CSS Syntax §4.3.6）。
			if (i >= css.length || css[i] === ')') return { end: Math.min(i + 1, css.length), value: decodeCssEscapes(css.slice(valueStart, i)) };
			if (isSrcsetSpace(css[i])) {
				const end = skipCssSpace(css, i);
				if (end >= css.length || css[end] === ')') return { end: Math.min(end + 1, css.length), value: decodeCssEscapes(css.slice(valueStart, i)) };
				i = end;
				break;
			}
			if (/["'(\x00-\x08\x0b\x0e-\x1f\x7f]/.test(css[i])) break;
			if (css[i] === '\\') {
				if (!isValidCssEscape(css, i)) break;
				i = cssEscapeEnd(css, i);
			} else i++;
		}
	}
	// Consume the remnants of a bad URL, honoring escaped closing parentheses.
	while (i < css.length && css[i] !== ')') i = isValidCssEscape(css, i) ? cssEscapeEnd(css, i) : i + 1;
	return { end: Math.min(i + 1, css.length), value: null };
}

// 判断标识符按码元扫描；只有真的需要比较名称时才切片或解码。
function readCssNameEnd(source, i) {
	while (i < source.length) {
		const c = source.charCodeAt(i);
		if ((c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 48 && c <= 57) || c === 45 || c === 95 || c >= 0x80) i++;
		else if (isValidCssEscape(source, i)) i = cssEscapeEnd(source, i);
		else break;
	}
	return i;
}

function cssName(source, start, end) {
	const raw = source.slice(start, end);
	return (raw.includes('\\') ? decodeCssEscapes(raw) : raw).toLowerCase();
}

/**
 * 线性扫描 CSS URL token 与 @import 字符串，不匹配注释/普通字符串。
 * 这不是完整 CSS AST：仅改写 URL 载荷，其余源码（包括 media/layer 条件）保持原样。
 */
const rewriteCss = capRewriteGrowth((account, css, baseUrl, workerOrigin) => {
	const source = String(css);
	if (!source.includes('(') && !source.includes('@')) return source;
	const parts = [];
	let cursor = 0;
	let i = 0;
	let parenDepth = 0;
	const imageSetDepths = [];
	let expectImageSetOption = false;
	const replace = (start, end, value, wrapUrl = false) => {
		if (value === null || !value) return;
		const rewritten = rewriteUrl(value, baseUrl, workerOrigin);
		if (rewritten === value) return;
		const quoted = quoteCssString(rewritten);
		parts.push(source.slice(cursor, start), account(end - start, wrapUrl ? `url(${quoted})` : quoted));
		cursor = end;
	};
	while (i < source.length) {
		if (source.startsWith('/*', i) || isSrcsetSpace(source[i])) {
			i = skipCssSpace(source, i, true);
			continue;
		}
		if (source[i] === '"' || source[i] === "'") {
			const str = readCssString(source, i);
			if (expectImageSetOption && imageSetDepths.length &&
				imageSetDepths[imageSetDepths.length - 1] === parenDepth) {
				replace(i, str.end, str.value);
				expectImageSetOption = false;
			}
			i = str.end;
			continue;
		}
		if (source[i] === '(') {
			parenDepth++;
			expectImageSetOption = false;
			i++;
			continue;
		}
		if (source[i] === ')') {
			if (imageSetDepths.length && imageSetDepths[imageSetDepths.length - 1] === parenDepth) {
				imageSetDepths.pop();
			}
			if (parenDepth > 0) parenDepth--;
			expectImageSetOption = false;
			i++;
			continue;
		}
		if (source[i] === ',') {
			expectImageSetOption = imageSetDepths.length > 0 &&
				imageSetDepths[imageSetDepths.length - 1] === parenDepth;
			i++;
			continue;
		}
		expectImageSetOption = false;
		const start = i;
		const prefix = source[i] === '@' || source[i] === '#' ? source[i++] : '';
		const nameStart = i;
		i = readCssNameEnd(source, i);
		if (i === nameStart) { i = Math.max(i, start + 1); continue; }
		if (prefix !== '@' && source[i] !== '(') continue;
		const name = cssName(source, nameStart, i);
		if (prefix === '@' && name === 'import') {
			const valueStart = skipCssSpace(source, i, true);
			if (source[valueStart] === '"' || source[valueStart] === "'") {
				const str = readCssString(source, valueStart);
				replace(valueStart, str.end, str.value);
				i = str.end;
			}
		} else if (prefix === '@' && name === 'namespace') {
			// 命名空间 URL 只是标识符，从不加载；改写会让 svg|a 这类命名空间选择器全部失配。
			while (i < source.length && source[i] !== ';' && source[i] !== '{' && source[i] !== '}') {
				if (source[i] === '"' || source[i] === "'") i = readCssString(source, i).end;
				else if (source.startsWith('/*', i)) i = skipCssSpace(source, i, true);
				else {
					const end = readCssNameEnd(source, i);
					// 包括转义拼写的 url()，其中的分号或 /* 不能当成前导结束。
					if (end > i && source[end] === '(' && cssName(source, i, end) === 'url') i = readCssUrl(source, end + 1).end;
					else i = Math.max(end, i + 1);
				}
			}
		} else if (!prefix && name === 'url' && source[i] === '(') {
			const url = readCssUrl(source, i + 1);
			replace(start, url.end, url.value, true);
			i = url.end;
		} else if (!prefix && (name === 'image-set' || name === '-webkit-image-set') && source[i] === '(') {
			parenDepth++;
			imageSetDepths.push(parenDepth);
			expectImageSetOption = true;
			i++;
		}
	}
	if (!cursor) return source;
	parts.push(source.slice(cursor));
	return parts.join('');
});

/** 重写内联 style / CSS 字符串中的 url() */
function rewriteStyleAttr(style, baseUrl, workerOrigin) {
	const source = String(style);
	if (!source.includes('(') || !/(?:url|image-set|\\)/i.test(source)) return source;
	return rewriteCss(source, baseUrl, workerOrigin);
}

/**
 * 懒加载 data-* 是自由格式属性：data-lazy="true"、data-video="1"、data-background="dark"、JSON 配置等都不是 URL，
 * 一律按 URL 改写会把页面脚本读到的业务值换成代理地址。
 * 只改写 srcset 列表、CSS 函数写法（data-bg="url(a.jpg)"）和形似 URL 的值：
 * 以协议/斜杠/点斜杠/问号开头，或是带路径分隔符或点号的单个记号（不含空白、引号、尖/花/方括号，且非纯数字）。
 */
function rewriteLazyValue(attr, value, baseUrl, workerOrigin) {
	if (/(?:srcset|-set)$/.test(attr)) return rewriteSrcset(value, baseUrl, workerOrigin);
	const v = value.trim();
	if (/^[a-z-]+\(/i.test(v)) return rewriteStyleAttr(value, baseUrl, workerOrigin);
	const urlLike = /^(?:(?:[a-z][a-z0-9+.-]*:)?\/|\.\.?\/|\?)/i.test(v) ||
		(/[/.]/.test(v) && !/[\s"'<>{}[\]]/.test(v) && !/^[\d.]+$/.test(v));
	return urlLike ? rewriteUrl(value, baseUrl, workerOrigin) : value;
}

/** 重写 <meta http-equiv="refresh" content="0; url=...">（兼容省略 url= 的规范写法，避免误匹配查询串内 url= 或空 url= 回溯） */
function rewriteRefreshContent(content, baseUrl, workerOrigin) {
	const stripQuotes = (s) => {
		const t = s.trim();
		if (t[0] === "'" || t[0] === '"') {
			const end = t.indexOf(t[0], 1);
			return (end >= 0 ? t.slice(1, end) : t.slice(1)).trim();
		}
		return t;
	};
	return String(content).replace(
		/^(\s*(?:\d+(?:\.\d*)?|\.\d+)(?:\s*[;,]\s*|\s+))(?:url\s*=\s*|(?!url\s*=))([\s\S]*)$/i,
		(m, prefix, u) => {
			const cleaned = stripQuotes(u);
			return cleaned ? prefix + 'url=' + rewriteUrl(cleaned, baseUrl, workerOrigin) : m;
		}
	);
}

// Cookie 命名空间（不提供浏览器安全隔离）

const COOKIE_PREFIX = '__pe_';
/** 回源 Cookie 头预算：多数源站在 8K 处开始报错，留出余量 */
const MAX_COOKIE_HEADER = 6000;

/**
 * 无哈希碰撞且前缀无歧义的来源命名空间；ws/wss 与对应的 http/https 共享。
 * 长度前缀避免一个命名空间成为另一个的前缀。注意：这不是浏览器安全边界。
 * 旧版 FNV Cookie 不再读取，升级后需清理本站旧 Cookie 并重新登录。
 */
function cookieNamespace(targetUrl) {
	const u = new URL(targetUrl.href);
	if (u.protocol === 'ws:') u.protocol = 'http:';
	if (u.protocol === 'wss:') u.protocol = 'https:';
	const key = encodeURIComponent(u.origin);
	return COOKIE_PREFIX + key.length.toString(36) + '_' + key + '_';
}

// 浏览器依据名字开头执行前缀规则，命名空间必须放在保留前缀之后。
function reservedCookiePrefix(name) {
	return /^__(?:Host-Http|Host|Http|Secure)-/i.exec(name)?.[0] || '';
}

function originalCookieName(stored, ns) {
	const prefix = reservedCookiePrefix(stored);
	if (!stored.startsWith(ns, prefix.length)) return null;
	const name = prefix + stored.slice(prefix.length + ns.length);
	// 不接受旧版隐藏了保留前缀的名字，浏览器写入它们时没有验证相应约束。
	return reservedCookiePrefix(name) === prefix ? name : null;
}

/**
 * 改写上游 Set-Cookie：加命名空间前缀、强制 Path=/、去掉 Domain，
 * 确保 Secure / SameSite=None / Partitioned 不会被降级。
 * 返回 null 表示这条 cookie 无效、应丢弃。
 */
function scopeSetCookie(c, ns, workerIsHttps, fromScript = false) {
	const parts = String(c).split(';');
	const head = parts[0];
	const eq = head.indexOf('=');
	if (eq < 0) return null;
	const name = head.slice(0, eq).trim();
	if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(name)) return null;
	const value = head.slice(eq + 1).trim();

	const prefix = reservedCookiePrefix(name);
	const out = [`${prefix}${ns}${name.slice(prefix.length)}=${value}`];
	let path = null, hasDomain = false, hasHttpOnly = false;
	let sameSite = null;
	let hasSecure = false;
	let hasPartitioned = false;

	for (const raw of parts.slice(1)) {
		const part = raw.trim();
		if (!part) continue;
		const split = part.indexOf('=');
		const attr = part.slice(0, split < 0 ? undefined : split).trim().toLowerCase();
		if (attr === 'domain') { hasDomain = true; continue; }
		if (attr === 'path') { path = split < 0 ? '' : part.slice(split + 1).trim(); continue; }
		if (attr === 'httponly') {
			if (fromScript) return null;
			hasHttpOnly = true;
		}
		if (attr === 'secure') {
			if (!workerIsHttps) return null;
			if (!hasSecure) { out.push('Secure'); hasSecure = true; }
			continue;
		}
		if (attr === 'partitioned') {
			// CHIPS 同样要求 Secure；必须拒绝整条 Cookie，而非扩大作用域。
			if (!workerIsHttps) return null;
			if (!hasPartitioned) { out.push('Partitioned'); hasPartitioned = true; }
			continue;
		}
		if (attr === 'samesite') {
			// 同名属性以最后一个为准；未知或空值是浏览器的默认模式。
			const value = split < 0 ? '' : part.slice(split + 1).trim();
			sameSite = /^(?:lax|strict|none)$/i.test(value) ? value : null;
			continue;
		}
		out.push(part);
	}

	// 必须由上游或页面原本声明 Secure；补写会接受浏览器本应拒绝的 Cookie。
	if (!hasSecure && (prefix || hasPartitioned || sameSite?.toLowerCase() === 'none')) return null;
	if (/^__host-/i.test(prefix) && (hasDomain || path !== '/')) return null;
	if (/http-$/i.test(prefix) && !hasHttpOnly) return null;
	if (sameSite) out.push(`SameSite=${sameSite}`);
	out.push('Path=/');
	return out.join('; ');
}

/** 解析 Cookie 头为 [name, value] 对；值里允许出现 '=' */
function parseCookieHeader(header) {
	if (!header) return [];
	return header.split(';').map((p) => {
		const i = p.indexOf('=');
		if (i < 0) return null;
		return [p.slice(0, i).trim(), p.slice(i + 1).trim()];
	}).filter(Boolean);
}

/**
 * 从浏览器送来的 Cookie 头里只挑出属于当前目标站点的那部分，并剥掉前缀。
 * 其它站点的 cookie、以及 Worker 域名下无关的 cookie 都不会被转发。
 * 超出预算时跳过后续条目，避免源站因超大请求头返回 431/502。
 */
function scopeRequestCookie(header, ns) {
	const mine = parseCookieHeader(header)
		.map(([n, v]) => [originalCookieName(n, ns), v])
		.filter(([n]) => n && /^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(n));
	const kept = [];
	let len = 0;
	for (const [n, v] of mine) {
		const add = n.length + 1 + v.length + (kept.length ? 2 : 0);
		if (len + add > MAX_COOKIE_HEADER) continue;
		kept.push(`${n}=${v}`);
		len += add;
	}
	return kept.join('; ');
}

/** 就地重写 Headers 上的全部 Set-Cookie */
function rescopeSetCookies(headers, ns, workerIsHttps) {
	// Workers 的标准 API 可能尚不可用，但 getAll('Set-Cookie') 保留独立的字段。
	// 不读合并后的 get()：Expires 自身含逗号，无法安全地靠分隔符还原。
	const list = typeof headers.getSetCookie === 'function' ? headers.getSetCookie()
		: typeof headers.getAll === 'function' ? headers.getAll('Set-Cookie') : [];
	headers.delete('Set-Cookie');
	for (const c of list) {
		const scoped = scopeSetCookie(c, ns, workerIsHttps);
		if (scoped) headers.append('Set-Cookie', scoped);
	}
}

/** 用站点作用域后的 Cookie 覆盖转发头 */
function applyRequestCookieScope(fwdHeaders, request, ns) {
	fwdHeaders.delete('cookie');
	const scoped = scopeRequestCookie(request.headers.get('cookie'), ns);
	if (scoped) fwdHeaders.set('Cookie', scoped);
}

function isUtf8Charset(cs) {
	return !cs || cs === 'utf-8' || cs === 'utf8' || cs === 'unicode-1-1-utf-8';
}

/** 校验并规范化编码标签；不受 TextDecoder 支持的非法标签返回 null */
function normalizeCharsetLabel(label, fromMetaOrCss = false) {
	if (!label) return null;
	const cs = String(label).trim().toLowerCase();
	if (!cs) return null;
	if (fromMetaOrCss && cs === 'x-user-defined') return 'windows-1252';
	try {
		const encoding = new TextDecoder(cs).encoding;
		return fromMetaOrCss && /^utf-16(?:le|be)$/.test(encoding) ? 'utf-8' : encoding;
	} catch {
		return null;
	}
}

/** 参数名不能从另外一个参数的引号值里匹配。 */
function getCharset(contentType, fromMeta = false) {
	const param = /;[ \t]*([^;=\s]+)[ \t]*=[ \t]*(?:"((?:\\.|[^"\\])*)"|'([^']*)'|([^;]*))/g;
	for (const [, name, double, single, bare] of (contentType || '').matchAll(param)) {
		if (name.toLowerCase() === 'charset') {
			return normalizeCharsetLabel(double?.replace(/\\(.)/g, '$1') ?? single ?? bare, fromMeta);
		}
	}
	return null;
}

/** HTML 规范「从 meta 元素提取编码」：不要求前置分号，引号未闭合时放弃。 */
function extractMetaCharset(content) {
	const s = String(content || '');
	const re = /charset/gi;
	for (let m; (m = re.exec(s));) {
		let i = m.index + 7;
		while (i < s.length && isSrcsetSpace(s[i])) i++;
		if (s[i] !== '=') { re.lastIndex = i; continue; }
		i++;
		while (i < s.length && isSrcsetSpace(s[i])) i++;
		const quote = s[i];
		if (quote === '"' || quote === "'") {
			const end = s.indexOf(quote, i + 1);
			return end < 0 ? null : normalizeCharsetLabel(s.slice(i + 1, end), true);
		}
		let end = i;
		while (end < s.length && !isSrcsetSpace(s[end]) && s[end] !== ';') end++;
		return normalizeCharsetLabel(s.slice(i, end), true);
	}
	return null;
}

function scanHtmlPrescanAttrs(text, start, collect) {
	let i = start;
	const attrs = collect ? [] : null;
	const seen = collect ? new Set() : null;
	while (i < text.length) {
		while (isSrcsetSpace(text[i]) || text[i] === '/') i++;
		if (text[i] === '>') return { end: i + 1, attrs };
		const nameStart = i++;
		while (i < text.length && !isSrcsetSpace(text[i]) && !'/=>'.includes(text[i])) i++;
		const name = collect ? text.slice(nameStart, i).toLowerCase() : '';
		while (isSrcsetSpace(text[i])) i++;
		let value = '';
		if (text[i] === '=') {
			i++;
			while (isSrcsetSpace(text[i])) i++;
			const quote = text[i];
			if (quote === '"' || quote === "'") {
				const end = text.indexOf(quote, ++i);
				if (end === -1) return null;
				if (collect) value = text.slice(i, end);
				i = end + 1;
			} else {
				const valueStart = i;
				while (i < text.length && !isSrcsetSpace(text[i]) && text[i] !== '>') i++;
				if (collect) value = text.slice(valueStart, i);
			}
		}
		if (collect && name && !seen.has(name)) {
			seen.add(name);
			attrs.push([name, value]);
		}
	}
	return null;
}

function prescanHtmlCharset(text) {
	const tag = /<\/?([a-z][^\t\r\n\f />]*)/iy;
	for (let start = 0; (start = text.indexOf('<', start)) !== -1;) {
		if (text.startsWith('<!-->', start) || text.startsWith('<!--->', start)) {
			start += text[start + 4] === '>' ? 5 : 6;
			continue;
		}
		if (text.startsWith('<!--', start)) {
			const end = /--!?>/g;
			end.lastIndex = start + 4;
			if (!end.exec(text)) return null;
			start = end.lastIndex;
			continue;
		}
		if (text[start + 1] === '!' || text[start + 1] === '?') {
			const end = text.indexOf('>', start + 2);
			if (end < 0) return null;
			start = end + 1;
			continue;
		}
		tag.lastIndex = start;
		const match = tag.exec(text);
		if (!match) { start++; continue; }
		const meta = match[1].toLowerCase() === 'meta' && text[start + 1] !== '/';
		const scanned = scanHtmlPrescanAttrs(text, tag.lastIndex, meta);
		if (!scanned) return null;
		start = scanned.end;
		if (!meta) continue;
		let gotPragma = false, needPragma = null, charset = null;
		for (const [name, value] of scanned.attrs) {
			if (name === 'http-equiv' && value.toLowerCase() === 'content-type') gotPragma = true;
			else if (name === 'content' && charset === null) {
				const candidate = extractMetaCharset(value);
				if (candidate) { charset = candidate; needPragma = true; }
			} else if (name === 'charset' && charset === null) {
				const candidate = normalizeCharsetLabel(value, true);
				if (candidate) { charset = candidate; needPragma = false; }
			}
		}
		if (needPragma !== null && (!needPragma || gotPragma)) return charset;
	}
	return null;
}

function utf16XmlSignature(head) {
	if (head[0] === 0x3c && head[1] === 0 && head[2] === 0x3f && head[3] === 0) return 'utf-16le';
	if (head[0] === 0 && head[1] === 0x3c && head[2] === 0 && head[3] === 0x3f) return 'utf-16be';
	return null;
}

function utf8XmlDeclaration(declaration) {
	return declaration.replace(XML_ATTR, (m, space, name) => name === 'encoding' ? `${space}encoding="UTF-8"` : m);
}

function normalizeXhtmlProlog(stream) {
	// 使用 ReadableStream，避免要求 Workers 额外开启自定义 TransformStream 构造器。
	const reader = stream.getReader();
	let prefix = '';
	let canceled = false;
	return new ReadableStream({
		async pull(controller) {
			try {
				for (;;) {
					const { done, value } = await reader.read();
					if (canceled) return;
					if (done) {
						if (prefix) controller.enqueue(prefix);
						reader.releaseLock();
						controller.close();
						return;
					}
					if (prefix === null) { controller.enqueue(value); return; }
					prefix += value;
					if (prefix.length <= 5 && '<?xml'.startsWith(prefix)) continue;
					if (/^<\?xml[ \t\r\n]/.test(prefix)) {
						const end = prefix.indexOf('?>', 6);
						if (end < 0 && prefix.length <= 4096) continue;
						if (end >= 0 && end < 4096) prefix = utf8XmlDeclaration(prefix.slice(0, end + 2)) + prefix.slice(end + 2);
					}
					controller.enqueue(prefix);
					prefix = null;
					return;
				}
			} catch (error) {
				if (!canceled) reader.releaseLock();
				throw error;
			}
		},
		async cancel(reason) {
			canceled = true;
			try { await reader.cancel(reason); } finally { reader.releaseLock(); }
		},
	});
}

function xmlDeclaredCharset(text) {
	const m = /^<\?xml[ \t\r\n][^?]*\?>/.exec(text);
	if (!m) return null;
	for (const [, , name, , double, single] of m[0].matchAll(XML_ATTR)) {
		if (name !== 'encoding') continue;
		// 声明能按 ASCII 读出，正文就不可能是 UTF-16（真正的 UTF-16 已由 BOM 或字节签名识别）；
		// 与浏览器一致，把这种错误声明当作 UTF-8，而不是把整篇按 UTF-16 解成乱码。
		const encoding = normalizeCharsetLabel(double ?? single);
		return encoding && /^utf-16(?:le|be)$/.test(encoding) ? 'utf-8' : encoding;
	}
	return null;
}

/**
 * HTML 编码优先级：BOM > HTTP charset > 完整的 meta / XML 声明。
 * 都没有时，HTML 前缀若不是合法 UTF-8 则回退 windows-1252；XML 默认 UTF-8。
 * 一旦确定编码就停止嗅探，不必等到 4096 字节/EOF 才开始向浏览器输出。
 * tee 的另一支保留全部字节；只在固定大小的前缀缓冲中检查声明。
 */
async function sniffHtmlCharset(body, declaredCharset = null, isXml = false) {
	if (!body) return { charset: declaredCharset, body };
	const [a, b] = body.tee();
	const reader = a.getReader();
	const head = new Uint8Array(4096);
	let total = 0;
	let eof = false;
	let charset = declaredCharset;
	try {
		while (total < head.length) {
			const { done, value } = await reader.read();
			if (done) { eof = true; break; }
			const prefix = value.subarray(0, head.length - total);
			head.set(prefix, total);
			total += prefix.length;
			if (total >= 2 && head[0] === 0xff && head[1] === 0xfe) { charset = 'utf-16le'; break; }
			if (total >= 2 && head[0] === 0xfe && head[1] === 0xff) { charset = 'utf-16be'; break; }
			if (total < 3) continue;
			if (head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf) { charset = 'utf-8'; break; }
			if (declaredCharset) break;
			if (isXml) {
				// 3 字节的前缀仍可能是无 BOM 的 UTF-16 声明。
				if (total === 3 && ((head[0] === 0x3c && head[1] === 0 && head[2] === 0x3f) ||
					(head[0] === 0 && head[1] === 0x3c && head[2] === 0))) continue;
				if (total >= 4) {
					charset = utf16XmlSignature(head);
					if (charset) break;
				}
			}
			const prefixText = new TextDecoder().decode(head.subarray(0, total));
			charset = isXml ? xmlDeclaredCharset(prefixText) : prescanHtmlCharset(prefixText);
			if (charset) break;
			// XML 声明只能位于开头；末尾的 '?' 可能是跨分片的 '?>' 的第一部分。
			if (isXml && (prefixText.length <= 5
				? !'<?xml'.startsWith(prefixText)
				: !/^<\?xml[ \t\r\n][^?]*\??$/.test(prefixText))) break;
		}
	} finally {
		// 不 await：tee 另一支消费完之前 cancel 可能不 resolve。
		reader.cancel().catch(() => {});
		reader.releaseLock();
	}
	// 没有任何声明时浏览器不会假定 UTF-8：前缀不是合法 UTF-8 就使用 WHATWG 的通用回退编码。
	// 未到 EOF 时用 stream 模式容忍被 4096 字节边界截断的末尾序列。
	if (!charset && !isXml && total) {
		try { new TextDecoder('utf-8', { fatal: true }).decode(head.subarray(0, total), { stream: !eof }); }
		catch { charset = 'windows-1252'; }
	}
	return { charset, body: b };
}

/** 往 Vary 上追加一个字段名，不覆盖上游已有的 Vary */
function addVary(headers, field) {
	const cur = headers.get('vary');
	if (!cur) { headers.set('Vary', field); return; }
	const has = cur.split(',').some(v => v.trim() === '*' || v.trim().toLowerCase() === field.toLowerCase());
	if (!has) headers.set('Vary', cur + ', ' + field);
}

/** 只允许代理自身的 Origin；不能反射任意来源的凭证请求。 */
function applyCors(headers, request) {
	for (const name of [...headers.keys()]) {
		if (name.toLowerCase().startsWith('access-control-')) headers.delete(name);
	}
	// 上游看到的 Origin / Sec-Fetch-Site 还取决于 Referer，仅按代理请求的同名头分桶不够。
	const upstreamVary = headers.get('Vary') || '';
	if (upstreamVary.split(',').some(field => /^(?:origin|sec-fetch-site)$/i.test(field.trim()))) addVary(headers, 'Referer');
	addVary(headers, 'Origin');
	const origin = request && request.headers.get('origin');
	if (!origin || origin !== new URL(request.url).origin) return headers;
	headers.set('Access-Control-Allow-Origin', origin);
	headers.set('Access-Control-Allow-Credentials', 'true');
	headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS');
	const reqHeaders = request.headers.get('access-control-request-headers');
	if (reqHeaders) headers.set('Access-Control-Allow-Headers', reqHeaders);
	if (request.method === 'OPTIONS') {
		addVary(headers, 'Access-Control-Request-Method');
		addVary(headers, 'Access-Control-Request-Headers');
		headers.set('Access-Control-Max-Age', '600');
	}
	return headers;
}

function mimeType(contentType) {
	return (contentType || '').split(';', 1)[0].trim().toLowerCase();
}

function isJsonMime(mime) {
	return mime === 'application/json' || mime === 'text/json' || mime.endsWith('+json');
}

function contentCoding(headers) {
	return headers.get('Content-Encoding')?.trim().toLowerCase() || 'identity';
}

// Cache-Control 扩展可含带引号的逗号；引号值中的文本不是独立指令。
function hasNoTransform(value) {
	if (!value || !/no-transform/i.test(value)) return false;
	let start = 0, quoted = false;
	for (let i = 0; i <= value.length; i++) {
		const ch = value[i];
		if (quoted && ch === '\\') { i++; continue; }
		if (ch === '"') quoted = !quoted;
		else if (!quoted && (ch === ',' || i === value.length)) {
			if (value.slice(start, i).trim().toLowerCase() === 'no-transform') return true;
			start = i + 1;
		}
	}
	return false;
}

function transformKind(headers, request) {
	// Workerd 解码 HTTP 回源的 gzip/br；其它编码不假定能解开。
	if (!['identity', 'gzip', 'br'].includes(contentCoding(headers))) return null;
	if (/^\s*attachment\s*(?:;|$)/i.test(headers.get('Content-Disposition') || '') ||
		hasNoTransform(headers.get('Cache-Control'))) return null;
	const mime = mimeType(headers.get('Content-Type'));
	if (mime === 'text/html' || mime === 'application/xhtml+xml') return 'html';
	if (mime === 'text/css') return 'css';
	if (/^(?:(?:application|text)\/(?:x-)?(?:javascript|ecmascript)|text\/(?:javascript1\.[0-5]|jscript|livescript))$/.test(mime)) return 'js';
	if (mime === 'image/svg+xml') return 'svg';
	if (mime === 'application/manifest+json' || (isJsonMime(mime) &&
		request.headers.get('Sec-Fetch-Dest')?.toLowerCase() === 'manifest')) return 'manifest';
	return null;
}

/** 构造透传 Response（headers 可变），并做统一清洗 */
function buildResponse(upstream, request, ck, baseUrl) {
	const resp = new Response(upstream.body, upstream);
	stripResponseHeaders(resp.headers, request, baseUrl);
	return applyCommon(resp, request, ck);
}

function isCacheableMethod(m) { return m === 'GET' || m === 'HEAD'; }

/**
 * 代理把不同会话映射到同一 URL；有凭证或 Set-Cookie 时不允许共享缓存。
 * 浏览器会把代理域下所有站点的 Cookie 一并发来，只有属于当前目标来源、真正回源的那部分才算凭证；
 * 否则任一站点写入 Cookie 后，其它目标（含无 Cookie 的静态 CDN）的响应也会全部变成 no-store。
 */
function applyCachePolicy(response, request, ck) {
	// 不把匿名缓存条目用于后来带凭证的请求；不能只在带凭证的响应上设置 no-store。
	if (ck?.varyOnReferer) addVary(response.headers, 'Referer');
	addVary(response.headers, 'Cookie');
	addVary(response.headers, 'Authorization');
	// 304 等响应可能没有 Content-Type，仍需保留已缓存 GET 的 no-transform 分桶。
	addVary(response.headers, 'Cache-Control');
	// 缓存也必须区分会被入口拒绝的 Service Worker 脚本请求。
	addVary(response.headers, 'Service-Worker');
	addVary(response.headers, 'Sec-Fetch-Dest');
	const hasCookie = Boolean(request) && (ck ? ck.hasCookie : request.headers.has('cookie'));
	if (response.status >= 500 || response.headers.has('set-cookie') ||
		(request && (!isCacheableMethod(request.method) || hasCookie ||
		request.headers.has('authorization')))) {
		const policy = hasNoTransform(response.headers.get('Cache-Control')) ? 'no-store, no-transform' : 'no-store';
		response.headers.set('Cache-Control', policy);
		response.headers.delete('cdn-cache-control');
		response.headers.delete('cloudflare-cdn-cache-control');
		response.headers.delete('surrogate-control');
	}
}

// ============================================================
// 运行时注入脚本（浏览器端 shim）
// 让 JS 动态发起的请求（fetch/XHR/WebSocket/img.src 等）也走代理
// ============================================================

function getShimScript(workerOrigin, cookieNs, isXml = false) {
	// application/xhtml+xml 按 XML 解析，脚本里的 && 与 < 会让整页解析失败；
	// CDATA 守卫在 HTML 中只是行注释，在 XHTML 中则保护脚本正文。
	const openTag = isXml ? '<script xmlns="http://www.w3.org/1999/xhtml">' : '<script>';
	return `${openTag}//<![CDATA[
(function(){
try{
/* XHR/pjax 拉回的 HTML 片段同样注入了 shim，被 jQuery/Turbo 等再次执行时不能层层重复包裹原生 API */
if(window.__PE__)return;
var WO=${JSON.stringify(workerOrigin)};
var WOU=new URL(WO);
var WOH=WOU.hostname.toLowerCase().replace(/\\.+$/,'');
var WOP=WOU.port||'';
var CK=${JSON.stringify(cookieNs || '')};
var HTML_NS='http://www.w3.org/1999/xhtml';
${browserPathHelpers()}
function isHtmlEl(el){var ns=el&&el.namespaceURI;return !ns||ns===HTML_NS;}
function isSelfHost(u){
  var h=(u&&u.hostname||'').toLowerCase().replace(/\\.+$/,'');
  if(!h)return false;
  var p=u.port||'';
  var lh=(location.hostname||'').toLowerCase().replace(/\\.+$/,'');
  return (h===WOH&&p===WOP)||(Boolean(lh)&&h===lh&&p===(location.port||''));
}
function currentTarget(){
var DEC=trimUrlSpace(decodeProxyPath(location.pathname)).replace(/^\\/+/,'');
if(!/^[a-z][a-z0-9+.-]*:\\/\\//i.test(DEC))DEC='https://'+DEC;
var hIdx=DEC.indexOf('#');if(hIdx>=0)DEC=DEC.substring(0,hIdx);
var search=urlSuffix(new URL(location.href)).split('#',1)[0];
var full=DEC+(search?(DEC.indexOf('?')>=0?'&':'?')+search.substring(1):'');
try{var u=new URL(full);if(u.protocol==='ws:')u.protocol='http:';else if(u.protocol==='wss:')u.protocol='https:';u.username='';u.password='';u.hostname=u.hostname.toLowerCase().replace(/\\.+$/,'');return u.href;}catch(e){return full;}
}
var SKIP_RE=/^(data:|blob:|javascript:|mailto:|tel:|sms:|about:|#)/i;
function base(){
  var target=currentTarget();
  var list=document.querySelectorAll?document.querySelectorAll('base[data-pe-base],base[href]'):[];
  if(!list.length&&document.querySelector){var b0=document.querySelector('base[data-pe-base],base[href]');if(b0)list=[b0];}
  for(var i=0;i<list.length;i++){
    var b=list[i];
    if(!isHtmlEl(b))continue;
    var pe=b.getAttribute('data-pe-base');
    var h=pe!==null?pe:b.getAttribute('href');
    if(h===null)continue;
    if(h){try{var u=new URL(h,target);if(u.protocol==='http:'||u.protocol==='https:')return u.href;}catch(e){}}
    return target;
  }
  return target;
}
function normProxied(raw,keepOrigin,parsed){
  var pu=parsed||new URL(raw,WO);
  var isWs=pu.protocol==='ws:'||pu.protocol==='wss:';
  var cut=raw.search(/[?#]/);
  var rawPath=(cut<0?raw:raw.slice(0,cut)).replace(/^(?:[a-z][a-z0-9+.-]*:[\\/\\\\]*|[\\/\\\\]{2,})[^\\/\\\\?#]*/i,'').replace(/\\\\/g,'/');
  if(!/\\/(?:\\.|%2e){2}(?:\\/|$)/i.test(rawPath)&&isProxiedPath(pu.pathname)){
    if(!keepOrigin)return pu.pathname+urlSuffix(pu);
    if(isWs){
      var canonH=location.hostname||WOU.hostname;
      if(canonH&&pu.hostname!==canonH)pu.hostname=canonH;
      return pu.href;
    }
    return WO+pu.pathname+urlSuffix(pu);
  }
  var suffix=cut<0?'':raw.slice(cut);
  var dec=decodeProxyPath(rawPath);
  if(!dec)return keepOrigin?WO+pu.pathname+urlSuffix(pu):pu.pathname+urlSuffix(pu);
  var hCut=suffix.indexOf('#');
  var q=hCut<0?suffix:suffix.slice(0,hCut);
  var h=hCut<0?'':suffix.slice(hCut);
  var baseDec=dec.split('#',1)[0];
  var tu=new URL(baseDec+(q?(baseDec.indexOf('?')>=0?'&':'?')+q.slice(1):'')+h);
  var th=tu.hostname.toLowerCase().replace(/\\.+$/,'');
  if(th){try{tu.hostname=th;}catch(e){}}
  var prefix=keepOrigin?(isWs?pu.protocol+'//'+(location.host||WOU.host):WO):'';
  return prefix+encodeProxyPath(tu);
}
function rp(v){
  if(v==null||typeof v==='symbol')return v;
  if(v instanceof URL)return rp(v.href);
  var s=trimUrlSpace(String(v));
  if(!s||SKIP_RE.test(s))return s;
  if(isProxiedPath(s)){try{return normProxied(s,false);}catch(e){return s;}}
  var forcedWs='';
  var b;try{b=base();}catch(e){return s;}
  try{
    if(s===WO)s='/';
    else{
      /* 与服务端一致：先按文档基址解析，再判断是否落回代理域；反斜线或省略斜线的写法同样指向代理自身 */
      var pu=new URL(s,b);
      if((pu.protocol==='http:'||pu.protocol==='https:'||pu.protocol==='ws:'||pu.protocol==='wss:')&&isSelfHost(pu)){
        var rawSelf=s.replace(/^(?:[a-z][a-z0-9+.-]*:[\\/\\\\]*|[\\/\\\\]{2,})[^\\/\\\\?#]*/i,'').replace(/\\\\/g,'/');
        if(isProxiedPath(pu.pathname)||isProxiedPath(rawSelf))return normProxied(s,true,pu);
        if(pu.protocol==='ws:'||pu.protocol==='wss:')forcedWs=pu.protocol;
        // 用完整来源拼接：已解析路径开头的双斜线不是新的主机名。
        s=new URL(b).origin+pu.pathname+urlSuffix(pu);
      }
    }
  }catch(e){}
  var u;try{u=new URL(s,b);}catch(e){return s;}
  if(u.origin===WO&&isProxiedPath(u.pathname))return u.href;
  var p=forcedWs?(u.protocol==='http:'?'ws:':'wss:'):u.protocol;
  if(p!=='http:'&&p!=='https:'&&p!=='ws:'&&p!=='wss:')return s;
  var uh=u.hostname.toLowerCase().replace(/\\.+$/,'');
  if(uh){try{u.hostname=uh;}catch(e){}}
  return WO+encodeProxyPath(u,p);
}
function rwUrlArg(a){
  if(typeof a==='string')return rp(a);
  if(a instanceof URL)return new URL(rp(a.href),location.href||WO);
  if(typeof a!=='symbol')return rp(String(a));
  return a;
}
function rpBase(a){
  if(a instanceof URL)return new URL(rp(a.href),location.href||WO);
  if(typeof a!=='symbol'){
    var s=String(a);
    return !trimUrlSpace(s)?rp(base()):rp(s);
  }
  return a;
}
function isProxyRequestUrl(value){
  try{var u=new URL(value,WO);return u.origin===WO&&isProxiedPath(u.pathname);}catch(e){return false;}
}
function rwInit(init,stripIntegrity){
  if(init!=null&&typeof init!=='object'&&typeof init!=='function')return init;
  var ref=init?.referrer;
  var next=ref!==undefined&&ref!==null&&ref!==''&&ref!=='about:client'?rp(String(ref)):ref;
  if(next===ref&&!stripIntegrity)return init;
  // Fetch reads RequestInit as a dictionary, including inherited and non-enumerable
  // properties. Do not copy it with Object.assign or mutate the caller's object.
  return new Proxy(Object.create(null),{get:function(_,key){
    if(key==='integrity'&&stripIntegrity)return '';
    if(key==='referrer'&&next!==ref)return next;
    return init?.[key];
  }});
}
window.__PE__={get target(){return currentTarget();},rp:rp};
var oRequest=window.Request;
var getRequestUrl=oRequest&&Object.getOwnPropertyDescriptor(oRequest.prototype,'url')?.get;
function nativeRequestUrl(input){
  if(!oRequest||!input||typeof input!=='object')return null;
  if(getRequestUrl){try{return getRequestUrl.call(input);}catch(e){return null;}}
  return input instanceof oRequest?input.url:null;
}
function requestArgs(input,init){
  var original=nativeRequestUrl(input);
  if(original===null){
    var value=typeof input==='symbol'?input:rpBase(String(input));
    return [value,rwInit(init,Boolean(init?.integrity&&isProxyRequestUrl(value)))];
  }
  var url=rp(original);
  init=rwInit(init,Boolean((input.integrity||init?.integrity)&&isProxyRequestUrl(url)));
  if(!url||url===original)return [input,init];
  var r=init===undefined?input:new oRequest(input,init);
  var method=r.method||'GET';
  var body=method==='GET'||method==='HEAD'?undefined:(r.body??undefined);
  // A stream with keepalive or no-cors is not representable as a new native Request.
  // Let the native API report that rather than silently changing either option.
  return [url,{
    method:method,headers:r.headers,body:body,
    mode:r.mode,credentials:r.credentials,cache:r.cache,redirect:r.redirect,
    referrer:r.referrer==='about:client'?r.referrer:rp(r.referrer),referrerPolicy:r.referrerPolicy,
    integrity:isProxyRequestUrl(url)?'':r.integrity,keepalive:r.keepalive,signal:r.signal,
    duplex:body?'half':undefined
  }];
}
if(oRequest){
  var ProxyRequest=function(input,init){
    if(!new.target)throw new TypeError('Request requires new');
    return Reflect.construct(oRequest,arguments.length?requestArgs(input,init):[],new.target);
  };
  ProxyRequest.prototype=oRequest.prototype;
  Object.setPrototypeOf(ProxyRequest,oRequest);
  window.Request=ProxyRequest;
}
/* ---- fetch ---- */
var of_=window.fetch;
if(of_)window.fetch=function(input,init){
  if(!arguments.length)return of_.call(this);
  try{return of_.apply(this,requestArgs(input,init));}
  catch(e){return Promise.reject(e);}
};
/* ---- XMLHttpRequest ---- */
var oOpen=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){
  if(arguments.length>=2){try{arguments[1]=rpBase(u);}catch(e){}}
  return oOpen.apply(this,arguments);
};
/* ---- EventSource / sendBeacon / Worker / Audio / WebSocket ---- */
/* 与 Request 一样经 Reflect.construct 转发 new.target：子类实例必须得到子类原型，不带 new 的调用照常报错。 */
function wrapCtor(name,rewrite){
  var O=window[name];
  if(!O)return null;
  var W=function(){
    if(!new.target)throw new TypeError("Failed to construct '"+name+"': Please use the 'new' operator.");
    var args=Array.prototype.slice.call(arguments);
    if(args.length){try{args[0]=rewrite(args[0]);}catch(e){}}
    return Reflect.construct(O,args,new.target);
  };
  W.prototype=O.prototype;
  try{Object.setPrototypeOf(W,O);}catch(e){}
  window[name]=W;
  return W;
}
wrapCtor('EventSource',rpBase);
if(navigator.sendBeacon){var oSB=navigator.sendBeacon.bind(navigator);navigator.sendBeacon=function(u,d){try{if(arguments.length&&typeof u!=='symbol')u=rpBase(String(u));}catch(e){}return arguments.length>1?oSB(u,d):arguments.length?oSB(u):oSB();};}
wrapCtor('Worker',rpBase);
try{wrapCtor('SharedWorker',rpBase);}catch(e){}
try{wrapCtor('Audio',function(u){return u===undefined?u:rwUrlArg(u);});}catch(e){}
/* Service Worker 无法在代理路径下正确工作，直接禁用注册以免站点异常 */
try{if(navigator.serviceWorker)navigator.serviceWorker.register=function(){return Promise.reject(new Error('[ProxyEverything] service worker disabled'));};}catch(e){}
/* ---- WebSocket：目标地址已在路径内，无需污染目标查询串 ---- */
function rwWsUrl(u){
  if(typeof u==='symbol')return u;
  var nu=u instanceof URL?rp(u.href):rpBase(String(u));
  if(typeof nu==='string'){
    var au=new URL(nu,location.href||WO);
    if(au.origin===WO||au.origin===location.origin||isSelfHost(au)){
      au.protocol=(location.protocol||au.protocol)==='https:'?'wss:':'ws:';
      nu=au.href;
    }
  }
  return nu;
}
var WS=wrapCtor('WebSocket',rwWsUrl);
if(WS)['CONNECTING','OPEN','CLOSING','CLOSED'].forEach(function(k,i){try{WS[k]=i;}catch(e){}});
/* ---- history / window.open / location.assign ---- */
function wrapHistory(fn){return function(st,t,u){
  if(u!=null){
    var next=rwNavigation(String(u),true);
    var link=new URL(next,location.href);
    if(isSelfHost(link)){
      var dec=isProxiedPath(link.pathname)?decodeProxyPath(link.pathname):'';
      var dest=null;
      if(dec){try{dest=new URL(dec);var dh=dest.hostname.toLowerCase().replace(/\\.+$/,'');if(dh)dest.hostname=dh;}catch(e){dest=null;}}
      if(!dest||dest.origin!==new URL(currentTarget()).origin)throw new DOMException('History URL has a different target origin','SecurityError');
    }
    arguments[2]=next;
  }
  return fn.apply(this,arguments);
};}
if(history.pushState)history.pushState=wrapHistory(history.pushState);
if(history.replaceState)history.replaceState=wrapHistory(history.replaceState);
var oWo=window.open;
if(oWo)window.open=function(u){try{if(arguments.length&&u!==undefined&&typeof u!=='symbol')arguments[0]=rwUrlArg(String(u));}catch(e){}return oWo.apply(this,arguments);};
try{var oAs=location.assign.bind(location);location.assign=function(u){return arguments.length?oAs(typeof u!=='symbol'?rpBase(String(u)):u):oAs();};}catch(e){}
try{var oRe=location.replace.bind(location);location.replace=function(u){return arguments.length?oRe(typeof u!=='symbol'?rpBase(String(u)):u):oRe();};}catch(e){}
/* Location 的 href/assign/replace 不可配置，上面两行在真实浏览器中不会生效。支持 Navigation API 时在此兜底：
   把脚本或漏改链接发起的、会离开代理或落到未改写路径的跨文档导航改道；POST 表单与下载保持原样。 */
try{
  if(window.navigation&&navigation.addEventListener)navigation.addEventListener('navigate',function(ev){
    try{
      if(!ev.cancelable||ev.hashChange||ev.formData||ev.downloadRequest!=null)return;
      if(ev.navigationType!=='push'&&ev.navigationType!=='replace')return;
      if(ev.destination.sameDocument)return;
      var dest=new URL(ev.destination.url);
      if(dest.protocol!=='http:'&&dest.protocol!=='https:')return;
      if(isSelfHost(dest)&&isProxiedPath(dest.pathname))return;
      var next=rp(dest.href);
      if(!isProxyRequestUrl(next))return;
      ev.preventDefault();
      var replace=ev.navigationType==='replace';
      setTimeout(function(){if(replace)location.replace(next);else location.assign(next);},0);
    }catch(e){}
  });
}catch(e){}
/* ---- DOM 属性 setter 拦截：img.src = "..." 等动态赋值 ---- */
${mapPingUrls.toString()}
function rwPing(v){return typeof v!=='symbol'?mapPingUrls(String(v),rp):v;}
function rwAnchorArg(v){return typeof v!=='symbol'?rwNavigation(String(v),true):v;}
function rwFormArg(v){return typeof v!=='symbol'?rwNavigation(String(v),false):v;}
function patchSetter(ctor,prop,rewrite=rwUrlArg){
  try{
    if(!ctor||!ctor.prototype)return;
    var d=Object.getOwnPropertyDescriptor(ctor.prototype,prop);
    if(!d||!d.set||!d.configurable)return;
    var orig=d.set;
    Object.defineProperty(ctor.prototype,prop,{
      configurable:true,enumerable:d.enumerable,get:d.get,
      set:function(v){try{v=rewrite(v);}catch(e){}return orig.call(this,v);}
    });
  }catch(e){}
}
/* 与服务端共享同一解析器，保留候选 URL 内部的逗号。 */
${isSrcsetSpace.toString()}
${mapSrcset.toString()}
function rwSrcset(v){return typeof v!=='symbol'?mapSrcset(String(v),rp):v;}
var I=window.HTMLImageElement;
patchSetter(I,'src');patchSetter(I,'srcset',rwSrcset);
patchSetter(window.HTMLScriptElement,'src');
patchSetter(window.HTMLIFrameElement,'src');
patchSetter(window.HTMLFrameElement,'src');
patchSetter(window.HTMLLinkElement,'href');patchSetter(window.HTMLLinkElement,'imageSrcset',rwSrcset);
patchSetter(window.HTMLAnchorElement,'href',rwAnchorArg);patchSetter(window.HTMLAnchorElement,'ping',rwPing);
patchSetter(window.HTMLAreaElement,'href',rwAnchorArg);patchSetter(window.HTMLAreaElement,'ping',rwPing);
patchSetter(window.HTMLSourceElement,'src');patchSetter(window.HTMLSourceElement,'srcset',rwSrcset);
patchSetter(window.HTMLMediaElement,'src');
patchSetter(window.HTMLVideoElement,'poster');
patchSetter(window.HTMLFormElement,'action',rwFormArg);
patchSetter(window.HTMLObjectElement,'data');
patchSetter(window.HTMLEmbedElement,'src');
patchSetter(window.HTMLInputElement,'src');
patchSetter(window.HTMLInputElement,'formAction',rwFormArg);
patchSetter(window.HTMLButtonElement,'formAction',rwFormArg);
patchSetter(window.HTMLTrackElement,'src');
[window.HTMLScriptElement,window.HTMLLinkElement].forEach(function(C){
  try{
    if(!C||!C.prototype)return;
    var d=Object.getOwnPropertyDescriptor(C.prototype,'integrity');
    if(d&&d.configurable)Object.defineProperty(C.prototype,'integrity',{
      configurable:true,enumerable:d.enumerable,
      get:function(){return '';},
      set:function(){try{this.removeAttribute('integrity');}catch(e){}}
    });
  }catch(e){}
});
try{
  if(window.HTMLBaseElement&&window.HTMLBaseElement.prototype){
    var bd=Object.getOwnPropertyDescriptor(HTMLBaseElement.prototype,'href');
    if(bd&&bd.configurable){
      Object.defineProperty(HTMLBaseElement.prototype,'href',{
        configurable:true,enumerable:bd.enumerable,
        get:function(){
          var pe=this.getAttribute('data-pe-base');
          var h=pe!==null?pe:this.getAttribute('href');
          if(h!==null){
            if(h){try{var u=new URL(h,currentTarget());if(u.protocol==='http:'||u.protocol==='https:')return u.href;}catch(e){}}
            return currentTarget();
          }
          return base();
        },
        set:function(v){this.setAttribute('href',v);}
      });
    }
  }
}catch(e){}
/* setAttribute / setAttributeNS 兜底（src/srcset/imagesrcset/action/formaction/poster/data/href/xlink:href/ping） */
var XLINK_NS='http://www.w3.org/1999/xlink';
var ATTRS={src:0,srcset:1,imagesrcset:1,action:0,formaction:0,poster:0,data:0,href:0,'xlink:href':0,ping:2};
var HREF_TAGS={A:1,LINK:1,AREA:1,SCRIPT:1,IMAGE:1,USE:1,FEIMAGE:1,MPATH:1,TEXTPATH:1,PATTERN:1,FILTER:1,LINEARGRADIENT:1,RADIALGRADIENT:1};
/* 与服务端 HANDLERS 一致：data/action/formaction 等是常见的业务属性名，只在会据此加载资源的元素上改写 */
var ATTR_TAGS={href:HREF_TAGS,'xlink:href':HREF_TAGS,ping:{A:1,AREA:1},data:{OBJECT:1},action:{FORM:1},formaction:{INPUT:1,BUTTON:1}};
function rwAttrKind(name,tag){
  if(!Object.prototype.hasOwnProperty.call(ATTRS,name))return undefined;
  var tags=Object.prototype.hasOwnProperty.call(ATTR_TAGS,name)?ATTR_TAGS[name]:null;
  return !tags||tags[tag]===1?ATTRS[name]:undefined;
}
function normTag(el){
  var raw=(el&&(el.localName||el.tagName)||'').toUpperCase();
  var idx=raw.indexOf(':');
  return idx>=0?raw.slice(idx+1):raw;
}
function rwNavigation(sv,emptyUsesBase){
  var trimmed=trimUrlSpace(sv);
  if(!trimmed)return emptyUsesBase?rp(base()):sv;
  if(trimmed.charAt(0)==='#'){
    var b=base();
    if(b!==currentTarget())return rp(new URL(trimmed,b).href);
  }
  return rp(sv);
}
function rwAttrVal(el,tag,attr,kind,sv){
  if(kind===1)return rwSrcset(sv);
  if(kind===2)return rwPing(sv);
  if(attr==='action'||attr==='formaction')return rwNavigation(sv,false);
  if((tag==='A'||tag==='AREA')&&(attr==='href'||attr==='xlink:href'))return rwNavigation(sv,true);
  return rp(sv);
}
if(window.Element){
  var oSA=Element.prototype.setAttribute;
  var oRA=Element.prototype.removeAttribute;
  var oRANS=Element.prototype.removeAttributeNS;
  Element.prototype.setAttribute=function(n,v){
    try{
      if(arguments.length>=2&&typeof n==='string'&&typeof v!=='symbol'){
        var ln=n.toLowerCase();
        var sv=v instanceof URL?v.href:String(v);
        var tag=normTag(this);
        if(ln==='integrity'&&(tag==='SCRIPT'||tag==='LINK')){
          if(oRA)oRA.call(this,'integrity');
          return;
        }
        if(ln==='href'&&tag==='BASE'&&isHtmlEl(this)){
          var nextBase='';
          try{
            var bUrl=new URL(sv,currentTarget());
            if(bUrl.protocol==='http:'||bUrl.protocol==='https:')nextBase=bUrl.href;
          }catch(e){}
          oSA.call(this,'data-pe-base',nextBase);
          if(oRA)oRA.call(this,'href');
          return;
        }
        var kind=rwAttrKind(ln,tag);
        if(kind!==undefined)arguments[1]=rwAttrVal(this,tag,ln,kind,sv);
      }
    }catch(e){}
    return oSA.apply(this,arguments);
  };
  var oSANS=Element.prototype.setAttributeNS;
  if(oSANS)Element.prototype.setAttributeNS=function(ns,n,v){
    if(typeof n!=='string')return oSANS.apply(this,arguments);
    if(ns===XLINK_NS){
      if(n.slice(n.lastIndexOf(':')+1)!=='href')return oSANS.apply(this,arguments);
    }else if((ns!=null&&ns!=='')||n.indexOf(':')>=0)return oSANS.apply(this,arguments);
    try{
      if(arguments.length>=3&&typeof v!=='symbol'){
        var local=ns===XLINK_NS?'xlink:href':n;
        var sv=v instanceof URL?v.href:String(v);
        var tag=normTag(this);
        if(local==='integrity'&&(tag==='SCRIPT'||tag==='LINK')){
          if(oRA)oRA.call(this,'integrity');
          return;
        }
        if(local==='href'&&tag==='BASE'&&isHtmlEl(this)){
          var nextBase='';
          try{
            var bUrl=new URL(sv,currentTarget());
            if(bUrl.protocol==='http:'||bUrl.protocol==='https:')nextBase=bUrl.href;
          }catch(e){}
          oSA.call(this,'data-pe-base',nextBase);
          if(oRA)oRA.call(this,'href');
          return;
        }
        var kind=rwAttrKind(local,tag);
        if(kind!==undefined)arguments[2]=rwAttrVal(this,tag,local,kind,sv);
      }
    }catch(e){}
    return oSANS.apply(this,arguments);
  };
  if(oRA)Element.prototype.removeAttribute=function(n){
    try{
      if(typeof n==='string'&&n.toLowerCase()==='href'&&normTag(this)==='BASE'&&isHtmlEl(this)){
        oRA.call(this,'data-pe-base');
      }
    }catch(e){}
    return oRA.apply(this,arguments);
  };
  if(oRANS)Element.prototype.removeAttributeNS=function(ns,n){
    try{
      if((ns==null||ns==='')&&n==='href'&&normTag(this)==='BASE'&&isHtmlEl(this)&&oRA){
        oRA.call(this,'data-pe-base');
      }
    }catch(e){}
    return oRANS.apply(this,arguments);
  };
}
/* ---- document.cookie：读写都按站点命名空间转换 ----
   服务端下发的 cookie 名带 CK 前缀；页面脚本应当只看到原始名字。 */
try{
if(CK){
  ${reservedCookiePrefix.toString()}
  ${originalCookieName.toString()}
  var scopeCookie=${scopeSetCookie.toString()};
  var CD=Object.getOwnPropertyDescriptor(Document.prototype,'cookie')||
         Object.getOwnPropertyDescriptor(HTMLDocument.prototype,'cookie');
  if(CD&&CD.get&&CD.set&&CD.configurable){
    Object.defineProperty(document,'cookie',{
      configurable:true,enumerable:CD.enumerable,
      get:function(){
        var raw=CD.get.call(this)||'';
        var out=[];
        var parts=raw.split(';');
        for(var i=0;i<parts.length;i++){
          var p=parts[i].replace(/^\\s+/,'');
          var eq=p.indexOf('=');
          var name=eq<0?null:originalCookieName(p.slice(0,eq),CK);
          if(name)out.push(name+p.slice(eq));
        }
        return out.join('; ');
      },
      set:function(v){
        var scoped=scopeCookie(v,CK,location.protocol==='https:'&&new URL(currentTarget()).protocol==='https:',true);
        if(scoped===null)return;
        return CD.set.call(this,scoped);
      }
    });
  }
}
}catch(e){}
/* ---- 链接点击与表单提交兜底（覆盖 innerHTML 动态插入节点与编程式 submit） ---- */
function rwLinkEv(ev){
  try{
    var t=ev.target;
    if(t&&!t.closest)t=t.parentElement;
    var el=t&&t.closest?t.closest('a,area'):null;
    if(!el)return;
    var h=el.getAttribute('href');
    if(h!==null){var p=rwNavigation(h,true);if(p&&p!==h)el.setAttribute('href',p);}
    if(el.hasAttributeNS&&el.hasAttributeNS(XLINK_NS,'href')){
      var xhNs=el.getAttributeNS(XLINK_NS,'href');
      var pxNs=rwNavigation(xhNs,true);
      if(pxNs&&pxNs!==xhNs)el.setAttributeNS(XLINK_NS,'xlink:href',pxNs);
    }else{
      var xh=el.getAttribute('xlink:href');
      if(xh!==null){var px=rwNavigation(xh,true);if(px&&px!==xh)el.setAttribute('xlink:href',px);}
    }
    var pg=el.getAttribute('ping');
    if(pg){var ppg=rwPing(pg);if(ppg&&ppg!==pg)el.setAttribute('ping',ppg);}
  }catch(e){}
}
document.addEventListener('click',rwLinkEv,true);
document.addEventListener('auxclick',rwLinkEv,true);
document.addEventListener('contextmenu',rwLinkEv,true);
function rwForm(f,sub){
  try{
    if(!f||normTag(f)!=='FORM')return;
    var a=f.getAttribute('action');
    if(a&&trimUrlSpace(a)){var p=rwNavigation(a,false);if(p!==a)f.setAttribute('action',p);}
    if(sub&&sub.getAttribute){
      var fa=sub.getAttribute('formaction');
      if(fa&&trimUrlSpace(fa)){
        var pfa=rwNavigation(fa,false);
        if(pfa!==fa)sub.setAttribute('formaction',pfa);
      }
    }
  }catch(e){}
}
document.addEventListener('submit',function(ev){rwForm(ev.target,ev.submitter);},true);
if(window.HTMLFormElement&&HTMLFormElement.prototype){
  var oSub=HTMLFormElement.prototype.submit;
  if(oSub)HTMLFormElement.prototype.submit=function(){rwForm(this,null);return oSub.apply(this,arguments);};
  var oRSub=HTMLFormElement.prototype.requestSubmit;
  if(oRSub)HTMLFormElement.prototype.requestSubmit=function(sub){rwForm(this,sub);return oRSub.apply(this,arguments);};
}
}catch(e){try{console.error('[ProxyEverything] shim error',e);}catch(_){}}
})();
//]]></script>`;
}

// ============================================================
// HTML 重写（基于 HTMLRewriter，流式处理）
// ============================================================

/*
 * HTML named character references: data from the WHATWG HTML Standard
 * (https://html.spec.whatwg.org/entities.json), © WHATWG (Apple, Google,
 * Mozilla, Microsoft). Licensed under CC BY 4.0
 * (https://creativecommons.org/licenses/by/4.0/). Reformatted here as a
 * name-to-string table without the redundant codepoint arrays or leading &.
 */
const HTML_NAMED_REFERENCES = Object.freeze({
	"AElig":"\u00c6", "AElig;":"\u00c6", "AMP":"&", "AMP;":"&", "Aacute":"\u00c1", "Aacute;":"\u00c1", "Abreve;":"\u0102", "Acirc":"\u00c2",
	"Acirc;":"\u00c2", "Acy;":"\u0410", "Afr;":"\ud835\udd04", "Agrave":"\u00c0", "Agrave;":"\u00c0", "Alpha;":"\u0391", "Amacr;":"\u0100",
	"And;":"\u2a53", "Aogon;":"\u0104", "Aopf;":"\ud835\udd38", "ApplyFunction;":"\u2061", "Aring":"\u00c5", "Aring;":"\u00c5",
	"Ascr;":"\ud835\udc9c", "Assign;":"\u2254", "Atilde":"\u00c3", "Atilde;":"\u00c3", "Auml":"\u00c4", "Auml;":"\u00c4",
	"Backslash;":"\u2216", "Barv;":"\u2ae7", "Barwed;":"\u2306", "Bcy;":"\u0411", "Because;":"\u2235", "Bernoullis;":"\u212c",
	"Beta;":"\u0392", "Bfr;":"\ud835\udd05", "Bopf;":"\ud835\udd39", "Breve;":"\u02d8", "Bscr;":"\u212c", "Bumpeq;":"\u224e", "CHcy;":"\u0427",
	"COPY":"\u00a9", "COPY;":"\u00a9", "Cacute;":"\u0106", "Cap;":"\u22d2", "CapitalDifferentialD;":"\u2145", "Cayleys;":"\u212d",
	"Ccaron;":"\u010c", "Ccedil":"\u00c7", "Ccedil;":"\u00c7", "Ccirc;":"\u0108", "Cconint;":"\u2230", "Cdot;":"\u010a", "Cedilla;":"\u00b8",
	"CenterDot;":"\u00b7", "Cfr;":"\u212d", "Chi;":"\u03a7", "CircleDot;":"\u2299", "CircleMinus;":"\u2296", "CirclePlus;":"\u2295",
	"CircleTimes;":"\u2297", "ClockwiseContourIntegral;":"\u2232", "CloseCurlyDoubleQuote;":"\u201d", "CloseCurlyQuote;":"\u2019",
	"Colon;":"\u2237", "Colone;":"\u2a74", "Congruent;":"\u2261", "Conint;":"\u222f", "ContourIntegral;":"\u222e", "Copf;":"\u2102",
	"Coproduct;":"\u2210", "CounterClockwiseContourIntegral;":"\u2233", "Cross;":"\u2a2f", "Cscr;":"\ud835\udc9e", "Cup;":"\u22d3",
	"CupCap;":"\u224d", "DD;":"\u2145", "DDotrahd;":"\u2911", "DJcy;":"\u0402", "DScy;":"\u0405", "DZcy;":"\u040f", "Dagger;":"\u2021",
	"Darr;":"\u21a1", "Dashv;":"\u2ae4", "Dcaron;":"\u010e", "Dcy;":"\u0414", "Del;":"\u2207", "Delta;":"\u0394", "Dfr;":"\ud835\udd07",
	"DiacriticalAcute;":"\u00b4", "DiacriticalDot;":"\u02d9", "DiacriticalDoubleAcute;":"\u02dd", "DiacriticalGrave;":"`",
	"DiacriticalTilde;":"\u02dc", "Diamond;":"\u22c4", "DifferentialD;":"\u2146", "Dopf;":"\ud835\udd3b", "Dot;":"\u00a8", "DotDot;":"\u20dc",
	"DotEqual;":"\u2250", "DoubleContourIntegral;":"\u222f", "DoubleDot;":"\u00a8", "DoubleDownArrow;":"\u21d3", "DoubleLeftArrow;":"\u21d0",
	"DoubleLeftRightArrow;":"\u21d4", "DoubleLeftTee;":"\u2ae4", "DoubleLongLeftArrow;":"\u27f8", "DoubleLongLeftRightArrow;":"\u27fa",
	"DoubleLongRightArrow;":"\u27f9", "DoubleRightArrow;":"\u21d2", "DoubleRightTee;":"\u22a8", "DoubleUpArrow;":"\u21d1",
	"DoubleUpDownArrow;":"\u21d5", "DoubleVerticalBar;":"\u2225", "DownArrow;":"\u2193", "DownArrowBar;":"\u2913",
	"DownArrowUpArrow;":"\u21f5", "DownBreve;":"\u0311", "DownLeftRightVector;":"\u2950", "DownLeftTeeVector;":"\u295e",
	"DownLeftVector;":"\u21bd", "DownLeftVectorBar;":"\u2956", "DownRightTeeVector;":"\u295f", "DownRightVector;":"\u21c1",
	"DownRightVectorBar;":"\u2957", "DownTee;":"\u22a4", "DownTeeArrow;":"\u21a7", "Downarrow;":"\u21d3", "Dscr;":"\ud835\udc9f",
	"Dstrok;":"\u0110", "ENG;":"\u014a", "ETH":"\u00d0", "ETH;":"\u00d0", "Eacute":"\u00c9", "Eacute;":"\u00c9", "Ecaron;":"\u011a",
	"Ecirc":"\u00ca", "Ecirc;":"\u00ca", "Ecy;":"\u042d", "Edot;":"\u0116", "Efr;":"\ud835\udd08", "Egrave":"\u00c8", "Egrave;":"\u00c8",
	"Element;":"\u2208", "Emacr;":"\u0112", "EmptySmallSquare;":"\u25fb", "EmptyVerySmallSquare;":"\u25ab", "Eogon;":"\u0118",
	"Eopf;":"\ud835\udd3c", "Epsilon;":"\u0395", "Equal;":"\u2a75", "EqualTilde;":"\u2242", "Equilibrium;":"\u21cc", "Escr;":"\u2130",
	"Esim;":"\u2a73", "Eta;":"\u0397", "Euml":"\u00cb", "Euml;":"\u00cb", "Exists;":"\u2203", "ExponentialE;":"\u2147", "Fcy;":"\u0424",
	"Ffr;":"\ud835\udd09", "FilledSmallSquare;":"\u25fc", "FilledVerySmallSquare;":"\u25aa", "Fopf;":"\ud835\udd3d", "ForAll;":"\u2200",
	"Fouriertrf;":"\u2131", "Fscr;":"\u2131", "GJcy;":"\u0403", "GT":">", "GT;":">", "Gamma;":"\u0393", "Gammad;":"\u03dc", "Gbreve;":"\u011e",
	"Gcedil;":"\u0122", "Gcirc;":"\u011c", "Gcy;":"\u0413", "Gdot;":"\u0120", "Gfr;":"\ud835\udd0a", "Gg;":"\u22d9", "Gopf;":"\ud835\udd3e",
	"GreaterEqual;":"\u2265", "GreaterEqualLess;":"\u22db", "GreaterFullEqual;":"\u2267", "GreaterGreater;":"\u2aa2", "GreaterLess;":"\u2277",
	"GreaterSlantEqual;":"\u2a7e", "GreaterTilde;":"\u2273", "Gscr;":"\ud835\udca2", "Gt;":"\u226b", "HARDcy;":"\u042a", "Hacek;":"\u02c7",
	"Hat;":"^", "Hcirc;":"\u0124", "Hfr;":"\u210c", "HilbertSpace;":"\u210b", "Hopf;":"\u210d", "HorizontalLine;":"\u2500", "Hscr;":"\u210b",
	"Hstrok;":"\u0126", "HumpDownHump;":"\u224e", "HumpEqual;":"\u224f", "IEcy;":"\u0415", "IJlig;":"\u0132", "IOcy;":"\u0401",
	"Iacute":"\u00cd", "Iacute;":"\u00cd", "Icirc":"\u00ce", "Icirc;":"\u00ce", "Icy;":"\u0418", "Idot;":"\u0130", "Ifr;":"\u2111",
	"Igrave":"\u00cc", "Igrave;":"\u00cc", "Im;":"\u2111", "Imacr;":"\u012a", "ImaginaryI;":"\u2148", "Implies;":"\u21d2", "Int;":"\u222c",
	"Integral;":"\u222b", "Intersection;":"\u22c2", "InvisibleComma;":"\u2063", "InvisibleTimes;":"\u2062", "Iogon;":"\u012e",
	"Iopf;":"\ud835\udd40", "Iota;":"\u0399", "Iscr;":"\u2110", "Itilde;":"\u0128", "Iukcy;":"\u0406", "Iuml":"\u00cf", "Iuml;":"\u00cf",
	"Jcirc;":"\u0134", "Jcy;":"\u0419", "Jfr;":"\ud835\udd0d", "Jopf;":"\ud835\udd41", "Jscr;":"\ud835\udca5", "Jsercy;":"\u0408",
	"Jukcy;":"\u0404", "KHcy;":"\u0425", "KJcy;":"\u040c", "Kappa;":"\u039a", "Kcedil;":"\u0136", "Kcy;":"\u041a", "Kfr;":"\ud835\udd0e",
	"Kopf;":"\ud835\udd42", "Kscr;":"\ud835\udca6", "LJcy;":"\u0409", "LT":"<", "LT;":"<", "Lacute;":"\u0139", "Lambda;":"\u039b",
	"Lang;":"\u27ea", "Laplacetrf;":"\u2112", "Larr;":"\u219e", "Lcaron;":"\u013d", "Lcedil;":"\u013b", "Lcy;":"\u041b",
	"LeftAngleBracket;":"\u27e8", "LeftArrow;":"\u2190", "LeftArrowBar;":"\u21e4", "LeftArrowRightArrow;":"\u21c6", "LeftCeiling;":"\u2308",
	"LeftDoubleBracket;":"\u27e6", "LeftDownTeeVector;":"\u2961", "LeftDownVector;":"\u21c3", "LeftDownVectorBar;":"\u2959",
	"LeftFloor;":"\u230a", "LeftRightArrow;":"\u2194", "LeftRightVector;":"\u294e", "LeftTee;":"\u22a3", "LeftTeeArrow;":"\u21a4",
	"LeftTeeVector;":"\u295a", "LeftTriangle;":"\u22b2", "LeftTriangleBar;":"\u29cf", "LeftTriangleEqual;":"\u22b4",
	"LeftUpDownVector;":"\u2951", "LeftUpTeeVector;":"\u2960", "LeftUpVector;":"\u21bf", "LeftUpVectorBar;":"\u2958", "LeftVector;":"\u21bc",
	"LeftVectorBar;":"\u2952", "Leftarrow;":"\u21d0", "Leftrightarrow;":"\u21d4", "LessEqualGreater;":"\u22da", "LessFullEqual;":"\u2266",
	"LessGreater;":"\u2276", "LessLess;":"\u2aa1", "LessSlantEqual;":"\u2a7d", "LessTilde;":"\u2272", "Lfr;":"\ud835\udd0f", "Ll;":"\u22d8",
	"Lleftarrow;":"\u21da", "Lmidot;":"\u013f", "LongLeftArrow;":"\u27f5", "LongLeftRightArrow;":"\u27f7", "LongRightArrow;":"\u27f6",
	"Longleftarrow;":"\u27f8", "Longleftrightarrow;":"\u27fa", "Longrightarrow;":"\u27f9", "Lopf;":"\ud835\udd43", "LowerLeftArrow;":"\u2199",
	"LowerRightArrow;":"\u2198", "Lscr;":"\u2112", "Lsh;":"\u21b0", "Lstrok;":"\u0141", "Lt;":"\u226a", "Map;":"\u2905", "Mcy;":"\u041c",
	"MediumSpace;":"\u205f", "Mellintrf;":"\u2133", "Mfr;":"\ud835\udd10", "MinusPlus;":"\u2213", "Mopf;":"\ud835\udd44", "Mscr;":"\u2133",
	"Mu;":"\u039c", "NJcy;":"\u040a", "Nacute;":"\u0143", "Ncaron;":"\u0147", "Ncedil;":"\u0145", "Ncy;":"\u041d",
	"NegativeMediumSpace;":"\u200b", "NegativeThickSpace;":"\u200b", "NegativeThinSpace;":"\u200b", "NegativeVeryThinSpace;":"\u200b",
	"NestedGreaterGreater;":"\u226b", "NestedLessLess;":"\u226a", "NewLine;":"\n", "Nfr;":"\ud835\udd11", "NoBreak;":"\u2060",
	"NonBreakingSpace;":"\u00a0", "Nopf;":"\u2115", "Not;":"\u2aec", "NotCongruent;":"\u2262", "NotCupCap;":"\u226d",
	"NotDoubleVerticalBar;":"\u2226", "NotElement;":"\u2209", "NotEqual;":"\u2260", "NotEqualTilde;":"\u2242\u0338", "NotExists;":"\u2204",
	"NotGreater;":"\u226f", "NotGreaterEqual;":"\u2271", "NotGreaterFullEqual;":"\u2267\u0338", "NotGreaterGreater;":"\u226b\u0338",
	"NotGreaterLess;":"\u2279", "NotGreaterSlantEqual;":"\u2a7e\u0338", "NotGreaterTilde;":"\u2275", "NotHumpDownHump;":"\u224e\u0338",
	"NotHumpEqual;":"\u224f\u0338", "NotLeftTriangle;":"\u22ea", "NotLeftTriangleBar;":"\u29cf\u0338", "NotLeftTriangleEqual;":"\u22ec",
	"NotLess;":"\u226e", "NotLessEqual;":"\u2270", "NotLessGreater;":"\u2278", "NotLessLess;":"\u226a\u0338",
	"NotLessSlantEqual;":"\u2a7d\u0338", "NotLessTilde;":"\u2274", "NotNestedGreaterGreater;":"\u2aa2\u0338",
	"NotNestedLessLess;":"\u2aa1\u0338", "NotPrecedes;":"\u2280", "NotPrecedesEqual;":"\u2aaf\u0338", "NotPrecedesSlantEqual;":"\u22e0",
	"NotReverseElement;":"\u220c", "NotRightTriangle;":"\u22eb", "NotRightTriangleBar;":"\u29d0\u0338", "NotRightTriangleEqual;":"\u22ed",
	"NotSquareSubset;":"\u228f\u0338", "NotSquareSubsetEqual;":"\u22e2", "NotSquareSuperset;":"\u2290\u0338",
	"NotSquareSupersetEqual;":"\u22e3", "NotSubset;":"\u2282\u20d2", "NotSubsetEqual;":"\u2288", "NotSucceeds;":"\u2281",
	"NotSucceedsEqual;":"\u2ab0\u0338", "NotSucceedsSlantEqual;":"\u22e1", "NotSucceedsTilde;":"\u227f\u0338", "NotSuperset;":"\u2283\u20d2",
	"NotSupersetEqual;":"\u2289", "NotTilde;":"\u2241", "NotTildeEqual;":"\u2244", "NotTildeFullEqual;":"\u2247", "NotTildeTilde;":"\u2249",
	"NotVerticalBar;":"\u2224", "Nscr;":"\ud835\udca9", "Ntilde":"\u00d1", "Ntilde;":"\u00d1", "Nu;":"\u039d", "OElig;":"\u0152",
	"Oacute":"\u00d3", "Oacute;":"\u00d3", "Ocirc":"\u00d4", "Ocirc;":"\u00d4", "Ocy;":"\u041e", "Odblac;":"\u0150", "Ofr;":"\ud835\udd12",
	"Ograve":"\u00d2", "Ograve;":"\u00d2", "Omacr;":"\u014c", "Omega;":"\u03a9", "Omicron;":"\u039f", "Oopf;":"\ud835\udd46",
	"OpenCurlyDoubleQuote;":"\u201c", "OpenCurlyQuote;":"\u2018", "Or;":"\u2a54", "Oscr;":"\ud835\udcaa", "Oslash":"\u00d8",
	"Oslash;":"\u00d8", "Otilde":"\u00d5", "Otilde;":"\u00d5", "Otimes;":"\u2a37", "Ouml":"\u00d6", "Ouml;":"\u00d6", "OverBar;":"\u203e",
	"OverBrace;":"\u23de", "OverBracket;":"\u23b4", "OverParenthesis;":"\u23dc", "PartialD;":"\u2202", "Pcy;":"\u041f", "Pfr;":"\ud835\udd13",
	"Phi;":"\u03a6", "Pi;":"\u03a0", "PlusMinus;":"\u00b1", "Poincareplane;":"\u210c", "Popf;":"\u2119", "Pr;":"\u2abb", "Precedes;":"\u227a",
	"PrecedesEqual;":"\u2aaf", "PrecedesSlantEqual;":"\u227c", "PrecedesTilde;":"\u227e", "Prime;":"\u2033", "Product;":"\u220f",
	"Proportion;":"\u2237", "Proportional;":"\u221d", "Pscr;":"\ud835\udcab", "Psi;":"\u03a8", "QUOT":"\"", "QUOT;":"\"",
	"Qfr;":"\ud835\udd14", "Qopf;":"\u211a", "Qscr;":"\ud835\udcac", "RBarr;":"\u2910", "REG":"\u00ae", "REG;":"\u00ae", "Racute;":"\u0154",
	"Rang;":"\u27eb", "Rarr;":"\u21a0", "Rarrtl;":"\u2916", "Rcaron;":"\u0158", "Rcedil;":"\u0156", "Rcy;":"\u0420", "Re;":"\u211c",
	"ReverseElement;":"\u220b", "ReverseEquilibrium;":"\u21cb", "ReverseUpEquilibrium;":"\u296f", "Rfr;":"\u211c", "Rho;":"\u03a1",
	"RightAngleBracket;":"\u27e9", "RightArrow;":"\u2192", "RightArrowBar;":"\u21e5", "RightArrowLeftArrow;":"\u21c4",
	"RightCeiling;":"\u2309", "RightDoubleBracket;":"\u27e7", "RightDownTeeVector;":"\u295d", "RightDownVector;":"\u21c2",
	"RightDownVectorBar;":"\u2955", "RightFloor;":"\u230b", "RightTee;":"\u22a2", "RightTeeArrow;":"\u21a6", "RightTeeVector;":"\u295b",
	"RightTriangle;":"\u22b3", "RightTriangleBar;":"\u29d0", "RightTriangleEqual;":"\u22b5", "RightUpDownVector;":"\u294f",
	"RightUpTeeVector;":"\u295c", "RightUpVector;":"\u21be", "RightUpVectorBar;":"\u2954", "RightVector;":"\u21c0", "RightVectorBar;":"\u2953",
	"Rightarrow;":"\u21d2", "Ropf;":"\u211d", "RoundImplies;":"\u2970", "Rrightarrow;":"\u21db", "Rscr;":"\u211b", "Rsh;":"\u21b1",
	"RuleDelayed;":"\u29f4", "SHCHcy;":"\u0429", "SHcy;":"\u0428", "SOFTcy;":"\u042c", "Sacute;":"\u015a", "Sc;":"\u2abc", "Scaron;":"\u0160",
	"Scedil;":"\u015e", "Scirc;":"\u015c", "Scy;":"\u0421", "Sfr;":"\ud835\udd16", "ShortDownArrow;":"\u2193", "ShortLeftArrow;":"\u2190",
	"ShortRightArrow;":"\u2192", "ShortUpArrow;":"\u2191", "Sigma;":"\u03a3", "SmallCircle;":"\u2218", "Sopf;":"\ud835\udd4a",
	"Sqrt;":"\u221a", "Square;":"\u25a1", "SquareIntersection;":"\u2293", "SquareSubset;":"\u228f", "SquareSubsetEqual;":"\u2291",
	"SquareSuperset;":"\u2290", "SquareSupersetEqual;":"\u2292", "SquareUnion;":"\u2294", "Sscr;":"\ud835\udcae", "Star;":"\u22c6",
	"Sub;":"\u22d0", "Subset;":"\u22d0", "SubsetEqual;":"\u2286", "Succeeds;":"\u227b", "SucceedsEqual;":"\u2ab0",
	"SucceedsSlantEqual;":"\u227d", "SucceedsTilde;":"\u227f", "SuchThat;":"\u220b", "Sum;":"\u2211", "Sup;":"\u22d1", "Superset;":"\u2283",
	"SupersetEqual;":"\u2287", "Supset;":"\u22d1", "THORN":"\u00de", "THORN;":"\u00de", "TRADE;":"\u2122", "TSHcy;":"\u040b", "TScy;":"\u0426",
	"Tab;":"\t", "Tau;":"\u03a4", "Tcaron;":"\u0164", "Tcedil;":"\u0162", "Tcy;":"\u0422", "Tfr;":"\ud835\udd17", "Therefore;":"\u2234",
	"Theta;":"\u0398", "ThickSpace;":"\u205f\u200a", "ThinSpace;":"\u2009", "Tilde;":"\u223c", "TildeEqual;":"\u2243",
	"TildeFullEqual;":"\u2245", "TildeTilde;":"\u2248", "Topf;":"\ud835\udd4b", "TripleDot;":"\u20db", "Tscr;":"\ud835\udcaf",
	"Tstrok;":"\u0166", "Uacute":"\u00da", "Uacute;":"\u00da", "Uarr;":"\u219f", "Uarrocir;":"\u2949", "Ubrcy;":"\u040e", "Ubreve;":"\u016c",
	"Ucirc":"\u00db", "Ucirc;":"\u00db", "Ucy;":"\u0423", "Udblac;":"\u0170", "Ufr;":"\ud835\udd18", "Ugrave":"\u00d9", "Ugrave;":"\u00d9",
	"Umacr;":"\u016a", "UnderBar;":"_", "UnderBrace;":"\u23df", "UnderBracket;":"\u23b5", "UnderParenthesis;":"\u23dd", "Union;":"\u22c3",
	"UnionPlus;":"\u228e", "Uogon;":"\u0172", "Uopf;":"\ud835\udd4c", "UpArrow;":"\u2191", "UpArrowBar;":"\u2912",
	"UpArrowDownArrow;":"\u21c5", "UpDownArrow;":"\u2195", "UpEquilibrium;":"\u296e", "UpTee;":"\u22a5", "UpTeeArrow;":"\u21a5",
	"Uparrow;":"\u21d1", "Updownarrow;":"\u21d5", "UpperLeftArrow;":"\u2196", "UpperRightArrow;":"\u2197", "Upsi;":"\u03d2",
	"Upsilon;":"\u03a5", "Uring;":"\u016e", "Uscr;":"\ud835\udcb0", "Utilde;":"\u0168", "Uuml":"\u00dc", "Uuml;":"\u00dc", "VDash;":"\u22ab",
	"Vbar;":"\u2aeb", "Vcy;":"\u0412", "Vdash;":"\u22a9", "Vdashl;":"\u2ae6", "Vee;":"\u22c1", "Verbar;":"\u2016", "Vert;":"\u2016",
	"VerticalBar;":"\u2223", "VerticalLine;":"|", "VerticalSeparator;":"\u2758", "VerticalTilde;":"\u2240", "VeryThinSpace;":"\u200a",
	"Vfr;":"\ud835\udd19", "Vopf;":"\ud835\udd4d", "Vscr;":"\ud835\udcb1", "Vvdash;":"\u22aa", "Wcirc;":"\u0174", "Wedge;":"\u22c0",
	"Wfr;":"\ud835\udd1a", "Wopf;":"\ud835\udd4e", "Wscr;":"\ud835\udcb2", "Xfr;":"\ud835\udd1b", "Xi;":"\u039e", "Xopf;":"\ud835\udd4f",
	"Xscr;":"\ud835\udcb3", "YAcy;":"\u042f", "YIcy;":"\u0407", "YUcy;":"\u042e", "Yacute":"\u00dd", "Yacute;":"\u00dd", "Ycirc;":"\u0176",
	"Ycy;":"\u042b", "Yfr;":"\ud835\udd1c", "Yopf;":"\ud835\udd50", "Yscr;":"\ud835\udcb4", "Yuml;":"\u0178", "ZHcy;":"\u0416",
	"Zacute;":"\u0179", "Zcaron;":"\u017d", "Zcy;":"\u0417", "Zdot;":"\u017b", "ZeroWidthSpace;":"\u200b", "Zeta;":"\u0396", "Zfr;":"\u2128",
	"Zopf;":"\u2124", "Zscr;":"\ud835\udcb5", "aacute":"\u00e1", "aacute;":"\u00e1", "abreve;":"\u0103", "ac;":"\u223e", "acE;":"\u223e\u0333",
	"acd;":"\u223f", "acirc":"\u00e2", "acirc;":"\u00e2", "acute":"\u00b4", "acute;":"\u00b4", "acy;":"\u0430", "aelig":"\u00e6",
	"aelig;":"\u00e6", "af;":"\u2061", "afr;":"\ud835\udd1e", "agrave":"\u00e0", "agrave;":"\u00e0", "alefsym;":"\u2135", "aleph;":"\u2135",
	"alpha;":"\u03b1", "amacr;":"\u0101", "amalg;":"\u2a3f", "amp":"&", "amp;":"&", "and;":"\u2227", "andand;":"\u2a55", "andd;":"\u2a5c",
	"andslope;":"\u2a58", "andv;":"\u2a5a", "ang;":"\u2220", "ange;":"\u29a4", "angle;":"\u2220", "angmsd;":"\u2221", "angmsdaa;":"\u29a8",
	"angmsdab;":"\u29a9", "angmsdac;":"\u29aa", "angmsdad;":"\u29ab", "angmsdae;":"\u29ac", "angmsdaf;":"\u29ad", "angmsdag;":"\u29ae",
	"angmsdah;":"\u29af", "angrt;":"\u221f", "angrtvb;":"\u22be", "angrtvbd;":"\u299d", "angsph;":"\u2222", "angst;":"\u00c5",
	"angzarr;":"\u237c", "aogon;":"\u0105", "aopf;":"\ud835\udd52", "ap;":"\u2248", "apE;":"\u2a70", "apacir;":"\u2a6f", "ape;":"\u224a",
	"apid;":"\u224b", "apos;":"'", "approx;":"\u2248", "approxeq;":"\u224a", "aring":"\u00e5", "aring;":"\u00e5", "ascr;":"\ud835\udcb6",
	"ast;":"*", "asymp;":"\u2248", "asympeq;":"\u224d", "atilde":"\u00e3", "atilde;":"\u00e3", "auml":"\u00e4", "auml;":"\u00e4",
	"awconint;":"\u2233", "awint;":"\u2a11", "bNot;":"\u2aed", "backcong;":"\u224c", "backepsilon;":"\u03f6", "backprime;":"\u2035",
	"backsim;":"\u223d", "backsimeq;":"\u22cd", "barvee;":"\u22bd", "barwed;":"\u2305", "barwedge;":"\u2305", "bbrk;":"\u23b5",
	"bbrktbrk;":"\u23b6", "bcong;":"\u224c", "bcy;":"\u0431", "bdquo;":"\u201e", "becaus;":"\u2235", "because;":"\u2235", "bemptyv;":"\u29b0",
	"bepsi;":"\u03f6", "bernou;":"\u212c", "beta;":"\u03b2", "beth;":"\u2136", "between;":"\u226c", "bfr;":"\ud835\udd1f", "bigcap;":"\u22c2",
	"bigcirc;":"\u25ef", "bigcup;":"\u22c3", "bigodot;":"\u2a00", "bigoplus;":"\u2a01", "bigotimes;":"\u2a02", "bigsqcup;":"\u2a06",
	"bigstar;":"\u2605", "bigtriangledown;":"\u25bd", "bigtriangleup;":"\u25b3", "biguplus;":"\u2a04", "bigvee;":"\u22c1",
	"bigwedge;":"\u22c0", "bkarow;":"\u290d", "blacklozenge;":"\u29eb", "blacksquare;":"\u25aa", "blacktriangle;":"\u25b4",
	"blacktriangledown;":"\u25be", "blacktriangleleft;":"\u25c2", "blacktriangleright;":"\u25b8", "blank;":"\u2423", "blk12;":"\u2592",
	"blk14;":"\u2591", "blk34;":"\u2593", "block;":"\u2588", "bne;":"=\u20e5", "bnequiv;":"\u2261\u20e5", "bnot;":"\u2310",
	"bopf;":"\ud835\udd53", "bot;":"\u22a5", "bottom;":"\u22a5", "bowtie;":"\u22c8", "boxDL;":"\u2557", "boxDR;":"\u2554", "boxDl;":"\u2556",
	"boxDr;":"\u2553", "boxH;":"\u2550", "boxHD;":"\u2566", "boxHU;":"\u2569", "boxHd;":"\u2564", "boxHu;":"\u2567", "boxUL;":"\u255d",
	"boxUR;":"\u255a", "boxUl;":"\u255c", "boxUr;":"\u2559", "boxV;":"\u2551", "boxVH;":"\u256c", "boxVL;":"\u2563", "boxVR;":"\u2560",
	"boxVh;":"\u256b", "boxVl;":"\u2562", "boxVr;":"\u255f", "boxbox;":"\u29c9", "boxdL;":"\u2555", "boxdR;":"\u2552", "boxdl;":"\u2510",
	"boxdr;":"\u250c", "boxh;":"\u2500", "boxhD;":"\u2565", "boxhU;":"\u2568", "boxhd;":"\u252c", "boxhu;":"\u2534", "boxminus;":"\u229f",
	"boxplus;":"\u229e", "boxtimes;":"\u22a0", "boxuL;":"\u255b", "boxuR;":"\u2558", "boxul;":"\u2518", "boxur;":"\u2514", "boxv;":"\u2502",
	"boxvH;":"\u256a", "boxvL;":"\u2561", "boxvR;":"\u255e", "boxvh;":"\u253c", "boxvl;":"\u2524", "boxvr;":"\u251c", "bprime;":"\u2035",
	"breve;":"\u02d8", "brvbar":"\u00a6", "brvbar;":"\u00a6", "bscr;":"\ud835\udcb7", "bsemi;":"\u204f", "bsim;":"\u223d", "bsime;":"\u22cd",
	"bsol;":"\\", "bsolb;":"\u29c5", "bsolhsub;":"\u27c8", "bull;":"\u2022", "bullet;":"\u2022", "bump;":"\u224e", "bumpE;":"\u2aae",
	"bumpe;":"\u224f", "bumpeq;":"\u224f", "cacute;":"\u0107", "cap;":"\u2229", "capand;":"\u2a44", "capbrcup;":"\u2a49", "capcap;":"\u2a4b",
	"capcup;":"\u2a47", "capdot;":"\u2a40", "caps;":"\u2229\ufe00", "caret;":"\u2041", "caron;":"\u02c7", "ccaps;":"\u2a4d",
	"ccaron;":"\u010d", "ccedil":"\u00e7", "ccedil;":"\u00e7", "ccirc;":"\u0109", "ccups;":"\u2a4c", "ccupssm;":"\u2a50", "cdot;":"\u010b",
	"cedil":"\u00b8", "cedil;":"\u00b8", "cemptyv;":"\u29b2", "cent":"\u00a2", "cent;":"\u00a2", "centerdot;":"\u00b7", "cfr;":"\ud835\udd20",
	"chcy;":"\u0447", "check;":"\u2713", "checkmark;":"\u2713", "chi;":"\u03c7", "cir;":"\u25cb", "cirE;":"\u29c3", "circ;":"\u02c6",
	"circeq;":"\u2257", "circlearrowleft;":"\u21ba", "circlearrowright;":"\u21bb", "circledR;":"\u00ae", "circledS;":"\u24c8",
	"circledast;":"\u229b", "circledcirc;":"\u229a", "circleddash;":"\u229d", "cire;":"\u2257", "cirfnint;":"\u2a10", "cirmid;":"\u2aef",
	"cirscir;":"\u29c2", "clubs;":"\u2663", "clubsuit;":"\u2663", "colon;":":", "colone;":"\u2254", "coloneq;":"\u2254", "comma;":",",
	"commat;":"@", "comp;":"\u2201", "compfn;":"\u2218", "complement;":"\u2201", "complexes;":"\u2102", "cong;":"\u2245", "congdot;":"\u2a6d",
	"conint;":"\u222e", "copf;":"\ud835\udd54", "coprod;":"\u2210", "copy":"\u00a9", "copy;":"\u00a9", "copysr;":"\u2117", "crarr;":"\u21b5",
	"cross;":"\u2717", "cscr;":"\ud835\udcb8", "csub;":"\u2acf", "csube;":"\u2ad1", "csup;":"\u2ad0", "csupe;":"\u2ad2", "ctdot;":"\u22ef",
	"cudarrl;":"\u2938", "cudarrr;":"\u2935", "cuepr;":"\u22de", "cuesc;":"\u22df", "cularr;":"\u21b6", "cularrp;":"\u293d", "cup;":"\u222a",
	"cupbrcap;":"\u2a48", "cupcap;":"\u2a46", "cupcup;":"\u2a4a", "cupdot;":"\u228d", "cupor;":"\u2a45", "cups;":"\u222a\ufe00",
	"curarr;":"\u21b7", "curarrm;":"\u293c", "curlyeqprec;":"\u22de", "curlyeqsucc;":"\u22df", "curlyvee;":"\u22ce", "curlywedge;":"\u22cf",
	"curren":"\u00a4", "curren;":"\u00a4", "curvearrowleft;":"\u21b6", "curvearrowright;":"\u21b7", "cuvee;":"\u22ce", "cuwed;":"\u22cf",
	"cwconint;":"\u2232", "cwint;":"\u2231", "cylcty;":"\u232d", "dArr;":"\u21d3", "dHar;":"\u2965", "dagger;":"\u2020", "daleth;":"\u2138",
	"darr;":"\u2193", "dash;":"\u2010", "dashv;":"\u22a3", "dbkarow;":"\u290f", "dblac;":"\u02dd", "dcaron;":"\u010f", "dcy;":"\u0434",
	"dd;":"\u2146", "ddagger;":"\u2021", "ddarr;":"\u21ca", "ddotseq;":"\u2a77", "deg":"\u00b0", "deg;":"\u00b0", "delta;":"\u03b4",
	"demptyv;":"\u29b1", "dfisht;":"\u297f", "dfr;":"\ud835\udd21", "dharl;":"\u21c3", "dharr;":"\u21c2", "diam;":"\u22c4",
	"diamond;":"\u22c4", "diamondsuit;":"\u2666", "diams;":"\u2666", "die;":"\u00a8", "digamma;":"\u03dd", "disin;":"\u22f2", "div;":"\u00f7",
	"divide":"\u00f7", "divide;":"\u00f7", "divideontimes;":"\u22c7", "divonx;":"\u22c7", "djcy;":"\u0452", "dlcorn;":"\u231e",
	"dlcrop;":"\u230d", "dollar;":"$", "dopf;":"\ud835\udd55", "dot;":"\u02d9", "doteq;":"\u2250", "doteqdot;":"\u2251", "dotminus;":"\u2238",
	"dotplus;":"\u2214", "dotsquare;":"\u22a1", "doublebarwedge;":"\u2306", "downarrow;":"\u2193", "downdownarrows;":"\u21ca",
	"downharpoonleft;":"\u21c3", "downharpoonright;":"\u21c2", "drbkarow;":"\u2910", "drcorn;":"\u231f", "drcrop;":"\u230c",
	"dscr;":"\ud835\udcb9", "dscy;":"\u0455", "dsol;":"\u29f6", "dstrok;":"\u0111", "dtdot;":"\u22f1", "dtri;":"\u25bf", "dtrif;":"\u25be",
	"duarr;":"\u21f5", "duhar;":"\u296f", "dwangle;":"\u29a6", "dzcy;":"\u045f", "dzigrarr;":"\u27ff", "eDDot;":"\u2a77", "eDot;":"\u2251",
	"eacute":"\u00e9", "eacute;":"\u00e9", "easter;":"\u2a6e", "ecaron;":"\u011b", "ecir;":"\u2256", "ecirc":"\u00ea", "ecirc;":"\u00ea",
	"ecolon;":"\u2255", "ecy;":"\u044d", "edot;":"\u0117", "ee;":"\u2147", "efDot;":"\u2252", "efr;":"\ud835\udd22", "eg;":"\u2a9a",
	"egrave":"\u00e8", "egrave;":"\u00e8", "egs;":"\u2a96", "egsdot;":"\u2a98", "el;":"\u2a99", "elinters;":"\u23e7", "ell;":"\u2113",
	"els;":"\u2a95", "elsdot;":"\u2a97", "emacr;":"\u0113", "empty;":"\u2205", "emptyset;":"\u2205", "emptyv;":"\u2205", "emsp13;":"\u2004",
	"emsp14;":"\u2005", "emsp;":"\u2003", "eng;":"\u014b", "ensp;":"\u2002", "eogon;":"\u0119", "eopf;":"\ud835\udd56", "epar;":"\u22d5",
	"eparsl;":"\u29e3", "eplus;":"\u2a71", "epsi;":"\u03b5", "epsilon;":"\u03b5", "epsiv;":"\u03f5", "eqcirc;":"\u2256", "eqcolon;":"\u2255",
	"eqsim;":"\u2242", "eqslantgtr;":"\u2a96", "eqslantless;":"\u2a95", "equals;":"=", "equest;":"\u225f", "equiv;":"\u2261",
	"equivDD;":"\u2a78", "eqvparsl;":"\u29e5", "erDot;":"\u2253", "erarr;":"\u2971", "escr;":"\u212f", "esdot;":"\u2250", "esim;":"\u2242",
	"eta;":"\u03b7", "eth":"\u00f0", "eth;":"\u00f0", "euml":"\u00eb", "euml;":"\u00eb", "euro;":"\u20ac", "excl;":"!", "exist;":"\u2203",
	"expectation;":"\u2130", "exponentiale;":"\u2147", "fallingdotseq;":"\u2252", "fcy;":"\u0444", "female;":"\u2640", "ffilig;":"\ufb03",
	"fflig;":"\ufb00", "ffllig;":"\ufb04", "ffr;":"\ud835\udd23", "filig;":"\ufb01", "fjlig;":"fj", "flat;":"\u266d", "fllig;":"\ufb02",
	"fltns;":"\u25b1", "fnof;":"\u0192", "fopf;":"\ud835\udd57", "forall;":"\u2200", "fork;":"\u22d4", "forkv;":"\u2ad9", "fpartint;":"\u2a0d",
	"frac12":"\u00bd", "frac12;":"\u00bd", "frac13;":"\u2153", "frac14":"\u00bc", "frac14;":"\u00bc", "frac15;":"\u2155", "frac16;":"\u2159",
	"frac18;":"\u215b", "frac23;":"\u2154", "frac25;":"\u2156", "frac34":"\u00be", "frac34;":"\u00be", "frac35;":"\u2157", "frac38;":"\u215c",
	"frac45;":"\u2158", "frac56;":"\u215a", "frac58;":"\u215d", "frac78;":"\u215e", "frasl;":"\u2044", "frown;":"\u2322",
	"fscr;":"\ud835\udcbb", "gE;":"\u2267", "gEl;":"\u2a8c", "gacute;":"\u01f5", "gamma;":"\u03b3", "gammad;":"\u03dd", "gap;":"\u2a86",
	"gbreve;":"\u011f", "gcirc;":"\u011d", "gcy;":"\u0433", "gdot;":"\u0121", "ge;":"\u2265", "gel;":"\u22db", "geq;":"\u2265",
	"geqq;":"\u2267", "geqslant;":"\u2a7e", "ges;":"\u2a7e", "gescc;":"\u2aa9", "gesdot;":"\u2a80", "gesdoto;":"\u2a82", "gesdotol;":"\u2a84",
	"gesl;":"\u22db\ufe00", "gesles;":"\u2a94", "gfr;":"\ud835\udd24", "gg;":"\u226b", "ggg;":"\u22d9", "gimel;":"\u2137", "gjcy;":"\u0453",
	"gl;":"\u2277", "glE;":"\u2a92", "gla;":"\u2aa5", "glj;":"\u2aa4", "gnE;":"\u2269", "gnap;":"\u2a8a", "gnapprox;":"\u2a8a",
	"gne;":"\u2a88", "gneq;":"\u2a88", "gneqq;":"\u2269", "gnsim;":"\u22e7", "gopf;":"\ud835\udd58", "grave;":"`", "gscr;":"\u210a",
	"gsim;":"\u2273", "gsime;":"\u2a8e", "gsiml;":"\u2a90", "gt":">", "gt;":">", "gtcc;":"\u2aa7", "gtcir;":"\u2a7a", "gtdot;":"\u22d7",
	"gtlPar;":"\u2995", "gtquest;":"\u2a7c", "gtrapprox;":"\u2a86", "gtrarr;":"\u2978", "gtrdot;":"\u22d7", "gtreqless;":"\u22db",
	"gtreqqless;":"\u2a8c", "gtrless;":"\u2277", "gtrsim;":"\u2273", "gvertneqq;":"\u2269\ufe00", "gvnE;":"\u2269\ufe00", "hArr;":"\u21d4",
	"hairsp;":"\u200a", "half;":"\u00bd", "hamilt;":"\u210b", "hardcy;":"\u044a", "harr;":"\u2194", "harrcir;":"\u2948", "harrw;":"\u21ad",
	"hbar;":"\u210f", "hcirc;":"\u0125", "hearts;":"\u2665", "heartsuit;":"\u2665", "hellip;":"\u2026", "hercon;":"\u22b9",
	"hfr;":"\ud835\udd25", "hksearow;":"\u2925", "hkswarow;":"\u2926", "hoarr;":"\u21ff", "homtht;":"\u223b", "hookleftarrow;":"\u21a9",
	"hookrightarrow;":"\u21aa", "hopf;":"\ud835\udd59", "horbar;":"\u2015", "hscr;":"\ud835\udcbd", "hslash;":"\u210f", "hstrok;":"\u0127",
	"hybull;":"\u2043", "hyphen;":"\u2010", "iacute":"\u00ed", "iacute;":"\u00ed", "ic;":"\u2063", "icirc":"\u00ee", "icirc;":"\u00ee",
	"icy;":"\u0438", "iecy;":"\u0435", "iexcl":"\u00a1", "iexcl;":"\u00a1", "iff;":"\u21d4", "ifr;":"\ud835\udd26", "igrave":"\u00ec",
	"igrave;":"\u00ec", "ii;":"\u2148", "iiiint;":"\u2a0c", "iiint;":"\u222d", "iinfin;":"\u29dc", "iiota;":"\u2129", "ijlig;":"\u0133",
	"imacr;":"\u012b", "image;":"\u2111", "imagline;":"\u2110", "imagpart;":"\u2111", "imath;":"\u0131", "imof;":"\u22b7", "imped;":"\u01b5",
	"in;":"\u2208", "incare;":"\u2105", "infin;":"\u221e", "infintie;":"\u29dd", "inodot;":"\u0131", "int;":"\u222b", "intcal;":"\u22ba",
	"integers;":"\u2124", "intercal;":"\u22ba", "intlarhk;":"\u2a17", "intprod;":"\u2a3c", "iocy;":"\u0451", "iogon;":"\u012f",
	"iopf;":"\ud835\udd5a", "iota;":"\u03b9", "iprod;":"\u2a3c", "iquest":"\u00bf", "iquest;":"\u00bf", "iscr;":"\ud835\udcbe",
	"isin;":"\u2208", "isinE;":"\u22f9", "isindot;":"\u22f5", "isins;":"\u22f4", "isinsv;":"\u22f3", "isinv;":"\u2208", "it;":"\u2062",
	"itilde;":"\u0129", "iukcy;":"\u0456", "iuml":"\u00ef", "iuml;":"\u00ef", "jcirc;":"\u0135", "jcy;":"\u0439", "jfr;":"\ud835\udd27",
	"jmath;":"\u0237", "jopf;":"\ud835\udd5b", "jscr;":"\ud835\udcbf", "jsercy;":"\u0458", "jukcy;":"\u0454", "kappa;":"\u03ba",
	"kappav;":"\u03f0", "kcedil;":"\u0137", "kcy;":"\u043a", "kfr;":"\ud835\udd28", "kgreen;":"\u0138", "khcy;":"\u0445", "kjcy;":"\u045c",
	"kopf;":"\ud835\udd5c", "kscr;":"\ud835\udcc0", "lAarr;":"\u21da", "lArr;":"\u21d0", "lAtail;":"\u291b", "lBarr;":"\u290e", "lE;":"\u2266",
	"lEg;":"\u2a8b", "lHar;":"\u2962", "lacute;":"\u013a", "laemptyv;":"\u29b4", "lagran;":"\u2112", "lambda;":"\u03bb", "lang;":"\u27e8",
	"langd;":"\u2991", "langle;":"\u27e8", "lap;":"\u2a85", "laquo":"\u00ab", "laquo;":"\u00ab", "larr;":"\u2190", "larrb;":"\u21e4",
	"larrbfs;":"\u291f", "larrfs;":"\u291d", "larrhk;":"\u21a9", "larrlp;":"\u21ab", "larrpl;":"\u2939", "larrsim;":"\u2973",
	"larrtl;":"\u21a2", "lat;":"\u2aab", "latail;":"\u2919", "late;":"\u2aad", "lates;":"\u2aad\ufe00", "lbarr;":"\u290c", "lbbrk;":"\u2772",
	"lbrace;":"{", "lbrack;":"[", "lbrke;":"\u298b", "lbrksld;":"\u298f", "lbrkslu;":"\u298d", "lcaron;":"\u013e", "lcedil;":"\u013c",
	"lceil;":"\u2308", "lcub;":"{", "lcy;":"\u043b", "ldca;":"\u2936", "ldquo;":"\u201c", "ldquor;":"\u201e", "ldrdhar;":"\u2967",
	"ldrushar;":"\u294b", "ldsh;":"\u21b2", "le;":"\u2264", "leftarrow;":"\u2190", "leftarrowtail;":"\u21a2", "leftharpoondown;":"\u21bd",
	"leftharpoonup;":"\u21bc", "leftleftarrows;":"\u21c7", "leftrightarrow;":"\u2194", "leftrightarrows;":"\u21c6",
	"leftrightharpoons;":"\u21cb", "leftrightsquigarrow;":"\u21ad", "leftthreetimes;":"\u22cb", "leg;":"\u22da", "leq;":"\u2264",
	"leqq;":"\u2266", "leqslant;":"\u2a7d", "les;":"\u2a7d", "lescc;":"\u2aa8", "lesdot;":"\u2a7f", "lesdoto;":"\u2a81", "lesdotor;":"\u2a83",
	"lesg;":"\u22da\ufe00", "lesges;":"\u2a93", "lessapprox;":"\u2a85", "lessdot;":"\u22d6", "lesseqgtr;":"\u22da", "lesseqqgtr;":"\u2a8b",
	"lessgtr;":"\u2276", "lesssim;":"\u2272", "lfisht;":"\u297c", "lfloor;":"\u230a", "lfr;":"\ud835\udd29", "lg;":"\u2276", "lgE;":"\u2a91",
	"lhard;":"\u21bd", "lharu;":"\u21bc", "lharul;":"\u296a", "lhblk;":"\u2584", "ljcy;":"\u0459", "ll;":"\u226a", "llarr;":"\u21c7",
	"llcorner;":"\u231e", "llhard;":"\u296b", "lltri;":"\u25fa", "lmidot;":"\u0140", "lmoust;":"\u23b0", "lmoustache;":"\u23b0",
	"lnE;":"\u2268", "lnap;":"\u2a89", "lnapprox;":"\u2a89", "lne;":"\u2a87", "lneq;":"\u2a87", "lneqq;":"\u2268", "lnsim;":"\u22e6",
	"loang;":"\u27ec", "loarr;":"\u21fd", "lobrk;":"\u27e6", "longleftarrow;":"\u27f5", "longleftrightarrow;":"\u27f7", "longmapsto;":"\u27fc",
	"longrightarrow;":"\u27f6", "looparrowleft;":"\u21ab", "looparrowright;":"\u21ac", "lopar;":"\u2985", "lopf;":"\ud835\udd5d",
	"loplus;":"\u2a2d", "lotimes;":"\u2a34", "lowast;":"\u2217", "lowbar;":"_", "loz;":"\u25ca", "lozenge;":"\u25ca", "lozf;":"\u29eb",
	"lpar;":"(", "lparlt;":"\u2993", "lrarr;":"\u21c6", "lrcorner;":"\u231f", "lrhar;":"\u21cb", "lrhard;":"\u296d", "lrm;":"\u200e",
	"lrtri;":"\u22bf", "lsaquo;":"\u2039", "lscr;":"\ud835\udcc1", "lsh;":"\u21b0", "lsim;":"\u2272", "lsime;":"\u2a8d", "lsimg;":"\u2a8f",
	"lsqb;":"[", "lsquo;":"\u2018", "lsquor;":"\u201a", "lstrok;":"\u0142", "lt":"<", "lt;":"<", "ltcc;":"\u2aa6", "ltcir;":"\u2a79",
	"ltdot;":"\u22d6", "lthree;":"\u22cb", "ltimes;":"\u22c9", "ltlarr;":"\u2976", "ltquest;":"\u2a7b", "ltrPar;":"\u2996", "ltri;":"\u25c3",
	"ltrie;":"\u22b4", "ltrif;":"\u25c2", "lurdshar;":"\u294a", "luruhar;":"\u2966", "lvertneqq;":"\u2268\ufe00", "lvnE;":"\u2268\ufe00",
	"mDDot;":"\u223a", "macr":"\u00af", "macr;":"\u00af", "male;":"\u2642", "malt;":"\u2720", "maltese;":"\u2720", "map;":"\u21a6",
	"mapsto;":"\u21a6", "mapstodown;":"\u21a7", "mapstoleft;":"\u21a4", "mapstoup;":"\u21a5", "marker;":"\u25ae", "mcomma;":"\u2a29",
	"mcy;":"\u043c", "mdash;":"\u2014", "measuredangle;":"\u2221", "mfr;":"\ud835\udd2a", "mho;":"\u2127", "micro":"\u00b5", "micro;":"\u00b5",
	"mid;":"\u2223", "midast;":"*", "midcir;":"\u2af0", "middot":"\u00b7", "middot;":"\u00b7", "minus;":"\u2212", "minusb;":"\u229f",
	"minusd;":"\u2238", "minusdu;":"\u2a2a", "mlcp;":"\u2adb", "mldr;":"\u2026", "mnplus;":"\u2213", "models;":"\u22a7",
	"mopf;":"\ud835\udd5e", "mp;":"\u2213", "mscr;":"\ud835\udcc2", "mstpos;":"\u223e", "mu;":"\u03bc", "multimap;":"\u22b8",
	"mumap;":"\u22b8", "nGg;":"\u22d9\u0338", "nGt;":"\u226b\u20d2", "nGtv;":"\u226b\u0338", "nLeftarrow;":"\u21cd",
	"nLeftrightarrow;":"\u21ce", "nLl;":"\u22d8\u0338", "nLt;":"\u226a\u20d2", "nLtv;":"\u226a\u0338", "nRightarrow;":"\u21cf",
	"nVDash;":"\u22af", "nVdash;":"\u22ae", "nabla;":"\u2207", "nacute;":"\u0144", "nang;":"\u2220\u20d2", "nap;":"\u2249",
	"napE;":"\u2a70\u0338", "napid;":"\u224b\u0338", "napos;":"\u0149", "napprox;":"\u2249", "natur;":"\u266e", "natural;":"\u266e",
	"naturals;":"\u2115", "nbsp":"\u00a0", "nbsp;":"\u00a0", "nbump;":"\u224e\u0338", "nbumpe;":"\u224f\u0338", "ncap;":"\u2a43",
	"ncaron;":"\u0148", "ncedil;":"\u0146", "ncong;":"\u2247", "ncongdot;":"\u2a6d\u0338", "ncup;":"\u2a42", "ncy;":"\u043d",
	"ndash;":"\u2013", "ne;":"\u2260", "neArr;":"\u21d7", "nearhk;":"\u2924", "nearr;":"\u2197", "nearrow;":"\u2197", "nedot;":"\u2250\u0338",
	"nequiv;":"\u2262", "nesear;":"\u2928", "nesim;":"\u2242\u0338", "nexist;":"\u2204", "nexists;":"\u2204", "nfr;":"\ud835\udd2b",
	"ngE;":"\u2267\u0338", "nge;":"\u2271", "ngeq;":"\u2271", "ngeqq;":"\u2267\u0338", "ngeqslant;":"\u2a7e\u0338", "nges;":"\u2a7e\u0338",
	"ngsim;":"\u2275", "ngt;":"\u226f", "ngtr;":"\u226f", "nhArr;":"\u21ce", "nharr;":"\u21ae", "nhpar;":"\u2af2", "ni;":"\u220b",
	"nis;":"\u22fc", "nisd;":"\u22fa", "niv;":"\u220b", "njcy;":"\u045a", "nlArr;":"\u21cd", "nlE;":"\u2266\u0338", "nlarr;":"\u219a",
	"nldr;":"\u2025", "nle;":"\u2270", "nleftarrow;":"\u219a", "nleftrightarrow;":"\u21ae", "nleq;":"\u2270", "nleqq;":"\u2266\u0338",
	"nleqslant;":"\u2a7d\u0338", "nles;":"\u2a7d\u0338", "nless;":"\u226e", "nlsim;":"\u2274", "nlt;":"\u226e", "nltri;":"\u22ea",
	"nltrie;":"\u22ec", "nmid;":"\u2224", "nopf;":"\ud835\udd5f", "not":"\u00ac", "not;":"\u00ac", "notin;":"\u2209", "notinE;":"\u22f9\u0338",
	"notindot;":"\u22f5\u0338", "notinva;":"\u2209", "notinvb;":"\u22f7", "notinvc;":"\u22f6", "notni;":"\u220c", "notniva;":"\u220c",
	"notnivb;":"\u22fe", "notnivc;":"\u22fd", "npar;":"\u2226", "nparallel;":"\u2226", "nparsl;":"\u2afd\u20e5", "npart;":"\u2202\u0338",
	"npolint;":"\u2a14", "npr;":"\u2280", "nprcue;":"\u22e0", "npre;":"\u2aaf\u0338", "nprec;":"\u2280", "npreceq;":"\u2aaf\u0338",
	"nrArr;":"\u21cf", "nrarr;":"\u219b", "nrarrc;":"\u2933\u0338", "nrarrw;":"\u219d\u0338", "nrightarrow;":"\u219b", "nrtri;":"\u22eb",
	"nrtrie;":"\u22ed", "nsc;":"\u2281", "nsccue;":"\u22e1", "nsce;":"\u2ab0\u0338", "nscr;":"\ud835\udcc3", "nshortmid;":"\u2224",
	"nshortparallel;":"\u2226", "nsim;":"\u2241", "nsime;":"\u2244", "nsimeq;":"\u2244", "nsmid;":"\u2224", "nspar;":"\u2226",
	"nsqsube;":"\u22e2", "nsqsupe;":"\u22e3", "nsub;":"\u2284", "nsubE;":"\u2ac5\u0338", "nsube;":"\u2288", "nsubset;":"\u2282\u20d2",
	"nsubseteq;":"\u2288", "nsubseteqq;":"\u2ac5\u0338", "nsucc;":"\u2281", "nsucceq;":"\u2ab0\u0338", "nsup;":"\u2285",
	"nsupE;":"\u2ac6\u0338", "nsupe;":"\u2289", "nsupset;":"\u2283\u20d2", "nsupseteq;":"\u2289", "nsupseteqq;":"\u2ac6\u0338",
	"ntgl;":"\u2279", "ntilde":"\u00f1", "ntilde;":"\u00f1", "ntlg;":"\u2278", "ntriangleleft;":"\u22ea", "ntrianglelefteq;":"\u22ec",
	"ntriangleright;":"\u22eb", "ntrianglerighteq;":"\u22ed", "nu;":"\u03bd", "num;":"#", "numero;":"\u2116", "numsp;":"\u2007",
	"nvDash;":"\u22ad", "nvHarr;":"\u2904", "nvap;":"\u224d\u20d2", "nvdash;":"\u22ac", "nvge;":"\u2265\u20d2", "nvgt;":">\u20d2",
	"nvinfin;":"\u29de", "nvlArr;":"\u2902", "nvle;":"\u2264\u20d2", "nvlt;":"<\u20d2", "nvltrie;":"\u22b4\u20d2", "nvrArr;":"\u2903",
	"nvrtrie;":"\u22b5\u20d2", "nvsim;":"\u223c\u20d2", "nwArr;":"\u21d6", "nwarhk;":"\u2923", "nwarr;":"\u2196", "nwarrow;":"\u2196",
	"nwnear;":"\u2927", "oS;":"\u24c8", "oacute":"\u00f3", "oacute;":"\u00f3", "oast;":"\u229b", "ocir;":"\u229a", "ocirc":"\u00f4",
	"ocirc;":"\u00f4", "ocy;":"\u043e", "odash;":"\u229d", "odblac;":"\u0151", "odiv;":"\u2a38", "odot;":"\u2299", "odsold;":"\u29bc",
	"oelig;":"\u0153", "ofcir;":"\u29bf", "ofr;":"\ud835\udd2c", "ogon;":"\u02db", "ograve":"\u00f2", "ograve;":"\u00f2", "ogt;":"\u29c1",
	"ohbar;":"\u29b5", "ohm;":"\u03a9", "oint;":"\u222e", "olarr;":"\u21ba", "olcir;":"\u29be", "olcross;":"\u29bb", "oline;":"\u203e",
	"olt;":"\u29c0", "omacr;":"\u014d", "omega;":"\u03c9", "omicron;":"\u03bf", "omid;":"\u29b6", "ominus;":"\u2296", "oopf;":"\ud835\udd60",
	"opar;":"\u29b7", "operp;":"\u29b9", "oplus;":"\u2295", "or;":"\u2228", "orarr;":"\u21bb", "ord;":"\u2a5d", "order;":"\u2134",
	"orderof;":"\u2134", "ordf":"\u00aa", "ordf;":"\u00aa", "ordm":"\u00ba", "ordm;":"\u00ba", "origof;":"\u22b6", "oror;":"\u2a56",
	"orslope;":"\u2a57", "orv;":"\u2a5b", "oscr;":"\u2134", "oslash":"\u00f8", "oslash;":"\u00f8", "osol;":"\u2298", "otilde":"\u00f5",
	"otilde;":"\u00f5", "otimes;":"\u2297", "otimesas;":"\u2a36", "ouml":"\u00f6", "ouml;":"\u00f6", "ovbar;":"\u233d", "par;":"\u2225",
	"para":"\u00b6", "para;":"\u00b6", "parallel;":"\u2225", "parsim;":"\u2af3", "parsl;":"\u2afd", "part;":"\u2202", "pcy;":"\u043f",
	"percnt;":"%", "period;":".", "permil;":"\u2030", "perp;":"\u22a5", "pertenk;":"\u2031", "pfr;":"\ud835\udd2d", "phi;":"\u03c6",
	"phiv;":"\u03d5", "phmmat;":"\u2133", "phone;":"\u260e", "pi;":"\u03c0", "pitchfork;":"\u22d4", "piv;":"\u03d6", "planck;":"\u210f",
	"planckh;":"\u210e", "plankv;":"\u210f", "plus;":"+", "plusacir;":"\u2a23", "plusb;":"\u229e", "pluscir;":"\u2a22", "plusdo;":"\u2214",
	"plusdu;":"\u2a25", "pluse;":"\u2a72", "plusmn":"\u00b1", "plusmn;":"\u00b1", "plussim;":"\u2a26", "plustwo;":"\u2a27", "pm;":"\u00b1",
	"pointint;":"\u2a15", "popf;":"\ud835\udd61", "pound":"\u00a3", "pound;":"\u00a3", "pr;":"\u227a", "prE;":"\u2ab3", "prap;":"\u2ab7",
	"prcue;":"\u227c", "pre;":"\u2aaf", "prec;":"\u227a", "precapprox;":"\u2ab7", "preccurlyeq;":"\u227c", "preceq;":"\u2aaf",
	"precnapprox;":"\u2ab9", "precneqq;":"\u2ab5", "precnsim;":"\u22e8", "precsim;":"\u227e", "prime;":"\u2032", "primes;":"\u2119",
	"prnE;":"\u2ab5", "prnap;":"\u2ab9", "prnsim;":"\u22e8", "prod;":"\u220f", "profalar;":"\u232e", "profline;":"\u2312",
	"profsurf;":"\u2313", "prop;":"\u221d", "propto;":"\u221d", "prsim;":"\u227e", "prurel;":"\u22b0", "pscr;":"\ud835\udcc5", "psi;":"\u03c8",
	"puncsp;":"\u2008", "qfr;":"\ud835\udd2e", "qint;":"\u2a0c", "qopf;":"\ud835\udd62", "qprime;":"\u2057", "qscr;":"\ud835\udcc6",
	"quaternions;":"\u210d", "quatint;":"\u2a16", "quest;":"?", "questeq;":"\u225f", "quot":"\"", "quot;":"\"", "rAarr;":"\u21db",
	"rArr;":"\u21d2", "rAtail;":"\u291c", "rBarr;":"\u290f", "rHar;":"\u2964", "race;":"\u223d\u0331", "racute;":"\u0155", "radic;":"\u221a",
	"raemptyv;":"\u29b3", "rang;":"\u27e9", "rangd;":"\u2992", "range;":"\u29a5", "rangle;":"\u27e9", "raquo":"\u00bb", "raquo;":"\u00bb",
	"rarr;":"\u2192", "rarrap;":"\u2975", "rarrb;":"\u21e5", "rarrbfs;":"\u2920", "rarrc;":"\u2933", "rarrfs;":"\u291e", "rarrhk;":"\u21aa",
	"rarrlp;":"\u21ac", "rarrpl;":"\u2945", "rarrsim;":"\u2974", "rarrtl;":"\u21a3", "rarrw;":"\u219d", "ratail;":"\u291a", "ratio;":"\u2236",
	"rationals;":"\u211a", "rbarr;":"\u290d", "rbbrk;":"\u2773", "rbrace;":"}", "rbrack;":"]", "rbrke;":"\u298c", "rbrksld;":"\u298e",
	"rbrkslu;":"\u2990", "rcaron;":"\u0159", "rcedil;":"\u0157", "rceil;":"\u2309", "rcub;":"}", "rcy;":"\u0440", "rdca;":"\u2937",
	"rdldhar;":"\u2969", "rdquo;":"\u201d", "rdquor;":"\u201d", "rdsh;":"\u21b3", "real;":"\u211c", "realine;":"\u211b", "realpart;":"\u211c",
	"reals;":"\u211d", "rect;":"\u25ad", "reg":"\u00ae", "reg;":"\u00ae", "rfisht;":"\u297d", "rfloor;":"\u230b", "rfr;":"\ud835\udd2f",
	"rhard;":"\u21c1", "rharu;":"\u21c0", "rharul;":"\u296c", "rho;":"\u03c1", "rhov;":"\u03f1", "rightarrow;":"\u2192",
	"rightarrowtail;":"\u21a3", "rightharpoondown;":"\u21c1", "rightharpoonup;":"\u21c0", "rightleftarrows;":"\u21c4",
	"rightleftharpoons;":"\u21cc", "rightrightarrows;":"\u21c9", "rightsquigarrow;":"\u219d", "rightthreetimes;":"\u22cc", "ring;":"\u02da",
	"risingdotseq;":"\u2253", "rlarr;":"\u21c4", "rlhar;":"\u21cc", "rlm;":"\u200f", "rmoust;":"\u23b1", "rmoustache;":"\u23b1",
	"rnmid;":"\u2aee", "roang;":"\u27ed", "roarr;":"\u21fe", "robrk;":"\u27e7", "ropar;":"\u2986", "ropf;":"\ud835\udd63", "roplus;":"\u2a2e",
	"rotimes;":"\u2a35", "rpar;":")", "rpargt;":"\u2994", "rppolint;":"\u2a12", "rrarr;":"\u21c9", "rsaquo;":"\u203a", "rscr;":"\ud835\udcc7",
	"rsh;":"\u21b1", "rsqb;":"]", "rsquo;":"\u2019", "rsquor;":"\u2019", "rthree;":"\u22cc", "rtimes;":"\u22ca", "rtri;":"\u25b9",
	"rtrie;":"\u22b5", "rtrif;":"\u25b8", "rtriltri;":"\u29ce", "ruluhar;":"\u2968", "rx;":"\u211e", "sacute;":"\u015b", "sbquo;":"\u201a",
	"sc;":"\u227b", "scE;":"\u2ab4", "scap;":"\u2ab8", "scaron;":"\u0161", "sccue;":"\u227d", "sce;":"\u2ab0", "scedil;":"\u015f",
	"scirc;":"\u015d", "scnE;":"\u2ab6", "scnap;":"\u2aba", "scnsim;":"\u22e9", "scpolint;":"\u2a13", "scsim;":"\u227f", "scy;":"\u0441",
	"sdot;":"\u22c5", "sdotb;":"\u22a1", "sdote;":"\u2a66", "seArr;":"\u21d8", "searhk;":"\u2925", "searr;":"\u2198", "searrow;":"\u2198",
	"sect":"\u00a7", "sect;":"\u00a7", "semi;":";", "seswar;":"\u2929", "setminus;":"\u2216", "setmn;":"\u2216", "sext;":"\u2736",
	"sfr;":"\ud835\udd30", "sfrown;":"\u2322", "sharp;":"\u266f", "shchcy;":"\u0449", "shcy;":"\u0448", "shortmid;":"\u2223",
	"shortparallel;":"\u2225", "shy":"\u00ad", "shy;":"\u00ad", "sigma;":"\u03c3", "sigmaf;":"\u03c2", "sigmav;":"\u03c2", "sim;":"\u223c",
	"simdot;":"\u2a6a", "sime;":"\u2243", "simeq;":"\u2243", "simg;":"\u2a9e", "simgE;":"\u2aa0", "siml;":"\u2a9d", "simlE;":"\u2a9f",
	"simne;":"\u2246", "simplus;":"\u2a24", "simrarr;":"\u2972", "slarr;":"\u2190", "smallsetminus;":"\u2216", "smashp;":"\u2a33",
	"smeparsl;":"\u29e4", "smid;":"\u2223", "smile;":"\u2323", "smt;":"\u2aaa", "smte;":"\u2aac", "smtes;":"\u2aac\ufe00", "softcy;":"\u044c",
	"sol;":"/", "solb;":"\u29c4", "solbar;":"\u233f", "sopf;":"\ud835\udd64", "spades;":"\u2660", "spadesuit;":"\u2660", "spar;":"\u2225",
	"sqcap;":"\u2293", "sqcaps;":"\u2293\ufe00", "sqcup;":"\u2294", "sqcups;":"\u2294\ufe00", "sqsub;":"\u228f", "sqsube;":"\u2291",
	"sqsubset;":"\u228f", "sqsubseteq;":"\u2291", "sqsup;":"\u2290", "sqsupe;":"\u2292", "sqsupset;":"\u2290", "sqsupseteq;":"\u2292",
	"squ;":"\u25a1", "square;":"\u25a1", "squarf;":"\u25aa", "squf;":"\u25aa", "srarr;":"\u2192", "sscr;":"\ud835\udcc8", "ssetmn;":"\u2216",
	"ssmile;":"\u2323", "sstarf;":"\u22c6", "star;":"\u2606", "starf;":"\u2605", "straightepsilon;":"\u03f5", "straightphi;":"\u03d5",
	"strns;":"\u00af", "sub;":"\u2282", "subE;":"\u2ac5", "subdot;":"\u2abd", "sube;":"\u2286", "subedot;":"\u2ac3", "submult;":"\u2ac1",
	"subnE;":"\u2acb", "subne;":"\u228a", "subplus;":"\u2abf", "subrarr;":"\u2979", "subset;":"\u2282", "subseteq;":"\u2286",
	"subseteqq;":"\u2ac5", "subsetneq;":"\u228a", "subsetneqq;":"\u2acb", "subsim;":"\u2ac7", "subsub;":"\u2ad5", "subsup;":"\u2ad3",
	"succ;":"\u227b", "succapprox;":"\u2ab8", "succcurlyeq;":"\u227d", "succeq;":"\u2ab0", "succnapprox;":"\u2aba", "succneqq;":"\u2ab6",
	"succnsim;":"\u22e9", "succsim;":"\u227f", "sum;":"\u2211", "sung;":"\u266a", "sup1":"\u00b9", "sup1;":"\u00b9", "sup2":"\u00b2",
	"sup2;":"\u00b2", "sup3":"\u00b3", "sup3;":"\u00b3", "sup;":"\u2283", "supE;":"\u2ac6", "supdot;":"\u2abe", "supdsub;":"\u2ad8",
	"supe;":"\u2287", "supedot;":"\u2ac4", "suphsol;":"\u27c9", "suphsub;":"\u2ad7", "suplarr;":"\u297b", "supmult;":"\u2ac2",
	"supnE;":"\u2acc", "supne;":"\u228b", "supplus;":"\u2ac0", "supset;":"\u2283", "supseteq;":"\u2287", "supseteqq;":"\u2ac6",
	"supsetneq;":"\u228b", "supsetneqq;":"\u2acc", "supsim;":"\u2ac8", "supsub;":"\u2ad4", "supsup;":"\u2ad6", "swArr;":"\u21d9",
	"swarhk;":"\u2926", "swarr;":"\u2199", "swarrow;":"\u2199", "swnwar;":"\u292a", "szlig":"\u00df", "szlig;":"\u00df", "target;":"\u2316",
	"tau;":"\u03c4", "tbrk;":"\u23b4", "tcaron;":"\u0165", "tcedil;":"\u0163", "tcy;":"\u0442", "tdot;":"\u20db", "telrec;":"\u2315",
	"tfr;":"\ud835\udd31", "there4;":"\u2234", "therefore;":"\u2234", "theta;":"\u03b8", "thetasym;":"\u03d1", "thetav;":"\u03d1",
	"thickapprox;":"\u2248", "thicksim;":"\u223c", "thinsp;":"\u2009", "thkap;":"\u2248", "thksim;":"\u223c", "thorn":"\u00fe",
	"thorn;":"\u00fe", "tilde;":"\u02dc", "times":"\u00d7", "times;":"\u00d7", "timesb;":"\u22a0", "timesbar;":"\u2a31", "timesd;":"\u2a30",
	"tint;":"\u222d", "toea;":"\u2928", "top;":"\u22a4", "topbot;":"\u2336", "topcir;":"\u2af1", "topf;":"\ud835\udd65", "topfork;":"\u2ada",
	"tosa;":"\u2929", "tprime;":"\u2034", "trade;":"\u2122", "triangle;":"\u25b5", "triangledown;":"\u25bf", "triangleleft;":"\u25c3",
	"trianglelefteq;":"\u22b4", "triangleq;":"\u225c", "triangleright;":"\u25b9", "trianglerighteq;":"\u22b5", "tridot;":"\u25ec",
	"trie;":"\u225c", "triminus;":"\u2a3a", "triplus;":"\u2a39", "trisb;":"\u29cd", "tritime;":"\u2a3b", "trpezium;":"\u23e2",
	"tscr;":"\ud835\udcc9", "tscy;":"\u0446", "tshcy;":"\u045b", "tstrok;":"\u0167", "twixt;":"\u226c", "twoheadleftarrow;":"\u219e",
	"twoheadrightarrow;":"\u21a0", "uArr;":"\u21d1", "uHar;":"\u2963", "uacute":"\u00fa", "uacute;":"\u00fa", "uarr;":"\u2191",
	"ubrcy;":"\u045e", "ubreve;":"\u016d", "ucirc":"\u00fb", "ucirc;":"\u00fb", "ucy;":"\u0443", "udarr;":"\u21c5", "udblac;":"\u0171",
	"udhar;":"\u296e", "ufisht;":"\u297e", "ufr;":"\ud835\udd32", "ugrave":"\u00f9", "ugrave;":"\u00f9", "uharl;":"\u21bf", "uharr;":"\u21be",
	"uhblk;":"\u2580", "ulcorn;":"\u231c", "ulcorner;":"\u231c", "ulcrop;":"\u230f", "ultri;":"\u25f8", "umacr;":"\u016b", "uml":"\u00a8",
	"uml;":"\u00a8", "uogon;":"\u0173", "uopf;":"\ud835\udd66", "uparrow;":"\u2191", "updownarrow;":"\u2195", "upharpoonleft;":"\u21bf",
	"upharpoonright;":"\u21be", "uplus;":"\u228e", "upsi;":"\u03c5", "upsih;":"\u03d2", "upsilon;":"\u03c5", "upuparrows;":"\u21c8",
	"urcorn;":"\u231d", "urcorner;":"\u231d", "urcrop;":"\u230e", "uring;":"\u016f", "urtri;":"\u25f9", "uscr;":"\ud835\udcca",
	"utdot;":"\u22f0", "utilde;":"\u0169", "utri;":"\u25b5", "utrif;":"\u25b4", "uuarr;":"\u21c8", "uuml":"\u00fc", "uuml;":"\u00fc",
	"uwangle;":"\u29a7", "vArr;":"\u21d5", "vBar;":"\u2ae8", "vBarv;":"\u2ae9", "vDash;":"\u22a8", "vangrt;":"\u299c", "varepsilon;":"\u03f5",
	"varkappa;":"\u03f0", "varnothing;":"\u2205", "varphi;":"\u03d5", "varpi;":"\u03d6", "varpropto;":"\u221d", "varr;":"\u2195",
	"varrho;":"\u03f1", "varsigma;":"\u03c2", "varsubsetneq;":"\u228a\ufe00", "varsubsetneqq;":"\u2acb\ufe00", "varsupsetneq;":"\u228b\ufe00",
	"varsupsetneqq;":"\u2acc\ufe00", "vartheta;":"\u03d1", "vartriangleleft;":"\u22b2", "vartriangleright;":"\u22b3", "vcy;":"\u0432",
	"vdash;":"\u22a2", "vee;":"\u2228", "veebar;":"\u22bb", "veeeq;":"\u225a", "vellip;":"\u22ee", "verbar;":"|", "vert;":"|",
	"vfr;":"\ud835\udd33", "vltri;":"\u22b2", "vnsub;":"\u2282\u20d2", "vnsup;":"\u2283\u20d2", "vopf;":"\ud835\udd67", "vprop;":"\u221d",
	"vrtri;":"\u22b3", "vscr;":"\ud835\udccb", "vsubnE;":"\u2acb\ufe00", "vsubne;":"\u228a\ufe00", "vsupnE;":"\u2acc\ufe00",
	"vsupne;":"\u228b\ufe00", "vzigzag;":"\u299a", "wcirc;":"\u0175", "wedbar;":"\u2a5f", "wedge;":"\u2227", "wedgeq;":"\u2259",
	"weierp;":"\u2118", "wfr;":"\ud835\udd34", "wopf;":"\ud835\udd68", "wp;":"\u2118", "wr;":"\u2240", "wreath;":"\u2240",
	"wscr;":"\ud835\udccc", "xcap;":"\u22c2", "xcirc;":"\u25ef", "xcup;":"\u22c3", "xdtri;":"\u25bd", "xfr;":"\ud835\udd35", "xhArr;":"\u27fa",
	"xharr;":"\u27f7", "xi;":"\u03be", "xlArr;":"\u27f8", "xlarr;":"\u27f5", "xmap;":"\u27fc", "xnis;":"\u22fb", "xodot;":"\u2a00",
	"xopf;":"\ud835\udd69", "xoplus;":"\u2a01", "xotime;":"\u2a02", "xrArr;":"\u27f9", "xrarr;":"\u27f6", "xscr;":"\ud835\udccd",
	"xsqcup;":"\u2a06", "xuplus;":"\u2a04", "xutri;":"\u25b3", "xvee;":"\u22c1", "xwedge;":"\u22c0", "yacute":"\u00fd", "yacute;":"\u00fd",
	"yacy;":"\u044f", "ycirc;":"\u0177", "ycy;":"\u044b", "yen":"\u00a5", "yen;":"\u00a5", "yfr;":"\ud835\udd36", "yicy;":"\u0457",
	"yopf;":"\ud835\udd6a", "yscr;":"\ud835\udcce", "yucy;":"\u044e", "yuml":"\u00ff", "yuml;":"\u00ff", "zacute;":"\u017a",
	"zcaron;":"\u017e", "zcy;":"\u0437", "zdot;":"\u017c", "zeetrf;":"\u2128", "zeta;":"\u03b6", "zfr;":"\ud835\udd37", "zhcy;":"\u0436",
	"zigrarr;":"\u21dd", "zopf;":"\ud835\udd6b", "zscr;":"\ud835\udccf", "zwj;":"\u200d", "zwnj;":"\u200c",
});
const NUMERIC_HTML_C1 = [
	0x20ac, 0x81, 0x201a, 0x192, 0x201e, 0x2026, 0x2020, 0x2021,
	0x2c6, 0x2030, 0x160, 0x2039, 0x152, 0x8d, 0x17d, 0x8f,
	0x90, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
	0x2dc, 0x2122, 0x161, 0x203a, 0x153, 0x9d, 0x17e, 0x178,
];

function decodeHtmlAttribute(raw) {
	if (!raw.includes('&')) return raw;
	return raw.replace(/&(?:#(?:x([0-9a-f]+)|(\d+));?|([a-z][a-z0-9]*;?))/gi,
		(match, hex, decimal, name, offset) => {
			if (name) {
				if (!Object.hasOwn(HTML_NAMED_REFERENCES, name)) return match;
				// 属性中的历史无分号实体后紧接字母、数字或 '=' 时，是普通文本。
				if (!name.endsWith(';') && /[a-z0-9=]/i.test(raw[offset + match.length] || '')) return match;
				return HTML_NAMED_REFERENCES[name];
			}
			const code = hex ? parseInt(hex, 16) : Number(decimal);
			if (!code || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return '\ufffd';
			return String.fromCodePoint(NUMERIC_HTML_C1[code - 0x80] ?? code);
		});
}

// HTMLRewriter 提供原始属性文本；setAttribute 只负责保护引号，不会转义 '&'。
function decodeXmlAttribute(raw) {
	// XML 先规范化原始换行及属性空白，再展开引用；&#9; 等引用不能被折叠成空格。
	return decodeXmlEntities(raw.replace(/\r\n?/g, '\n').replace(/[\t\n]/g, ' '));
}

function getHtmlAttribute(el, name, isXml = false) {
	const raw = el.getAttribute(name);
	// 未解析 DTD 中的自定义实体时，不把它改成 HTML 实体或普通文本。
	if (raw == null || (isXml && hasCustomXmlEntity(raw))) return null;
	return isXml ? decodeXmlAttribute(raw) : decodeHtmlAttribute(raw);
}

// XHTML 的属性值按 XML 规范化，制表符和换行必须写成字符引用才能保留。
function setHtmlAttribute(el, name, value, isXml = false) {
	el.setAttribute(name, isXml ? escapeXmlAttr(value) : escapeHtml(value), isXml);
}

const HANDLERS = {
	a:            { href: 'url', 'xlink:href': 'url', ping: 'ping' },
	area:         { href: 'url', 'xlink:href': 'url', ping: 'ping' },
	link:         { href: 'url', imagesrcset: 'srcset' },
	script:       { src: 'url', href: 'url', 'xlink:href': 'url' },
	img:          { src: 'url', srcset: 'srcset' },
	// HTML 解析器把 SVG 之外的 <image> 当作 <img>，src/srcset 会直接加载。
	image:        { href: 'url', 'xlink:href': 'url', src: 'url', srcset: 'srcset' },
	feimage:      { href: 'url', 'xlink:href': 'url' },
	iframe:       { src: 'url' },
	frame:        { src: 'url' },
	source:       { src: 'url', srcset: 'srcset' },
	video:        { src: 'url', poster: 'url' },
	audio:        { src: 'url' },
	track:        { src: 'url' },
	embed:        { src: 'url' },
	object:       { data: 'url' },
	input:        { src: 'url', formaction: 'url' },
	button:       { formaction: 'url' },
	form:         { action: 'url' },
	use:          { href: 'url', 'xlink:href': 'url' },
	mpath:        { href: 'url', 'xlink:href': 'url' },
	textpath:     { href: 'url', 'xlink:href': 'url' },
	pattern:      { href: 'url', 'xlink:href': 'url' },
	filter:       { href: 'url', 'xlink:href': 'url' },
	lineargradient: { href: 'url', 'xlink:href': 'url' },
	radialgradient: { href: 'url', 'xlink:href': 'url' },
};
const HANDLER_ENTRIES = Object.entries(HANDLERS).map(([tag, attrs]) => [tag, Object.entries(attrs)]);

/** raw-text 元素需要跨分片改写，但不能让单个 style/module 耗尽 Worker 内存。 */
function bufferedTextHandler(rewrite, matches = () => true) {
	let parts = [];
	let bytes = 0;
	let active = false;
	let mode = null;
	const encoder = new TextEncoder();
	return {
		element(el) {
			parts = []; bytes = 0;
			mode = matches(el);
			active = Boolean(mode);
		},
		text(chunk) {
			if (!active) return;
			bytes += encoder.encode(chunk.text).byteLength;
			if (bytes > MAX_TRANSFORM_BYTES) {
				// 响应头可能已经发出；此处抛错会留下带 200 状态的截断页面。
				// 尚未输出任何改写正文，恢复已缓冲的原文并流式透传本元素余下部分。
				chunk.replace(parts.join('') + chunk.text, { html: true });
				parts = []; bytes = 0; active = false; mode = null;
				return;
			}
			parts.push(chunk.text);
			if (chunk.lastInTextNode) {
				const raw = parts.join('');
				parts = []; bytes = 0;
				let out = raw;
				try { out = rewrite(raw, mode); } catch {}
				// script/style 是 raw-text，不能把 & 等字符实体转义。
				chunk.replace(out, { html: true });
			} else chunk.remove();
		},
	};
}

function transformHtml(response, baseUrl, workerOrigin, ck) {
	const rewriter = new HTMLRewriter();
	const isXml = mimeType(response.headers.get('Content-Type')) === 'application/xhtml+xml';
	const rawText = (text, transform) => isXml ? rewriteXmlText(text, transform) : transform(text);
	let baseHref = baseUrl;
	let sawBaseHref = false;
	let hasBaseHref = false;
	let sawRoot = false;
	let templateDepth = 0;
	const htmlNamespace = 'http://www.w3.org/1999/xhtml';
	let injected = false;
	const shim = getShimScript(workerOrigin, ck ? ck.ns : '', isXml);
	const rw = (v) => rewriteUrl(v, baseHref, workerOrigin);

	// 注入运行时 shim（head 优先，无 head 则 body 兜底）
	rewriter.on('head', {
		element(el) {
			if (!injected && !templateDepth && el.namespaceURI === htmlNamespace) {
				injected = true;
				el.prepend(shim, { html: true });
			}
		},
	});
	rewriter.on('body', {
		element(el) {
			if (!injected && !templateDepth && el.namespaceURI === htmlNamespace) {
				injected = true;
				el.prepend(shim, { html: true });
			}
		},
	});

	// template 内容不是活动文档的一部分；嵌套模板也不能改变文档基地址。
	rewriter.on('template', {
		element(el) {
			if (el.namespaceURI !== htmlNamespace) return;
			templateDepth++;
			el.onEndTag(() => { templateDepth--; });
		},
	});

	// HTML 规范以活动文档内第一个带 href 的 base 冻结基地址；无效或非 HTTP(S) 回退文档原地址，不顺延后续 base。
	rewriter.on('base', {
		element(el) {
			if (templateDepth || el.namespaceURI !== htmlNamespace) return;
			if (el.hasAttribute('href')) {
				const h = getHtmlAttribute(el, 'href', isXml);
				let nextBase = '';
				if (h != null) {
					try {
						const u = new URL(h, baseUrl);
						if (u.protocol === 'http:' || u.protocol === 'https:') nextBase = u.href;
					} catch {}
				}
				if (!sawBaseHref) {
					sawBaseHref = true;
					if (nextBase) {
						hasBaseHref = true;
						baseHref = nextBase;
					}
				}
				setHtmlAttribute(el, 'data-pe-base', nextBase, isXml);
				el.removeAttribute('href');
			} else {
				el.removeAttribute('data-pe-base');
			}
		},
	});

	// CSP/Set-Cookie/X-Frame-Options/referrer meta 标签直接移除；refresh meta 重写目标；charset meta 对齐为 UTF-8
	rewriter.on('meta', {
		element(el) {
			const he = (getHtmlAttribute(el, 'http-equiv', isXml) || '').trim().toLowerCase();
			const name = (getHtmlAttribute(el, 'name', isXml) || '').trim().toLowerCase();
			if (he === 'content-security-policy' || he === 'content-security-policy-report-only' ||
				he === 'set-cookie' || he === 'x-frame-options' || name === 'referrer') {
				el.remove();
				return;
			}
			if (he === 'refresh') {
				const c = getHtmlAttribute(el, 'content', isXml);
				if (c) setHtmlAttribute(el, 'content', rewriteRefreshContent(c, baseHref, workerOrigin), isXml);
			}
			if (he === 'content-type') {
				const c = getHtmlAttribute(el, 'content', isXml);
				if (c) setHtmlAttribute(el, 'content', c.replace(/charset\s*=\s*[^;]*/gi, 'charset=UTF-8'), isXml);
			}
			if (getHtmlAttribute(el, 'charset', isXml) != null) {
				setHtmlAttribute(el, 'charset', 'UTF-8', isXml);
			}
		},
	});

	// 对 style、内联 ES module、importmap 与 speculationrules 使用同一个有界缓冲器；其它脚本原样保留。
	rewriter.on('style', bufferedTextHandler(css => rawText(css, part => rewriteCss(part, baseHref, workerOrigin))));
	rewriter.on('script', bufferedTextHandler(
		(text, kind) => rawText(text, part => kind === 'importmap'
			? rewriteImportMap(part, baseHref, workerOrigin)
			: kind === 'speculationrules'
				? rewriteSpeculationRules(part, baseHref, workerOrigin, baseUrl)
				: rewriteJsModuleSpecifiers(part, baseHref, workerOrigin)),
		el => {
			if (el.hasAttribute('src') || el.hasAttribute('href') || el.hasAttribute('xlink:href')) return null;
			const type = (getHtmlAttribute(el, 'type', isXml) || '').trim().toLowerCase();
			return type === 'module' || type === 'importmap' || type === 'speculationrules' ? type : null;
		}
	));

	// 具体标签的 URL 属性
	for (const [tag, attrs] of HANDLER_ENTRIES) {
		rewriter.on(tag, {
			element(el) {
				// 内容被我们改写过的资源必须去掉 SRI，否则哈希校验失败被浏览器拦截
				if (tag === 'script' || tag === 'link') el.removeAttribute('integrity');
				for (const [attr, kind] of attrs) {
					const v = getHtmlAttribute(el, attr, isXml);
					if (v == null) continue;
					let next;
					if (kind === 'srcset') {
						next = rewriteSrcset(v, baseHref, workerOrigin);
					} else if (kind === 'ping') {
						next = rewritePing(v, baseHref, workerOrigin);
					} else {
						const trimmed = trimUrlSpace(v);
						const isFormAction = attr === 'action' || attr === 'formaction';
						const isAnchor = (tag === 'a' || tag === 'area') && (attr === 'href' || attr === 'xlink:href');
						// 缺省或空的 form action 始终使用文档地址，不使用 <base>。
						if (!trimmed && isFormAction) continue;
						if (hasBaseHref && (isAnchor || isFormAction) && (trimmed === '' || trimmed.startsWith('#'))) {
							next = rw(new URL(trimmed, baseHref).href);
						} else next = rw(v);
					}
					// 页内锚点、javascript:/mailto:/data: 等不变的值无需跨运行时回写（与通配处理器一致）。
					if (next !== v) setHtmlAttribute(el, attr, next, isXml);
				}
				// script 标签上的内联 srcset 不存在；但懒加载属性可能出现在任意标签上（下面统一处理）
			},
		});
	}

	const BG_TAGS = new Set(['body', 'table', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th']);
	const SVG_URL_ATTRS = new Set([
		'fill', 'stroke', 'filter', 'clip-path', 'mask',
		'marker', 'marker-start', 'marker-mid', 'marker-end', 'cursor',
	]);

	// 通配：style 属性、表格/页面 background、SVG url() 表现属性、懒加载 data-* 属性
	rewriter.on('*', {
		element(el) {
			// 兜底注入：源文档既没有 <head> 也没有 <body> 起始标签时
			// （XHR 拉回的 HTML 片段、<frameset> 老页面等），上面的两个 handler
			// 都不会触发，shim 就丢了。这里插到文档第一个非容器元素之前，
			// 保证它仍然先于页面自身脚本执行。
			const isRoot = !sawRoot;
			sawRoot = true;
			const tag = (el.tagName || '').toLowerCase();
			if (!injected && !templateDepth && !(isXml && isRoot) && tag !== 'html' && tag !== 'head' && tag !== 'body') {
				injected = true;
				el.before(shim, { html: true });
			}

			// 只遍历元素实际携带的属性：逐个 getAttribute 探测 40 多个候选名，意味着每个元素 40 多次跨运行时调用，
			// 而绝大多数元素一个都没有。改写推迟到遍历结束后再写回，避免在迭代过程中修改属性表。
			let handled = null;
			let updates = null;
			for (const [rawName, rawValue] of el.attributes) {
				const attr = rawName.toLowerCase();
				const isSvgUrl = SVG_URL_ATTRS.has(attr);
				if (attr !== 'style' && attr !== 'background' && !isSvgUrl && !LAZY_ATTRS.has(attr)) continue;
				// 重复属性以第一个为准（与浏览器和 getAttribute 一致）
				if (handled && handled.includes(attr)) continue;
				(handled || (handled = [])).push(attr);
				if (!rawValue) continue;
				if (isXml && hasCustomXmlEntity(rawValue)) continue;
				const v = isXml ? decodeXmlAttribute(rawValue) : decodeHtmlAttribute(rawValue);
				let next = v;
				if (attr === 'style') {
					next = rewriteStyleAttr(v, baseHref, workerOrigin);
				} else if (attr === 'background') {
					if (BG_TAGS.has(tag)) next = rw(v);
				} else if (isSvgUrl) {
					next = rewriteStyleAttr(v, baseHref, workerOrigin);
				} else {
					next = rewriteLazyValue(attr, v, baseHref, workerOrigin);
				}
				if (next !== v) (updates || (updates = [])).push([attr, next]);
			}
			if (updates) for (const [attr, next] of updates) setHtmlAttribute(el, attr, next, isXml);
		},
	});

	const out = rewriter.transform(response);
	// HTMLRewriter 输出统一为 UTF-8
	const ct = (out.headers.get('content-type') || 'text/html').split(';')[0].trim();
	out.headers.set('content-type', (ct || 'text/html') + '; charset=UTF-8');
	return out;
}

// ============================================================
// CSS / JS / SVG / JSON / Manifest 文本重写（整体缓冲）
// ============================================================

// CSS Syntax §3.2 指定字节签名而非一般 at-rule；含终止符最多 1024 字节。
const CSS_CHARSET_SIGNATURE = /^@charset "([\x00-\x21\x23-\x7f]{0,1012})";/;

/** 整体缓冲文本的编码：BOM > HTTP charset > CSS @charset 或 XML 声明，默认 UTF-8。 */
function sniffTextCharset(bytes, kind, declaredCharset = null) {
	const head = bytes.subarray(0, kind === 'css' ? 1024 : kind === 'svg' ? 4096 : 256);
	if (head[0] === 0xff && head[1] === 0xfe) return 'utf-16le';
	if (head[0] === 0xfe && head[1] === 0xff) return 'utf-16be';
	if (head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf) return 'utf-8';
	if (declaredCharset) return declaredCharset;
	if (kind === 'css') {
		const m = CSS_CHARSET_SIGNATURE.exec(new TextDecoder().decode(head));
		const label = m && normalizeCharsetLabel(m[1]);
		if (label && !/^utf-16(?:le|be)$/.test(label)) return label;
	}
	if (kind === 'svg') {
		return utf16XmlSignature(head) || xmlDeclaredCharset(new TextDecoder().decode(head)) || 'utf-8';
	}
	return 'utf-8';
}

function replayBody(reader, prefix, tail) {
	let stopped = false;
	return new ReadableStream({
		start(controller) {
			if (prefix.byteLength) controller.enqueue(prefix);
			controller.enqueue(tail);
		},
		async pull(controller) {
			try {
				const { done, value } = await reader.read();
				if (stopped) return;
				if (!done) controller.enqueue(value);
				else {
					reader.releaseLock();
					controller.close();
				}
			} catch (error) {
				if (!stopped) reader.releaseLock();
				throw error;
			}
		},
		async cancel(reason) {
			stopped = true;
			try { await reader.cancel(reason); } finally { reader.releaseLock(); }
		},
	});
}

/**
 * 限制整体缓冲的原始输入字节量；不信任 Content-Length（可缺失/虚报）。
 * 超过 2 MiB 上限时把已读分片与剩余流无缝拼接，原样透传正文及其表示元数据。
 */
async function readTransformText(body, kind = '', declaredCharset = null) {
	if (!body) return { text: '', passthrough: null };
	const reader = body.getReader();
	let buffer = new Uint8Array(0);
	let size = 0;
	let handedOff = false;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			if (!value.byteLength) continue;
			const nextSize = size + value.byteLength;
			if (nextSize > MAX_TRANSFORM_BYTES) {
				const passthrough = replayBody(reader, buffer.subarray(0, size), value);
				handedOff = true;
				return { text: null, passthrough };
			}
			if (nextSize > buffer.length) {
				// 分片数不影响内存上限：小分片合入容量倍增的单个缓冲区。
				const next = new Uint8Array(Math.min(MAX_TRANSFORM_BYTES, Math.max(4096, buffer.length * 2, nextSize)));
				next.set(buffer.subarray(0, size));
				buffer = next;
			}
			buffer.set(value, size);
			size = nextSize;
		}
		const bytes = buffer.subarray(0, size);
		return { text: new TextDecoder(sniffTextCharset(bytes, kind, declaredCharset)).decode(bytes), passthrough: null };
	} catch (error) {
		reader.cancel(error).catch(() => {});
		throw error;
	} finally {
		if (!handedOff) reader.releaseLock();
	}
}

async function transformText(response, baseUrl, workerOrigin, kind, request, declaredCharset = null) {
	const charset = declaredCharset || getCharset(response.headers.get('content-type'));
	const { text: rawText, passthrough } = await readTransformText(response.body, kind, charset);
	let bodyOut = passthrough;
	if (bodyOut === null) {
		let text = rawText;
		try {
			if (kind === 'css') {
				text = rewriteCss(text, baseUrl, workerOrigin).replace(CSS_CHARSET_SIGNATURE, '@charset "UTF-8";');
			} else if (kind === 'js') {
				text = rewriteJsModuleSpecifiers(text, baseUrl, workerOrigin);
			} else if (kind === 'svg') {
				text = rewriteSvg(text, baseUrl, workerOrigin);
			} else if (kind === 'json' || kind === 'manifest') {
				text = rewriteJsonUrls(text, baseUrl, workerOrigin);
			}
		} catch { /* 重写失败则回退原文 */ }
		bodyOut = text;
	}

	const resp = new Response(bodyOut, response);
	stripResponseHeaders(resp.headers, request, baseUrl);
	if (passthrough === null) {
		stripTransformedHeaders(resp.headers);
		const ct = (response.headers.get('content-type') || '').split(';')[0].trim();
		resp.headers.set('content-type', (ct || 'text/plain') + '; charset=UTF-8');
	} else if (contentCoding(response.headers) !== 'identity') {
		// 已读取的是解压后的流；重新压缩不保证得到同样的上游字节。
		for (const name of REPRESENTATION_HEADERS) resp.headers.delete(name);
	}
	return resp;
}

// BEGIN VENDORED ES MODULE LEXER
/*
MIT License
-----------

Copyright (C) 2018-2022 Guy Bedford

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
const parseModuleImports = (() => {
/* es-module-lexer (minimal) 3.0.3 */
let e,a,r,i=2<<19;const s=1===new Uint8Array(new Uint16Array([1]).buffer)[0]?function(e,a){const r=e.length;let i=0;for(;i<r;)a[i]=e.charCodeAt(i++)}:function(e,a){const r=e.length;let i=0;for(;i<r;){const r=e.charCodeAt(i);a[i++]=(255&r)<<8|r>>>8}},f="xportportlassrometavoyiedeleinstantyreturdebuggeawaithrwhileforifcatcfinallelsbreacontinsyncunctionourceefer;";let c,t,b;const init=()=>Promise.resolve();function parse(k,l="@"){c=k,t=l;const o=Math.max(2<<17,2*c.length),h=2*c.length+o+(2<<17);if(h>i||!e){for(;h>i;)i*=2;a=new ArrayBuffer(i),s(f,new Uint16Array(a,16,109)),e=function(e,a,r){"use asm";var i=new e.Int8Array(r),s=new e.Int16Array(r),f=new e.Int32Array(r),c=new e.Uint8Array(r),t=new e.Uint16Array(r),b=1056;function k(e,a){e=e|0;a=a|0;var r=0,c=0,t=0,b=0,k=0,n=0,o=0,w=0,C=0,y=0,x=0,m=0,S=0;y=s[409]|0;a=f[77]|0;f[74]=a;w=a;n=y;C=0;e:while(1){c=f[78]|0;b=n<<16>>16==y<<16>>16;t=C&e;k=a;while(1){r=k+2|0;if(k>>>0>=c>>>0){a=0;o=111;break e}a=s[r>>1]|0;if(!(L(a)|0)){if(b){switch(a<<16>>16){case 125:case 93:case 41:case 59:case 44:{o=111;break e}default:{}}if(t?se(a)|0:0){o=111;break e}}if(!(se(a)|0))break}k=r}f[77]=r;a:do{switch(a<<16>>16){case 101:{if((n<<16>>16==0?Q(r)|0:0)?(I(k+4|0,16,10)|0)==0:0){u()|0;o=101}else o=98;break}case 105:{if(((s[k+4>>1]|0)==109?Q(r)|0:0)?(I(k+6|0,26,8)|0)==0:0){l();o=101}else o=98;break}case 99:{if((((s[k+4>>1]|0)==108?Q(r)|0:0)?(I(k+6|0,36,6)|0)==0:0)?K(s[k+12>>1]|0)|0:0){i[822]=1;o=98}else o=98;break}case 40:if(n<<16>>16==1024){ee();break a}else{o=n&65535;k=f[75]|0;f[k+(o<<3)>>2]=1;s[409]=n+1<<16>>16;f[k+(o<<3)+4>>2]=w;o=101;break a}case 91:if(n<<16>>16==1024){ee();break a}else{o=n&65535;k=f[75]|0;f[k+(o<<3)>>2]=8;s[409]=n+1<<16>>16;f[k+(o<<3)+4>>2]=w;o=101;break a}case 93:if(!(n<<16>>16)){ee();break a}else{s[409]=n+-1<<16>>16;o=101;break a}case 44:{r=s[408]|0;if((!(n<<16>>16==0|r<<16>>16==0)?(f[(f[75]|0)+((n&65535)+-1<<3)>>2]|0)==5:0)?(x=f[(f[76]|0)+((r&65535)+-1<<2)>>2]|0,(f[x+4>>2]|0)==0):0){f[x+4>>2]=w+2;f[77]=k+4;v(1)|0;o=f[77]|0;f[x+16>>2]=o;f[77]=o+-2;o=101}else o=101;break}case 59:{o=101;break}case 41:{if(!(n<<16>>16)){ee();break a}o=n+-1<<16>>16;s[409]=o;r=s[408]|0;if(r<<16>>16!=0?(f[(f[75]|0)+((o&65535)<<3)>>2]|0)==5:0){c=f[(f[76]|0)+((r&65535)+-1<<2)>>2]|0;if(!(f[c+4>>2]|0))f[c+4>>2]=w+2;f[c+12>>2]=k+4;s[408]=r+-1<<16>>16;o=101}else o=101;break}case 123:{k=f[68]|0;do{if((s[w>>1]|0)==41&(k|0)!=0?(f[k+12>>2]|0)==(w+2|0):0){r=f[69]|0;f[68]=r;if(!r){f[64]=0;break}else{f[r+32>>2]=0;break}}}while(0);if(n<<16>>16==1024){ee();break a}else{o=n&65535;k=f[75]|0;f[k+(o<<3)>>2]=(i[822]|0)==0?2:6;s[409]=n+1<<16>>16;f[k+(o<<3)+4>>2]=w;i[822]=0;o=101;break a}}case 125:{if(!(n<<16>>16)){ee();break a}k=f[75]|0;o=n+-1<<16>>16;s[409]=o;if((f[k+((o&65535)<<3)>>2]|0)==4){d();o=101}else o=101;break}case 34:case 39:{A(a);o=101;break}case 47:switch(s[k+4>>1]|0){case 47:{D();break a}case 42:{g(1);break a}default:{c=s[w>>1]|0;r:do{if(!($(c)|0)){if(!(c<<16>>16==41?J(f[(f[75]|0)+((n&65535)<<3)+4>>2]|0)|0:0))o=68}else switch(c<<16>>16){case 46:if(((s[w+-2>>1]|0)+-48&65535)<10){o=68;break r}else break r;case 43:if((s[w+-2>>1]|0)==43){o=68;break r}else break r;case 45:if((s[w+-2>>1]|0)==45){o=68;break r}else break r;default:break r}}while(0);r:do{if((o|0)==68){o=0;if(n<<16>>16!=0?(m=f[75]|0,S=(n&65535)+-1|0,c<<16>>16==102?(f[m+(S<<3)>>2]|0)==1:0):0){if(((s[w+-2>>1]|0)==111?p(w+-4|0)|0:0)?j(f[m+(S<<3)+4>>2]|0,136,3)|0:0)break}else o=73;if((o|0)==73?(0,c<<16>>16==125):0){t=f[75]|0;r=n&65535;if(O(f[t+(r<<3)+4>>2]|0)|0)break;if((f[t+(r<<3)>>2]|0)==6)break}if(!(h(w)|0)){switch(c<<16>>16){case 0:break r;case 47:{if(i[821]|0)break r;break}default:{}}o=f[70]|0;if((o|0?w>>>0>=(f[o>>2]|0)>>>0:0)?w>>>0<=(f[o+4>>2]|0)>>>0:0){U();i[821]=0;o=101;break a}t=f[60]|0;r=w;do{if(r>>>0<=t>>>0)break;r=r+-2|0;f[74]=r;c=s[r>>1]|0}while(!(z(c)|0));if(L(c)|0){do{if(r>>>0<=t>>>0)break;r=r+-2|0;f[74]=r}while(L(s[r>>1]|0)|0);if(M(r)|0){U();i[821]=0;o=101;break a}}i[821]=1;o=101;break a}}}while(0);U();i[821]=0;o=101;break a}}case 96:if(n<<16>>16==1024){ee();break a}else{o=n&65535;k=f[75]|0;f[k+(o<<3)>>2]=3;s[409]=n+1<<16>>16;f[k+(o<<3)+4>>2]=w;d();o=101;break a}default:if((a&65535)>127&a<<16>>16!=160|(a<<16>>16==92|(a<<16>>16==95|(a<<16>>16==36|((a+-48&65535)<10|((a|32)+-97&65535)<26)))))o=98;else o=101}}while(0);a:do{if((o|0)==98)while(1){r=r+2|0;o=s[r>>1]|0;if(!((o&65535)>127&o<<16>>16!=160|(o<<16>>16==92|(o<<16>>16==95|(o<<16>>16==36|((o+-48&65535)<10|((o|32)+-97&65535)<26)))))){o=101;break a}f[77]=r}}while(0);if((o|0)==101){o=0;f[74]=f[77]}if(i[820]|0){a=0;break}c=f[74]|0;if((c|0)==(w|0)){a=s[409]|0;if(C&(a<<16>>16==y<<16>>16&e)){a=s[f[77]>>1]|0;if(se(a)|0)break;else{a=y;r=1}}else r=C}else{if(a<<16>>16==47)r=(i[821]^1)&255;else r=(a<<16>>16==96|(a<<16>>16==34|(a<<16>>16==39|((a|32)<<16>>16==125|(a<<16>>16==41|(F(a)|0))))))&1;a=s[409]|0;r=(r|0)!=0}w=c;n=a;C=r;a=f[77]|0}if((o|0)==111)f[77]=r;return a|0}function n(){var e=0,a=0,r=0,c=0,t=0,k=0,n=0,o=0,w=0;w=b;b=b+10240|0;s[408]=0;s[409]=0;f[74]=232;i[821]=0;f[73]=0;i[820]=0;f[75]=w+2048;f[76]=w;i[822]=0;r=(f[60]|0)+-2|0;f[77]=r;a=r+(f[71]<<1)|0;f[78]=a;e:while(1){e=r+2|0;f[77]=e;if(r>>>0>=a>>>0){c=97;break}a=s[e>>1]|0;a:do{switch(a<<16>>16){case 9:case 10:case 11:case 12:case 13:case 32:break;case 101:{if(((s[409]|0)==0?Q(e)|0:0)?(I(r+4|0,16,10)|0)==0:0){u()|0;c=96}else c=93;break}case 105:{if(((s[r+4>>1]|0)==109?Q(e)|0:0)?(I(r+6|0,26,8)|0)==0:0){l();c=96}else c=93;break}case 99:{if((((s[r+4>>1]|0)==108?Q(e)|0:0)?(I(r+6|0,36,6)|0)==0:0)?K(s[r+12>>1]|0)|0:0){i[822]=1;c=93}else c=93;break}case 40:{e=s[409]|0;if(e<<16>>16==1024){c=20;break e}r=f[74]|0;c=f[75]|0;f[c+((e&65535)<<3)>>2]=1;s[409]=e+1<<16>>16;f[c+((e&65535)<<3)+4>>2]=r;c=96;break}case 91:{e=s[409]|0;if(e<<16>>16==1024){c=23;break e}r=f[74]|0;c=f[75]|0;f[c+((e&65535)<<3)>>2]=8;s[409]=e+1<<16>>16;f[c+((e&65535)<<3)+4>>2]=r;c=96;break}case 93:{e=s[409]|0;if(!(e<<16>>16)){c=25;break e}s[409]=e+-1<<16>>16;c=96;break}case 44:{e=s[408]|0;if(((e<<16>>16!=0?(t=s[409]|0,t<<16>>16!=0):0)?(f[(f[75]|0)+((t&65535)+-1<<3)>>2]|0)==5:0)?(k=f[(f[76]|0)+((e&65535)+-1<<2)>>2]|0,(f[k+4>>2]|0)==0):0){f[k+4>>2]=(f[74]|0)+2;f[77]=r+4;v(1)|0;c=f[77]|0;f[k+16>>2]=c;f[77]=c+-2;c=96}else c=96;break}case 59:{c=96;break}case 41:{e=s[409]|0;if(!(e<<16>>16)){c=33;break e}s[409]=e+-1<<16>>16;a=s[408]|0;if(a<<16>>16!=0?(f[(f[75]|0)+((e+-1&65535)<<3)>>2]|0)==5:0){e=f[(f[76]|0)+((a&65535)+-1<<2)>>2]|0;if(!(f[e+4>>2]|0))f[e+4>>2]=(f[74]|0)+2;f[e+12>>2]=r+4;s[408]=a+-1<<16>>16;c=96}else c=96;break}case 123:{a=f[74]|0;c=f[68]|0;do{if((s[a>>1]|0)==41&(c|0)!=0?(f[c+12>>2]|0)==(a+2|0):0){e=f[69]|0;f[68]=e;if(!e){f[64]=0;break}else{f[e+32>>2]=0;break}}}while(0);e=s[409]|0;if(e<<16>>16==1024){c=45;break e}c=f[75]|0;f[c+((e&65535)<<3)>>2]=(i[822]|0)==0?2:6;s[409]=e+1<<16>>16;f[c+((e&65535)<<3)+4>>2]=a;i[822]=0;c=96;break}case 125:{e=s[409]|0;if(!(e<<16>>16)){c=48;break e}c=f[75]|0;s[409]=e+-1<<16>>16;if((f[c+((e+-1&65535)<<3)>>2]|0)==4){d();c=96}else c=96;break}case 34:case 39:{A(a);c=96;break}case 47:switch(s[r+4>>1]|0){case 47:{D();break a}case 42:{g(1);break a}default:{e=f[74]|0;a=s[e>>1]|0;r:do{if(!($(a)|0))if(a<<16>>16==41){r=s[409]|0;if(!(J(f[(f[75]|0)+((r&65535)<<3)+4>>2]|0)|0))c=63}else c=62;else switch(a<<16>>16){case 46:if(((s[e+-2>>1]|0)+-48&65535)<10){c=62;break r}else break r;case 43:if((s[e+-2>>1]|0)==43){c=62;break r}else break r;case 45:if((s[e+-2>>1]|0)==45){c=62;break r}else break r;default:break r}}while(0);if((c|0)==62){r=s[409]|0;c=63}r:do{if((c|0)==63){c=0;if(r<<16>>16!=0?(n=f[75]|0,o=(r&65535)+-1|0,a<<16>>16==102?(f[n+(o<<3)>>2]|0)==1:0):0){if(((s[e+-2>>1]|0)==111?p(e+-4|0)|0:0)?j(f[n+(o<<3)+4>>2]|0,136,3)|0:0)break}else c=68;if((c|0)==68?(0,a<<16>>16==125):0){c=f[75]|0;r=r&65535;if(O(f[c+(r<<3)+4>>2]|0)|0)break;if((f[c+(r<<3)>>2]|0)==6)break}if(!(h(e)|0)){switch(a<<16>>16){case 0:break r;case 47:{if(i[821]|0)break r;break}default:{}}c=f[70]|0;if((c|0?e>>>0>=(f[c>>2]|0)>>>0:0)?e>>>0<=(f[c+4>>2]|0)>>>0:0){U();i[821]=0;c=96;break a}r=f[60]|0;do{if(e>>>0<=r>>>0)break;e=e+-2|0;f[74]=e;a=s[e>>1]|0}while(!(z(a)|0));if(L(a)|0){do{if(e>>>0<=r>>>0)break;e=e+-2|0;f[74]=e}while(L(s[e>>1]|0)|0);if(M(e)|0){U();i[821]=0;c=96;break a}}i[821]=1;c=96;break a}}}while(0);U();i[821]=0;c=96;break a}}case 96:{e=s[409]|0;if(e<<16>>16==1024){c=90;break e}r=f[74]|0;c=f[75]|0;f[c+((e&65535)<<3)>>2]=3;s[409]=e+1<<16>>16;f[c+((e&65535)<<3)+4>>2]=r;d();c=96;break}default:if((a&65535)>127&a<<16>>16!=160|(a<<16>>16==92|(a<<16>>16==95|(a<<16>>16==36|((a+-48&65535)<10|((a|32)+-97&65535)<26)))))c=93;else c=96}}while(0);a:do{if((c|0)==93)while(1){e=e+2|0;c=s[e>>1]|0;if(!((c&65535)>127&c<<16>>16!=160|(c<<16>>16==92|(c<<16>>16==95|(c<<16>>16==36|((c+-48&65535)<10|((c|32)+-97&65535)<26)))))){c=96;break a}f[77]=e}}while(0);if((c|0)==96){c=0;f[74]=f[77]}r=f[77]|0;a=f[78]|0}if((c|0)==20){ee();e=0}else if((c|0)==23){ee();e=0}else if((c|0)==25){ee();e=0}else if((c|0)==33){ee();e=0}else if((c|0)==45){ee();e=0}else if((c|0)==48){ee();e=0}else if((c|0)==90){ee();e=0}else if((c|0)==97)e=(i[820]|0)==0?(s[408]|s[409])<<16>>16==0:0;b=w;return e|0}function l(){var e=0,a=0,r=0,c=0,t=0,b=0;b=f[77]|0;f[77]=b+12;e=v(1)|0;r=f[77]|0;e:do{if(e<<16>>16!=46){if(!(e<<16>>16==115&r>>>0>(b+12|0)>>>0)){if(!(e<<16>>16==100&r>>>0>(b+10|0)>>>0)){a=e;c=0;t=28;break}if(I(r+2|0,224,8)|0){e=r;a=100;r=0;t=66;break}if(!(K(s[r+10>>1]|0)|0)){e=r;a=100;r=0;t=66;break}f[77]=r+10;if((v(1)|0)<<16>>16==42){a=42;c=2;t=68;break}f[77]=r;a=s[r>>1]|0;c=0;t=28;break}if((I(r+2|0,214,10)|0)==0?K(s[r+12>>1]|0)|0:0){f[77]=r+12;a=v(1)|0;e=f[77]|0;if(!(a<<16>>16==44|(e|0)==(r+12|0))){if(a<<16>>16!=102){c=1;t=28;break}if(I(e+2|0,42,6)|0){a=102;r=1;t=66;break}if(!(z(s[e+8>>1]|0)|0)){a=102;r=1;t=66;break}}f[77]=r;a=s[r>>1]|0;c=0;t=28}else{e=r;a=115;r=0;t=66}}else{f[77]=r+2;switch((v(1)|0)<<16>>16){case 109:{e=f[77]|0;if(I(e+2|0,48,6)|0)break e;a=f[74]|0;if(!(N(a)|0)?(s[a>>1]|0)==46:0)break e;C(b,b,e+8|0,2);break e}case 115:{e=f[77]|0;if(I(e+2|0,214,10)|0)break e;a=f[74]|0;if(!(N(a)|0)?(s[a>>1]|0)==46:0)break e;f[77]=e+12;a=v(1)|0;c=1;t=28;break e}case 100:{e=f[77]|0;if(I(e+2|0,224,8)|0)break e;a=f[74]|0;if(!(N(a)|0)?(s[a>>1]|0)==46:0)break e;f[77]=e+10;a=v(1)|0;c=2;t=28;break e}default:break e}}}while(0);e:do{if((t|0)==28){if(a<<16>>16!=40){if(!((c|0)==0&a<<16>>16==123)){switch(a<<16>>16){case 42:case 39:case 34:{t=68;break e}default:{}}e=f[77]|0;r=c;t=66;break}e=f[77]|0;if(s[409]|0){f[77]=e+-2;break}while(1){if(e>>>0>=(f[78]|0)>>>0)break;e=v(1)|0;if(!(ae(e)|0)){if(e<<16>>16==125){t=56;break}}else A(e);e=(f[77]|0)+2|0;f[77]=e}if((t|0)==56)f[77]=(f[77]|0)+2;c=(v(1)|0)<<16>>16==102;e=f[77]|0;if(c?I(e+2|0,42,6)|0:0){ee();break}f[77]=e+8;e=v(1)|0;if(ae(e)|0){w(b,e,0);break}else{ee();break}}e=s[409]|0;if(e<<16>>16==1024){ee();break}a=f[77]|0;r=f[75]|0;f[r+((e&65535)<<3)>>2]=5;s[409]=e+1<<16>>16;f[r+((e&65535)<<3)+4>>2]=a;if((s[f[74]>>1]|0)!=46){if((s[408]|0)==512){ee();break}f[77]=a+2;r=v(1)|0;C(b,f[77]|0,0,a);if(!c)e=f[68]|0;else{e=f[68]|0;f[e+28>>2]=(c|0)==1?5:7}c=f[76]|0;b=s[408]|0;s[408]=b+1<<16>>16;f[c+((b&65535)<<2)>>2]=e;switch(r<<16>>16){case 39:{A(39);break}case 34:{A(34);break}case 96:{if(x()|0){if(i[823]|0){b=(f[68]|0)+24|0;i[b>>0]=i[b>>0]|2}}else t=43;break}default:t=43}if((t|0)==43){f[77]=(f[77]|0)+-2;break}e=(f[77]|0)+2|0;f[77]=e;switch((v(1)|0)<<16>>16){case 44:{f[77]=(f[77]|0)+2;v(1)|0;c=f[68]|0;f[c+4>>2]=e;b=f[77]|0;f[c+16>>2]=b;i[c+24>>0]=i[c+24>>0]|1;f[77]=b+-2;break e}case 41:{s[409]=(s[409]|0)+-1<<16>>16;b=f[68]|0;f[b+4>>2]=e;f[b+12>>2]=(f[77]|0)+2;i[b+24>>0]=i[b+24>>0]|1;s[408]=(s[408]|0)+-1<<16>>16;break e}default:{f[77]=(f[77]|0)+-2;break e}}}}}while(0);if((t|0)==66)if((e|0)==(b+12|0))f[77]=b+10;else{c=r;t=68}do{if((t|0)==68){if(!((a<<16>>16==42|(c|0)!=2)&(s[409]|0)==0)){f[77]=(f[77]|0)+-2;break}e=f[78]|0;a=f[77]|0;while(1){if(a>>>0>=e>>>0){t=75;break}r=s[a>>1]|0;if(ae(r)|0){t=73;break}t=a+2|0;f[77]=t;a=t}if((t|0)==73){w(b,r,c);break}else if((t|0)==75){ee();break}}}while(0);return}function u(){var e=0,a=0,r=0,c=0,t=0,b=0,n=0,l=0,u=0,o=0;l=f[77]|0;u=f[70]|0;f[77]=l+12;a=v(1)|0;e=f[77]|0;if(!((e|0)==(l+12|0)?!(S(a)|0):0))o=3;e:do{if((o|0)==3){a:do{switch(a<<16>>16){case 123:{f[77]=e+2;e=v(1)|0;r=f[77]|0;while(1){if(ae(e)|0){A(e);e=(f[77]|0)+2|0;f[77]=e}else{G(e)|0;e=f[77]|0}v(1)|0;e=y(r,e)|0;if(e<<16>>16==44){f[77]=(f[77]|0)+2;e=v(1)|0}a=r;r=f[77]|0;if(e<<16>>16==125){o=13;break}if((r|0)==(a|0)|r>>>0>(f[78]|0)>>>0){o=12;break}}if((o|0)==12){ee();break e}else if((o|0)==13){f[77]=r+2;o=47;break a}break}case 42:{f[77]=e+2;v(1)|0;o=f[77]|0;y(o,o)|0;o=47;break}case 100:{f[77]=e+14;switch((v(1)|0)<<16>>16){case 97:{a=f[77]|0;if((I(a+2|0,192,8)|0)==0?L(s[a+10>>1]|0)|0:0){f[77]=a+10;v(0)|0;o=19}break}case 102:{o=19;break}case 99:{a=f[77]|0;if(((I(a+2|0,34,8)|0)==0?(u=s[a+10>>1]|0,K(u)|0|u<<16>>16==123):0)?(f[77]=a+10,r=v(1)|0,r<<16>>16!=123):0){n=r;o=28}break}default:{}}r:do{if((o|0)==19?(c=f[77]|0,(I(c+2|0,200,14)|0)==0):0){a=s[c+16>>1]|0;if(!(K(a)|0))switch(a<<16>>16){case 40:case 42:break;default:break r}f[77]=c+16;a=v(1)|0;if(a<<16>>16==42){f[77]=(f[77]|0)+2;a=v(1)|0}if(a<<16>>16!=40){n=a;o=28}}}while(0);if((o|0)==28?(t=f[77]|0,G(n)|0,b=f[77]|0,b>>>0>t>>>0):0){B(e,e+14|0,t,b);f[77]=(f[77]|0)+-2;break e}B(e,e+14|0,0,0);f[77]=e+12;break e}case 97:{f[77]=e+10;v(0)|0;e=f[77]|0;o=32;break}case 102:{o=32;break}case 99:{if((I(e+2|0,34,8)|0)==0?z(s[e+10>>1]|0)|0:0){f[77]=e+10;o=v(1)|0;u=f[77]|0;G(o)|0;o=f[77]|0;B(u,o,u,o);f[77]=(f[77]|0)+-2;break e}f[77]=e+4;e=e+4|0;o=39;break}case 108:case 118:{o=39;break}default:break e}}while(0);if((o|0)==32){f[77]=e+16;e=v(1)|0;if(e<<16>>16==42){f[77]=(f[77]|0)+2;e=v(1)|0}u=f[77]|0;G(e)|0;o=f[77]|0;B(u,o,u,o);f[77]=(f[77]|0)+-2;break}else if((o|0)==39){f[77]=e+6;while(1){a=v(1)|0;e=f[77]|0;if(e>>>0>(f[78]|0)>>>0)break;a=E(a)|0;if((f[77]|0)==(e|0))break;if(a<<16>>16==61)a=k(1,0)|0;e=f[77]|0;if(a<<16>>16!=44)break;f[77]=e+2}f[77]=e+-2;break}else if((o|0)==47){o=(v(1)|0)<<16>>16==102;e=f[77]|0;if(o?(I(e+2|0,42,6)|0)==0:0){f[77]=e+8;w(l,v(1)|0,0);if(i[820]|0)break;e=(u|0)==0?260:u+16|0;while(1){e=f[e>>2]|0;if(!e)break e;f[e+12>>2]=0;f[e+8>>2]=0;e=e+16|0}}f[77]=e+-2;break}}}while(0);return 0}function o(){var e=0,a=0,r=0,i=0,c=0,t=0,b=0;e=f[77]|0;c=(s[e>>1]|0)==123;t=c?125:93;f[77]=e+2;e=v(1)|0;e:while(1){if(e<<16>>16==t<<16>>16)break;i=f[77]|0;if(i>>>0>(f[78]|0)>>>0)break;if((e<<16>>16==46?(s[i+2>>1]|0)==46:0)?(s[i+4>>1]|0)==46:0){f[77]=i+6;e=E(v(1)|0)|0}else b=9;a:do{if((b|0)==9){b=0;do{if(c){do{if(e<<16>>16==91){k(0,t)|0;f[77]=(f[77]|0)+2;a=i}else{if(ae(e)|0){A(e);f[77]=(f[77]|0)+2;a=i;break}if((e+-48&65535)>=10){G(e)|0;a=f[77]|0;break}e=i;r:while(1){r=e+2|0;a=s[r>>1]|0;i:do{if((a+-48&65535)>=10){switch(a<<16>>16){case 67:case 68:case 70:case 97:case 65:case 99:case 100:case 102:case 46:case 66:case 69:case 79:case 88:case 95:case 98:case 101:case 110:case 111:case 120:break i;case 43:case 45:break;default:break r}switch(s[e>>1]|0){case 69:case 101:break;default:break r}}}while(0);e=r}f[77]=r;a=i}}while(0);e=v(1)|0;if(e<<16>>16==58){f[77]=(f[77]|0)+2;e=E(v(1)|0)|0;break}if(a>>>0>i>>>0)B(i,a,i,a)}else if(e<<16>>16==44){f[77]=i+2;e=v(1)|0;break a}else{e=E(e)|0;break}}while(0);if(e<<16>>16==61)e=k(0,t)|0;if(e<<16>>16!=44)break e;f[77]=(f[77]|0)+2;e=v(1)|0}}while(0)}return}function h(e){e=e|0;e:do{switch(s[e>>1]|0){case 100:switch(s[e+-2>>1]|0){case 105:{e=j(e+-4|0,54,2)|0;break e}case 108:{e=j(e+-4|0,58,3)|0;break e}default:{e=0;break e}}case 101:switch(s[e+-2>>1]|0){case 115:switch(s[e+-4>>1]|0){case 108:{e=q(e+-6|0,101)|0;break e}case 97:{e=q(e+-6|0,99)|0;break e}default:{e=0;break e}}case 116:{e=j(e+-4|0,64,4)|0;break e}case 117:{e=j(e+-4|0,180,6)|0;break e}default:{e=0;break e}}case 102:{if((s[e+-2>>1]|0)==111?(s[e+-4>>1]|0)==101:0)switch(s[e+-6>>1]|0){case 99:{e=j(e+-8|0,72,6)|0;break e}case 112:{e=j(e+-8|0,84,2)|0;break e}default:{e=0;break e}}else e=0;break}case 107:{e=j(e+-2|0,172,4)|0;break}case 110:{if(q(e+-2|0,105)|0)e=1;else e=j(e+-2|0,88,5)|0;break}case 111:{e=q(e+-2|0,100)|0;break}case 114:{e=j(e+-2|0,98,7)|0;break}case 116:{e=j(e+-2|0,112,4)|0;break}case 119:switch(s[e+-2>>1]|0){case 101:{e=q(e+-4|0,110)|0;break e}case 111:{e=j(e+-4|0,120,3)|0;break e}default:{e=0;break e}}default:e=0}}while(0);return e|0}function w(e,a,r){e=e|0;a=a|0;r=r|0;var i=0,c=0;i=(f[77]|0)+2|0;switch(a<<16>>16){case 39:{A(39);c=5;break}case 34:{A(34);c=5;break}default:ee()}do{if((c|0)==5){C(e,i,f[77]|0,1);if((r|0)>0)f[(f[68]|0)+28>>2]=(r|0)==1?4:6;f[77]=(f[77]|0)+2;c=(v(0)|0)<<16>>16==119;a=f[77]|0;if(((c?(s[a+2>>1]|0)==105:0)?(s[a+4>>1]|0)==116:0)?(s[a+6>>1]|0)==104:0){f[77]=a+8;if((v(1)|0)<<16>>16!=123){f[77]=a;break}r=f[77]|0;i=r;e:while(1){f[77]=i+2;i=v(1)|0;switch(i<<16>>16){case 39:{A(39);f[77]=(f[77]|0)+2;i=v(1)|0;break}case 34:{A(34);f[77]=(f[77]|0)+2;i=v(1)|0;break}default:i=G(i)|0}if(i<<16>>16!=58){c=20;break}f[77]=(f[77]|0)+2;switch((v(1)|0)<<16>>16){case 39:{A(39);break}case 34:{A(34);break}default:{c=24;break e}}f[77]=(f[77]|0)+2;switch((v(1)|0)<<16>>16){case 125:{c=28;break e}case 44:break;default:{c=26;break e}}i=(f[77]|0)+2|0;f[77]=i}if((c|0)==20){f[77]=a;break}else if((c|0)==24){f[77]=a;break}else if((c|0)==26){f[77]=a;break}else if((c|0)==28){c=f[68]|0;f[c+16>>2]=r;f[c+12>>2]=(f[77]|0)+2;break}}f[77]=a+-2}}while(0);return}function d(){var e=0,a=0,r=0;a=f[78]|0;r=f[77]|0;e:while(1){e=r+2|0;if(r>>>0>=a>>>0){a=12;break}switch(s[e>>1]|0){case 96:{a=8;break e}case 36:{if((s[r+4>>1]|0)==123){a=5;break e}break}case 92:{e=r+4|0;break}default:{}}r=e}do{if((a|0)==5){a=r+4|0;f[77]=a;e=s[409]|0;if(e<<16>>16==1024){ee();break}else{r=f[75]|0;f[r+((e&65535)<<3)>>2]=4;s[409]=e+1<<16>>16;f[r+((e&65535)<<3)+4>>2]=a;break}}else if((a|0)==8){f[77]=e;a=f[75]|0;r=(s[409]|0)+-1<<16>>16;s[409]=r;if((f[a+((r&65535)<<3)>>2]|0)!=3)ee()}else if((a|0)==12){f[77]=e;ee()}}while(0);return}function v(e){e=e|0;var a=0,r=0,i=0;r=f[77]|0;e:do{a=s[r>>1]|0;a:do{if(a<<16>>16!=47)if(e)if(K(a)|0)break;else break e;else if(L(a)|0)break;else break e;else switch(s[r+2>>1]|0){case 47:{D();break a}case 42:{g(e);break a}default:{a=47;break e}}}while(0);i=f[77]|0;r=i+2|0;f[77]=r}while(i>>>0<(f[78]|0)>>>0);return a|0}function g(e){e=e|0;var a=0,r=0,i=0;a=(f[77]|0)+2|0;f[77]=a;i=f[78]|0;e:do{if(e){while(1){e=a+2|0;if(a>>>0>=i>>>0)break e;if((s[e>>1]|0)==42?(s[a+4>>1]|0)==47:0)break;a=e}e=a+4|0}else{while(1){e=a+2|0;if(a>>>0>=i>>>0)break e;r=s[e>>1]|0;if(se(r)|0)break e;if(r<<16>>16==42?(s[a+4>>1]|0)==47:0)break;a=e}e=a+4|0}}while(0);f[77]=e;return}function A(e){e=e|0;var a=0,r=0,i=0,c=0;c=f[78]|0;a=f[77]|0;while(1){i=a+2|0;if(a>>>0>=c>>>0){a=9;break}r=s[i>>1]|0;if(r<<16>>16==e<<16>>16){a=10;break}if(r<<16>>16==92){r=a+4|0;if((s[r>>1]|0)==13){a=a+6|0;a=(s[a>>1]|0)==10?a:r}else a=r}else if(se(r)|0){a=9;break}else a=i}if((a|0)==9){f[77]=i;ee()}else if((a|0)==10)f[77]=i;return}function p(e){e=e|0;var a=0,r=0;a=s[e>>1]|0;if(K(a)|0)r=3;else switch(a<<16>>16){case 41:case 125:case 93:{r=3;break}default:e=0}e:do{if((r|0)==3){r=f[60]|0;while(1){if(e>>>0<=r>>>0)break;e=e+-2|0;if(!(K(a)|0))break;a=s[e>>1]|0}switch(a<<16>>16){case 41:case 125:case 93:{e=1;break e}default:{}}e=(S(a)|0)^1}}while(0);return e|0}function C(e,a,r,s){e=e|0;a=a|0;r=r|0;s=s|0;var c=0,t=0;t=f[72]|0;f[72]=t+36;c=f[68]|0;f[((c|0)==0?256:c+32|0)>>2]=t;f[69]=c;f[68]=t;f[t+8>>2]=e;if(2==(s|0)){e=3;c=r}else{e=1==(s|0)?1:2;c=1==(s|0)?r+2|0:0}f[t+12>>2]=c;f[t+28>>2]=e;f[t>>2]=a;f[t+4>>2]=r;f[t+16>>2]=0;f[t+20>>2]=s;i[t+24>>0]=1==(s|0)&1;f[t+32>>2]=0;return}function y(e,a){e=e|0;a=a|0;var r=0,i=0,c=0,t=0;r=f[77]|0;i=s[r>>1]|0;c=(e|0)==(a|0)?0:e;t=(e|0)==(a|0)?0:a;if(i<<16>>16==97){f[77]=r+4;r=v(1)|0;e=f[77]|0;if(ae(r)|0){A(r);a=(f[77]|0)+2|0;f[77]=a}else{G(r)|0;a=f[77]|0}i=v(1)|0;r=f[77]|0}if((r|0)!=(e|0))B(e,a,c,t);return i|0}function x(){var e=0,a=0,r=0,c=0;a=f[77]|0;i[823]=0;r=f[78]|0;e:while(1){e=a+2|0;if(a>>>0>=r>>>0){e=0;break}switch(s[e>>1]|0){case 96:{c=8;break e}case 92:{e=a+4|0;break}case 13:{i[823]=1;break}case 36:{if((s[a+4>>1]|0)==123){e=0;break e}break}default:{}}a=e}if((c|0)==8){f[77]=e;e=1}return e|0}function m(){var e=0,a=0,r=0;r=f[78]|0;a=f[77]|0;e:while(1){e=a+2|0;if(a>>>0>=r>>>0){a=6;break}switch(s[e>>1]|0){case 13:case 10:{a=6;break e}case 93:{a=7;break e}case 92:{e=a+4|0;break}default:{}}a=e}if((a|0)==6){f[77]=e;ee();e=0}else if((a|0)==7){f[77]=e;e=93}return e|0}function U(){var e=0,a=0;e:while(1){e=f[77]|0;f[77]=e+2;if(e>>>0>=(f[78]|0)>>>0){a=7;break}switch(s[e+2>>1]|0){case 13:case 10:{a=7;break e}case 47:break e;case 91:{m()|0;break}case 92:{f[77]=e+4;break}default:{}}}if((a|0)==7)ee();return}function O(e){e=e|0;switch(s[e>>1]|0){case 62:{e=(s[e+-2>>1]|0)==61;break}case 41:case 59:{e=1;break}case 104:{e=j(e+-2|0,146,4)|0;break}case 121:{e=j(e+-2|0,154,6)|0;break}case 101:{e=j(e+-2|0,166,3)|0;break}default:e=0}return e|0}function I(e,a,r){e=e|0;a=a|0;r=r|0;var s=0,f=0;e:do{if(!r)e=0;else{while(1){s=i[e>>0]|0;f=i[a>>0]|0;if(s<<24>>24!=f<<24>>24)break;r=r+-1|0;if(!r){e=0;break e}else{e=e+1|0;a=a+1|0}}e=(s&255)-(f&255)|0}}while(0);return e|0}function S(e){e=e|0;e:do{switch(e<<16>>16){case 38:case 37:case 33:{e=1;break}default:if((e&-8)<<16>>16==40|(e+-58&65535)<6)e=1;else{switch(e<<16>>16){case 91:case 93:case 94:{e=1;break e}default:{}}e=(e+-123&65535)<4}}}while(0);return e|0}function $(e){e=e|0;e:do{switch(e<<16>>16){case 38:case 37:case 33:break;default:if(!((e+-58&65535)<6|(e+-40&65535)<7&e<<16>>16!=41)){switch(e<<16>>16){case 91:case 94:break e;default:{}}return e<<16>>16!=125&(e+-123&65535)<4|0}}}while(0);return 1}function P(e){e=e|0;var a=0;a=s[e>>1]|0;e:do{if((a+-9&65535)>=5){switch(a<<16>>16){case 160:case 32:{a=1;break e}default:{}}if(S(a)|0)return a<<16>>16!=46|(N(e)|0)|0;else a=0}else a=1}while(0);return a|0}function T(e){e=e|0;var a=0,r=0;r=b;b=b+16|0;f[r>>2]=0;f[71]=e;a=f[60]|0;s[a+(e<<1)>>1]=0;f[r>>2]=a+(e<<1)+2;f[72]=a+(e<<1)+2;f[64]=0;f[68]=0;f[66]=0;f[65]=0;f[70]=0;f[67]=0;b=r;return a|0}function j(e,a,r){e=e|0;a=a|0;r=r|0;var i=0,s=0;s=e+(0-r<<1)+2|0;i=f[60]|0;if(s>>>0>=i>>>0?(I(s,a,r<<1)|0)==0:0)if((s|0)==(i|0))i=1;else i=P(e+(0-r<<1)|0)|0;else i=0;return i|0}function B(e,a,r,i){e=e|0;a=a|0;r=r|0;i=i|0;var s=0,c=0;s=f[72]|0;f[72]=s+20;c=f[70]|0;f[((c|0)==0?260:c+16|0)>>2]=s;f[70]=s;f[s>>2]=e;f[s+4>>2]=a;f[s+8>>2]=r;f[s+12>>2]=i;f[s+16>>2]=0;return}function E(e){e=e|0;var a=0;switch(e<<16>>16){case 91:case 123:{o();f[77]=(f[77]|0)+2;break}default:{a=f[77]|0;G(e)|0;e=f[77]|0;if(e>>>0>a>>>0)B(a,e,a,e)}}return v(1)|0}function M(e){e=e|0;switch(s[e>>1]|0){case 107:{e=j(e+-2|0,172,4)|0;break}case 101:{if((s[e+-2>>1]|0)==117)e=j(e+-4|0,180,6)|0;else e=0;break}default:e=0}return e|0}function q(e,a){e=e|0;a=a|0;var r=0;r=f[60]|0;if(r>>>0<=e>>>0?(s[e>>1]|0)==a<<16>>16:0)if((r|0)==(e|0))r=1;else r=z(s[e+-2>>1]|0)|0;else r=0;return r|0}function z(e){e=e|0;e:do{if((e+-9&65535)<5)e=1;else{switch(e<<16>>16){case 32:case 160:{e=1;break e}default:{}}e=e<<16>>16!=46&(S(e)|0)}}while(0);return e|0}function D(){var e=0,a=0,r=0;e=f[78]|0;r=f[77]|0;e:while(1){a=r+2|0;if(r>>>0>=e>>>0)break;switch(s[a>>1]|0){case 13:case 10:break e;default:r=a}}f[77]=a;return}function F(e){e=e|0;e:do{if(((e&-33)+-65&65535)<26|(e+-48&65535)<10)e=1;else{switch(e<<16>>16){case 36:case 95:{e=1;break e}default:{}}e=(e&65535)>127}}while(0);return e|0}function G(e){e=e|0;while(1){if(K(e)|0)break;if(S(e)|0)break;e=(f[77]|0)+2|0;f[77]=e;e=s[e>>1]|0;if(!(e<<16>>16)){e=0;break}}return e|0}function H(){var e=0;e=f[(f[66]|0)+20>>2]|0;switch(e|0){case 1:{e=-1;break}case 2:{e=-2;break}default:e=e-(f[60]|0)>>1}return e|0}function J(e){e=e|0;if(!(j(e,126,5)|0)?!(j(e,136,3)|0):0)e=j(e,142,2)|0;else e=1;return e|0}function K(e){e=e|0;switch(e<<16>>16){case 160:case 9:case 10:case 11:case 12:case 13:case 32:{e=1;break}default:e=0}return e|0}function L(e){e=e|0;switch(e<<16>>16){case 160:case 32:case 12:case 11:case 9:{e=1;break}default:e=0}return e|0}function N(e){e=e|0;if((s[e>>1]|0)==46?(s[e+-2>>1]|0)==46:0)e=(s[e+-4>>1]|0)==46;else e=0;return e|0}function Q(e){e=e|0;if((f[60]|0)==(e|0))e=1;else e=P(e+-2|0)|0;return e|0}function R(){var e=0;e=f[(f[67]|0)+12>>2]|0;if(!e)e=-1;else e=e-(f[60]|0)>>1;return e|0}function V(){var e=0;e=f[(f[66]|0)+12>>2]|0;if(!e)e=-1;else e=e-(f[60]|0)>>1;return e|0}function W(){var e=0;e=f[(f[67]|0)+8>>2]|0;if(!e)e=-1;else e=e-(f[60]|0)>>1;return e|0}function X(){var e=0;e=f[(f[66]|0)+16>>2]|0;if(!e)e=-1;else e=e-(f[60]|0)>>1;return e|0}function Y(){var e=0;e=f[(f[66]|0)+4>>2]|0;if(!e)e=-1;else e=e-(f[60]|0)>>1;return e|0}function Z(){var e=0;e=f[66]|0;e=f[((e|0)==0?256:e+32|0)>>2]|0;f[66]=e;return(e|0)!=0|0}function _(){var e=0;e=f[67]|0;e=f[((e|0)==0?260:e+16|0)>>2]|0;f[67]=e;return e|0}function ee(){i[820]=1;f[73]=(f[77]|0)-(f[60]|0)>>1;f[77]=(f[78]|0)+2;return}function ae(e){e=e|0;return e<<16>>16==39|e<<16>>16==34|0}function re(){return(f[(f[66]|0)+8>>2]|0)-(f[60]|0)>>1|0}function ie(){return(f[(f[67]|0)+4>>2]|0)-(f[60]|0)>>1|0}function se(e){e=e|0;return e<<16>>16==13|e<<16>>16==10|0}function fe(){return(f[f[66]>>2]|0)-(f[60]|0)>>1|0}function ce(){return(f[f[67]>>2]|0)-(f[60]|0)>>1|0}function te(){return c[(f[66]|0)+24>>0]|0|0}function be(e){e=e|0;f[60]=e;return}function ke(){return f[(f[66]|0)+28>>2]|0}function ne(){return f[73]|0}function le(e,a){e=e|0;a=a|0;b=e+a+15&-16;return a|0}return{su:le,ai:X,e:ne,ee:ie,ele:R,els:W,es:ce,id:H,ie:Y,ip:te,is:fe,it:ke,p:n,re:_,ri:Z,sa:T,se:V,ses:be,ss:re}}("undefined"!=typeof globalThis?globalThis:self,{},a),r=e.su(i-(2<<17),1056)}const w=c.length+1;e.ses(r),e.sa(w-1),s(c,new Uint16Array(a,r,w)),e.p()||(b=e.e(),u());const d=[],v=[];for(;e.ri();){const a=e.is(),r=e.ie(),i=e.it(),s=15&i,f=e.ai(),c=e.id(),t=e.ss(),b=e.se(),k=e.ip();let l;1&k&&(l=n(-1===c?a:a+1,-1===c?r:r-1,!!(2&k))),d.push({t:s,n:l,s:a,e:r,ss:t,se:b,d:c,a:f})}let g;for(;g=e.re();){const a=e.es(),r=e.ee(),i=e.els(),s=e.ele();{const e=i<0?void 0:A(i,s),f=A(a,r);v.push({s:a,e:r,ls:i,le:s,n:f,ln:e});continue}}return[d,v];function A(e,a){const r=c.charCodeAt(e);return 34===r||39===r?n(e+1,a-1):c.slice(e,a)}}const k=/\r\n?/g;function n(e,a,r=!1){const i=c.slice(e,a);let s=i.indexOf("\\");if(-1===s)return r?i.replace(k,"\n"):i;let f=i.slice(0,s),t=r?f.replace(k,"\n"):f;for(;;){let a=s+1;a>=i.length&&(b=e+a,u());const c=i.charCodeAt(a++);switch(c){case 13:10===i.charCodeAt(a)&&a++;break;case 10:case 8232:case 8233:break;case 114:t+="\r";break;case 110:t+="\n";break;case 116:t+="\t";break;case 98:t+="\b";break;case 102:t+="\f";break;case 118:t+="\v";break;case 120:t+=String.fromCharCode(l(e+a,2)),a+=2;break;case 117:{let r;if(123===i.charCodeAt(a)){const s=i.indexOf("}",++a);-1===s&&(b=e+a,u()),r=l(e+a,s-a),a=s+1}else r=l(e+a,4),a+=4;r>1114111&&(b=e+a,u()),r<=65535?t+=String.fromCharCode(r):(r-=65536,t+=String.fromCharCode(55296+(r>>10),56320+(1023&r)));break}case 48:{const r=i.charCodeAt(a);r>=48&&r<=57&&(b=e+a,u()),t+="\0";break}default:c>=49&&c<=57&&(b=e+a-1,u()),t+=String.fromCharCode(c)}const n=i.indexOf("\\",a);if(-1===n)return f=i.slice(a),t+(r?f.replace(k,"\n"):f);f=i.slice(a,n),t+=r?f.replace(k,"\n"):f,s=n}}function l(e,a){(a<1||e+a>c.length)&&(b=e,u());let r=0;const i=e+a;for(let a=e;a<i;a++){const e=c.charCodeAt(a),i=32|e,s=e>=48&&e<=57?e-48:i>=97&&i<=102?i-87:-1;-1===s&&(b=a,u()),r=16*r+s}return r}function u(){throw Object.assign(Error(`Parse error ${t}:${c.slice(0,b).split("\n").length}:${b-c.lastIndexOf("\n",b-1)}`),{idx:b})}
return parse;
})();
// END VENDORED ES MODULE LEXER

/** HTML 的 URL-like module specifier：只有 /、./、../ 开头才带基址解析。 */
function rewriteModuleSpecifier(specifier, baseUrl, workerOrigin) {
	// 为保持幂等，已是代理路径的说明符不能按目标站点路径再次包装。
	if (isProxiedPath(specifier)) return rewriteUrl(specifier, baseUrl, workerOrigin);
	try {
		const resolved = /^(?:\/|\.\.?\/)/.test(specifier)
			? new URL(specifier, baseUrl) : new URL(specifier);
		if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') return specifier;
		return rewriteUrl(resolved.href, baseUrl, workerOrigin);
	} catch {
		// 裸说明符和无法解析的 URL 交给浏览器及 import map 原样处理。
		return specifier;
	}
}

/**
 * 只改写真正的模块说明符，保留注释、字符串、正则及 import attributes。
 * lexer 的 n 已解码 JS 转义；重新序列化整段字符串，不能直接拼回原引号。
 * 无法静态确定的动态 import、裸说明符和 import.meta 保持原样。
 * 解析失败时原样返回，避免对新语法/无效源码进行部分改写。
 */
const rewriteJsModuleSpecifiers = capRewriteGrowth((account, js, baseUrl, workerOrigin) => {
	const source = String(js);
	if (!source.includes('import') && !source.includes('export')) return source;
	let imports;
	try { [imports] = parseModuleImports(source); } catch { return source; }
	const parts = [];
	let cursor = 0;
	for (const item of imports) {
		const spec = item.n;
		if (typeof spec !== 'string') continue;
		const rewritten = rewriteModuleSpecifier(spec, baseUrl, workerOrigin);
		if (rewritten === spec) continue;
		// 静态说明符 s/e 不含引号；动态说明符 s/e 包含整个字面量。
		const start = item.d === -1 ? item.s - 1 : item.s;
		const end = item.d === -1 ? item.e + 1 : item.e;
		parts.push(source.slice(cursor, start), account(end - start, stringifyInlineJson(rewritten)));
		cursor = end;
	}
	if (!parts.length) return source;
	parts.push(source.slice(cursor));
	return parts.join('');
});

/** script raw-text 不解析 HTML 实体；用 JSON 转义防止 < 或 ]]> 破坏 HTML/CDATA 边界。 */
function stringifyInlineJson(value) {
	return JSON.stringify(value).replace(/</g, '\\u003c').replace(/]]>/g, ']]\\u003e');
}

/** 重写 <script type="importmap">：按 HTML 规范以文档基地址解析映射并移除失效的 integrity */
const rewriteImportMap = capRewriteGrowth((account, text, baseUrl, workerOrigin) => {
	let map;
	try { map = JSON.parse(text); } catch { return text; }
	if (!map || typeof map !== 'object' || Array.isArray(map)) return text;
	const rewriteSpecMap = (specMap) => {
		if (!specMap || typeof specMap !== 'object' || Array.isArray(specMap)) return specMap;
		// 模块名是任意 JSON 键，__proto__ 也必须作为普通属性保留。
		const next = Object.create(null);
		for (const [k, v] of Object.entries(specMap)) {
			const rwKey = account(k.length, rewriteModuleSpecifier(k, baseUrl, workerOrigin));
			next[rwKey] = typeof v === 'string' ? account(v.length, rewriteModuleSpecifier(v, baseUrl, workerOrigin)) : v;
		}
		return next;
	};
	if (map.imports && typeof map.imports === 'object' && !Array.isArray(map.imports)) {
		map.imports = rewriteSpecMap(map.imports);
	}
	if (map.scopes && typeof map.scopes === 'object' && !Array.isArray(map.scopes)) {
		const nextScopes = Object.create(null);
		for (const [scopeKey, specMap] of Object.entries(map.scopes)) {
			// 作用域前缀同样是文档基地址下的 URL，必须与被代理的模块 URL 使用同一种形式。
			nextScopes[account(scopeKey.length, rewriteUrl(scopeKey, baseUrl, workerOrigin, true))] = rewriteSpecMap(specMap);
		}
		map.scopes = nextScopes;
	}
	delete map.integrity;
	return stringifyInlineJson(map);
});

/** 重写 <script type="speculationrules"> 中的预取/预渲染 URL 列表 */
const rewriteSpeculationRules = capRewriteGrowth((account, text, baseUrl, workerOrigin, docUrl = baseUrl) => {
	let spec;
	try { spec = JSON.parse(text); } catch { return text; }
	if (!spec || typeof spec !== 'object' || Array.isArray(spec)) return text;
	for (const key of ['prefetch', 'prerender', 'prefetch_with_subresources', 'prerender_until_script']) {
		const rules = spec[key];
		if (!Array.isArray(rules)) continue;
		for (const rule of rules) {
			if (rule && Array.isArray(rule.urls)) {
				const ruleBase = rule.relative_to === 'document' ? docUrl : baseUrl;
				rule.urls = rule.urls.map(u => typeof u === 'string' ? account(u.length, rewriteUrl(u, ruleBase, workerOrigin, true)) : u);
			}
		}
	}
	return stringifyInlineJson(spec);
});

function isValidXmlCodePoint(code) {
	return code === 9 || code === 10 || code === 13 || (code >= 0x20 && code <= 0xd7ff) ||
		(code >= 0xe000 && code <= 0xfffd) || (code >= 0x10000 && code <= 0x10ffff);
}

function decodeXmlEntities(s) {
	return String(s).replace(/&(?:#(\d+)|#x([0-9a-fA-F]+)|(amp|lt|gt|quot|apos));/g, (m, dec, hex, named) => {
		if (dec || hex) {
			const code = dec ? Number(dec) : parseInt(hex, 16);
			return isValidXmlCodePoint(code) ? String.fromCodePoint(code) : m;
		}
		return { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[named];
	});
}

function hasCustomXmlEntity(s) {
	return /&(?!(?:amp|lt|gt|quot|apos);)[A-Za-z_:\u00c0-\ud7ff\uf900-\ufdcf\ufdf0-\ufffd\u{10000}-\u{effff}][\w.:\u00b7-\ud7ff\uf900-\ufdcf\ufdf0-\ufffd\u{10000}-\u{effff}-]*;/u.test(s);
}

function escapeXmlAttr(s) {
	return String(s).replace(/[&"<>\t\n\r]/g, c => ({
		'&': '&amp;', '"': '&quot;', '<': '&lt;', '>': '&gt;', '\t': '&#9;', '\n': '&#10;', '\r': '&#13;',
	}[c]));
}

const XML_ATTR = /([ \t\n\r])([^\s"'<>\/=]+)(\s*=\s*)(?:"([^"]*)"|'([^']*)')/g;
const XML_REFERENCE_ATTRS = new Set(['href', 'src', 'poster']);
const XML_XLINK_NS = 'http://www.w3.org/1999/xlink';
const SVG_CSS_ATTRS = new Set(['style', 'fill', 'stroke', 'filter', 'clip-path', 'mask', 'marker', 'marker-start', 'marker-mid', 'marker-end', 'cursor']);

/** 顺序读 XML 标记，避免在未闭合的标签、注释或 CDATA 上反复回溯。 */
function readXmlMarkup(source, start) {
	for (const [open, close, kind] of [['<!--', '-->', 'comment'], ['<![CDATA[', ']]>', 'cdata'], ['<?', '?>', 'pi']]) {
		if (source.startsWith(open, start)) {
			const end = source.indexOf(close, start + open.length);
			return end < 0 ? { end: source.length } : { end: end + close.length, kind };
		}
	}
	const declaration = source.startsWith('<!', start);
	let level = 0;
	let quote = '';
	for (let i = start + 1; i < source.length; i++) {
		const ch = source[i];
		if (quote) {
			if (ch === quote) quote = '';
		} else if (ch === '"' || ch === "'") {
			quote = ch;
		} else if (ch === '<' && !declaration) {
			return { end: i }; // 下一处标记仍独立处理
		} else if (declaration && source.startsWith('<!--', i)) {
			const end = source.indexOf('-->', i + 4);
			if (end < 0) break;
			i = end + 2;
		} else if (declaration && source.startsWith('<?', i)) {
			const end = source.indexOf('?>', i + 2);
			if (end < 0) break;
			i = end + 1;
		} else if (declaration && ch === '[') {
			level++;
		} else if (declaration && ch === ']' && level > 0) {
			level--;
		} else if (ch === '>' && level === 0) {
			return { end: i + 1, kind: declaration ? 'declaration' : 'tag' };
		}
	}
	return { end: source.length };
}

function readXmlTextEnd(source, start, qualifiedName) {
	let i = start;
	while ((i = source.indexOf('<', i)) !== -1) {
		if (source.startsWith('</' + qualifiedName, i)) {
			let end = i + 2 + qualifiedName.length;
			while (/[ \t\n\r]/.test(source[end] || '')) end++;
			if (source[end] === '>') return { start: i, end: end + 1 };
		}
		if (!source.startsWith('<!--', i) && !source.startsWith('<![CDATA[', i)) return null;
		const markup = readXmlMarkup(source, i);
		if (!markup.kind) return null;
		i = markup.end;
	}
	return null;
}

const rewriteXmlText = capRewriteGrowth((account, body, transform) => {
	const escapeXmlText = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/]]>/g, ']]&gt;');
	let out = '';
	let last = 0;
	let sawCustom = false;
	let hasCdata = false;
	const decodedParts = [];
	const transformedParts = [];
	const pushText = (part) => {
		if (!part && decodedParts.length) return '';
		if (hasCustomXmlEntity(part)) { sawCustom = true; return part; }
		const decoded = decodeXmlEntities(part);
		const next = transform(decoded);
		if (part) {
			decodedParts.push(decoded);
			transformedParts.push(next);
		}
		return next === decoded ? part : escapeXmlText(next);
	};
	const opener = /<!\[CDATA\[|<!--/g;
	let match;
	while ((match = opener.exec(body))) {
		const cdata = match[0] === '<![CDATA[';
		const end = body.indexOf(cdata ? ']]>' : '-->', opener.lastIndex);
		if (end < 0) return body;
		const before = body.slice(last, match.index);
		if (before) out += account(before.length, pushText(before));
		if (cdata) {
			hasCdata = true;
			const inner = body.slice(opener.lastIndex, end);
			const next = transform(inner);
			if (inner) {
				decodedParts.push(inner);
				transformedParts.push(next);
			}
			out += account(end + 3 - match.index, `<![CDATA[${next.replace(/]]>/g, ']]]]><![CDATA[>')}]]>`);
		} else {
			out += body.slice(match.index, end + 3);
		}
		last = opener.lastIndex = end + 3;
	}
	const tail = body.slice(last);
	if (tail || !out) out += account(tail.length, pushText(tail));
	// /*<![CDATA[*/ ... /*]]>*/ 等写法把同一段源码拆在多段文本间；逐段改写失配时按拼接后的 XML 字符数据改写。
	if (!sawCustom && decodedParts.length > 1) {
		const combined = decodedParts.join('');
		const combinedOut = transform(combined);
		if (combinedOut !== transformedParts.join('')) {
			const serialized = hasCdata
				? `<![CDATA[${combinedOut.replace(/]]>/g, ']]]]><![CDATA[>')}]]>`
				: escapeXmlText(combinedOut);
			return account(body.length, serialized);
		}
	}
	return out;
});

/** 独立 SVG 文档：重写引用属性和样式，保留不理解的 XML 声明与实体。 */
const rewriteSvg = capRewriteGrowth((account, source, baseUrl, workerOrigin) => {
	const out = [];
	const scopes = [{ name: null, base: baseUrl }];
	const xlinkPrefixes = new Set();
	const restorePrefixes = (bindings) => {
		if (!bindings) return;
		for (let i = bindings.length - 1; i >= 0; i--) {
			const [prefix, wasXlink] = bindings[i];
			if (wasXlink) xlinkPrefixes.add(prefix);
			else xlinkPrefixes.delete(prefix);
		}
	};
	let cursor = 0;
	for (let start; (start = source.indexOf('<', cursor)) !== -1;) {
		out.push(source.slice(cursor, start));
		const { end, kind } = readXmlMarkup(source, start);
		const tag = source.slice(start, end);
		cursor = end;
		const closingName = kind === 'tag' ? /^<\/([^\s\/>]+)[ \t\n\r]*>/.exec(tag)?.[1] : null;
		if (closingName) {
			if (scopes.length > 1 && scopes[scopes.length - 1].name === closingName) {
				restorePrefixes(scopes.pop().bindings);
			}
			out.push(tag);
			continue;
		}
		const qualifiedName = kind === 'tag' ? /^<([^\s\/>]+)(?=[\s\/>])/.exec(tag)?.[1] : null;
		const localName = qualifiedName?.split(':').pop();
		const stylesheet = kind === 'pi' && /^<\?xml-stylesheet[ \t\n\r]/.test(tag);
		if (kind === 'pi' && /^<\?xml[ \t\n\r]/.test(tag)) {
			out.push(account(tag.length, utf8XmlDeclaration(tag)));
			continue;
		}
		if (!localName && !stylesheet) { out.push(tag); continue; }
		let elementBase = scopes[scopes.length - 1].base;
		let bindings = null;
		if (localName) {
			// 声明作用于本元素及后代；前缀不必叫 xlink，也可能被同名的其他命名空间遮蔽。
			let sawBase = false;
			for (const [, , name, , dq, sq] of tag.matchAll(XML_ATTR)) {
				const raw = dq ?? sq;
				if (name.startsWith('xmlns:')) {
					const prefix = name.slice(6);
					const wasXlink = xlinkPrefixes.has(prefix);
					const isXlink = decodeXmlAttribute(raw) === XML_XLINK_NS;
					if (wasXlink !== isXlink) {
						(bindings || (bindings = [])).push([prefix, wasXlink]);
						if (isXlink) xlinkPrefixes.add(prefix);
						else xlinkPrefixes.delete(prefix);
					}
				}
				if (name !== 'xml:base' || sawBase) continue;
				sawBase = true;
				try {
					if (hasCustomXmlEntity(raw)) throw new Error();
					elementBase = new URL(decodeXmlAttribute(raw), elementBase ?? undefined).href;
				} catch { elementBase = null; }
			}
		}
		const rw = v => elementBase === null ? v : rewriteUrl(v, elementBase, workerOrigin);
		let type;
		let hasRef = false;
		out.push(tag.replace(XML_ATTR, (m, space, name, equals, dq, sq) => {
			const raw = dq ?? sq;
			if (name === 'type' && type === undefined) type = decodeXmlAttribute(raw).trim().toLowerCase();
			const xlinkHref = localName && name.endsWith(':href') && xlinkPrefixes.has(name.slice(0, -5));
			if (name === 'src' || name === 'href' || xlinkHref) hasRef = true;
			if (name === 'integrity' && (localName === 'script' || localName === 'link')) return '';
			if (hasCustomXmlEntity(raw) || elementBase === null) return m;
			const decoded = decodeXmlAttribute(raw);
			let next;
			// 保留原生片段引用的含义，但让浏览器解析片段时也留在代理基地址内。
			if (name === 'xml:base' && localName) next = rewriteUrl(elementBase, baseUrl, workerOrigin);
			else if (XML_REFERENCE_ATTRS.has(name) || xlinkHref ||
				(name === 'data' && localName === 'object') ||
				(name === 'action' && localName === 'form') ||
				(name === 'formaction' && (localName === 'input' || localName === 'button'))) next = rw(decoded);
			else if (name === 'srcset' || name === 'imagesrcset') next = rewriteSrcset(decoded, elementBase, workerOrigin);
			else if (name === 'ping') next = rewritePing(decoded, elementBase, workerOrigin);
			else if (SVG_CSS_ATTRS.has(name)) next = rewriteStyleAttr(decoded, elementBase, workerOrigin);
			return next === undefined || next === decoded ? m : account(m.length, `${space}${name}${equals}"${escapeXmlAttr(next)}"`);
		}));
		if (!localName || tag.endsWith('/>')) { restorePrefixes(bindings); continue; }
		scopes.push({ name: qualifiedName, base: elementBase, bindings });
		const rewrite = localName === 'style' ? rewriteCss
			: localName === 'script' && !hasRef
				? (type === 'module' ? rewriteJsModuleSpecifiers
					: type === 'importmap' ? rewriteImportMap
						: type === 'speculationrules' ? rewriteSpeculationRules : null)
				: null;
		if (!rewrite) continue;
		const close = readXmlTextEnd(source, cursor, qualifiedName);
		if (close) {
			const text = source.slice(cursor, close.start);
			const rewritten = elementBase === null ? text : rewriteXmlText(text, part => rewrite(part, elementBase, workerOrigin, baseUrl));
			out.push(account(text.length, rewritten), source.slice(close.start, close.end));
			cursor = close.end;
			restorePrefixes(scopes.pop().bindings); // 扫描已消费这个元素的闭合标签。
		}
	}
	out.push(source.slice(cursor));
	return out.join('');
});

/** Manifest：解析 JSON，仅改写规范中的 URL 字段，不触碰名称/键/任意业务字符串。 */
const rewriteJsonUrls = capRewriteGrowth((account, text, baseUrl, workerOrigin) => {
	let manifest;
	try { manifest = JSON.parse(text); } catch { return text; }
	if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) return text;
	const fields = (obj, names) => {
		if (!obj || typeof obj !== 'object') return;
		for (const name of names) {
			if (typeof obj[name] === 'string') obj[name] = account(obj[name].length, rewriteUrl(obj[name], baseUrl, workerOrigin));
		}
	};
	const images = (list) => {
		if (Array.isArray(list)) for (const item of list) fields(item, ['src']);
	};
	// id 按规范相对 start_url 的来源解析，而非 manifest 地址：否则 "?pwa"、"app" 这类 id 会拼到 manifest 所在路径上。
	if (typeof manifest.id === 'string' && manifest.id !== '') {
		let idBase = new URL('/', baseUrl).href;
		try {
			const start = new URL(typeof manifest.start_url === 'string' ? manifest.start_url : '', baseUrl);
			if (start.protocol === 'http:' || start.protocol === 'https:') idBase = start.origin + '/';
		} catch {}
		manifest.id = account(manifest.id.length, rewriteUrl(manifest.id, idBase, workerOrigin, true));
	}
	fields(manifest, ['start_url', 'scope']);
	images(manifest.icons);
	images(manifest.screenshots);
	if (Array.isArray(manifest.shortcuts)) for (const item of manifest.shortcuts) {
		fields(item, ['url']);
		if (item) images(item.icons);
	}
	if (Array.isArray(manifest.protocol_handlers)) for (const item of manifest.protocol_handlers) {
		fields(item, ['url']);
	}
	if (Array.isArray(manifest.file_handlers)) for (const item of manifest.file_handlers) {
		fields(item, ['action']);
		if (item) images(item.icons);
	}
	if (Array.isArray(manifest.related_applications)) for (const item of manifest.related_applications) {
		fields(item, ['url']);
	}
	fields(manifest.share_target, ['action']);
	delete manifest.serviceworker;
	return JSON.stringify(manifest);
});

// ============================================================
// 请求解析
// ============================================================

/** 规范化主机名：统一小写并剥除末尾根域点（包括多重尾点） */
function normalizeHostname(hostname) {
	return String(hostname || '').toLowerCase().replace(/\.+$/, '');
}

/** 从代理 URL 解析出目标绝对 URL；非法时返回 null */
function parseTarget(url) {
	if (url.pathname === '/' || url.pathname === '') return null;
	const raw = decodeProxyPath(url.pathname);
	if (!raw) return null;
	const trimmed = trimUrlSpace(raw).replace(/^\/+/, '');
	if (!trimmed) return null;
	// 拒绝无双斜杠的非 HTTP(S)/WS(S) scheme（如 mailto:user@host 被拼上 https:// 后误解析为认证凭据）
	if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed) &&
		!/^(?:https?|wss?):\/\//i.test(trimmed) &&
		!/^(?:localhost\.?|[a-z0-9_-]+\.[a-z0-9_.-]+):\d+(?:[/?#]|$)/i.test(trimmed)) {
		return null;
	}
	let target = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : 'https://' + trimmed;
	// 路径内若编码了 #fragment，须先截断再拼接查询串，避免查询参数被吞入 hash。
	const hashIdx = target.indexOf('#');
	if (hashIdx >= 0) target = target.slice(0, hashIdx);
	// 不保留内部参数名：目标站可能合法使用 __pe，且查询串可能参与签名。
	const search = urlSuffix(url).split('#', 1)[0];
	if (search) {
		target += (target.includes('?') ? '&' : '?') + search.slice(1);
	}
	let u;
	try { u = new URL(target); } catch { return null; }
	if (!['http:', 'https:', 'ws:', 'wss:'].includes(u.protocol)) return null;
	const rawHost = u.hostname;
	if (!rawHost || rawHost.startsWith('.') || rawHost.includes('..')) return null;
	const strippedHost = normalizeHostname(rawHost);
	if (!strippedHost) return null;
	// 就地规范化 hostname（使带尾点的缩写/十六进制/八进制 IPv4 被 URL 标准解析器展开）
	try { u.hostname = strippedHost; } catch { return null; }
	const host = normalizeHostname(u.hostname);
	if (!host || host.startsWith('.') || host.includes('..') ||
		(!host.includes('.') && host !== 'localhost' && !host.startsWith('['))) return null;
	if (u.username || u.password) return null;
	u.hash = '';
	return u;
}

/**
 * 部署防护：拒绝 IP 字面量/明显本地名称；必须配置精确的 HTTP(S) 来源允许列表。
 * 这不是 DNS/IP 出站防火墙：公网名称仍可能解析为内网地址或发生 DNS rebinding。
 */
function targetPolicyError(targetUrl, env) {
	const target = new URL(targetUrl.href);
	if (target.protocol === 'ws:') target.protocol = 'http:';
	if (target.protocol === 'wss:') target.protocol = 'https:';
	try { target.hostname = normalizeHostname(target.hostname); } catch {}
	const host = normalizeHostname(target.hostname);
	if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.startsWith('[') ||
		host === 'localhost' || /\.(localhost|local|internal)$/.test(host)) {
		return { status: 403, message: '不允许代理 IP 字面量或本地目标名称' };
	}
	const configured = env?.ALLOWED_TARGET_ORIGINS;
	try {
		if (typeof configured !== 'string' || !configured.trim()) throw new Error();
		// 多行配置常带尾随逗号或空行；空项不代表任何来源，忽略而不是让整个列表失效。
		const entries = configured.split(',').map(value => value.trim()).filter(Boolean);
		if (!entries.length) throw new Error();
		const origins = entries.map(entry => {
			// 先验证来源语法：URL 解析会消除点路径、反斜线、空查询串等输入错误。
			if (!/^https?:\/\/[^\s\\/@?#*\x00-\x1f\x7f]+\/?$/i.test(entry)) throw new Error();
			const u = new URL(entry);
			if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password ||
				u.pathname !== '/' || u.search || u.hash) throw new Error();
			u.hostname = normalizeHostname(u.hostname);
			return u.origin;
		});
		if (!origins.includes(target.origin)) return { status: 403, message: '目标来源不在允许列表中' };
	} catch {
		return { status: 503, message: 'ALLOWED_TARGET_ORIGINS 配置无效' };
	}
	return null;
}

/** 目标 URL → 页面“文档基地址”（用于解析相对 URL） */
function documentBase(targetUrl) {
	return targetUrl.href;
}

// 剥除代理链路注入的宿主/客户端转发头，避免源站据此生成指向代理域的链接或产生协议重定向循环
const STRIP_FORWARDED_HEADERS = new Set([
	'x-real-ip', 'true-client-ip', 'forwarded',
	'x-original-host', 'x-original-url', 'x-rewrite-url', 'x-client-ip', 'via',
	'cdn-loop', 'x-real-port', 'x-scheme', 'x-forwarded-ssl', 'front-end-https', 'fastly-client-ip',
]);

/** 从 Referer 还原发起请求的目标页面 URL（ws/wss 归一为 http/https）；缺失或不是合法代理地址时返回 null */
function refererTarget(request, workerOrigin, env) {
	const referer = request.headers.get('referer');
	if (!referer) return null;
	try {
		const rUrl = new URL(referer);
		const rTarget = rUrl.origin === workerOrigin ? parseTarget(rUrl) : null;
		if (rTarget && !isWorkerHost(rTarget, workerOrigin) && !targetPolicyError(rTarget, env)) {
			if (rTarget.protocol === 'ws:') rTarget.protocol = 'http:';
			else if (rTarget.protocol === 'wss:') rTarget.protocol = 'https:';
			return rTarget;
		}
	} catch {}
	return null;
}

/** HTTP 和 WebSocket 一律从真实的代理页面还原来源；没有证据时不得冒充目标。 */
function buildUpstreamHeaders(request, workerOrigin, destination, env) {
	const headers = new Headers();
	for (const [name, value] of request.headers) {
		const key = name.toLowerCase();
		if (!key.startsWith('cf-') && !key.startsWith('x-forwarded-') && !STRIP_FORWARDED_HEADERS.has(key)) {
			headers.set(name, value);
		}
	}
	stripHopByHop(headers);
	headers.delete('Host');
	headers.delete('Referer');
	const source = refererTarget(request, workerOrigin, env);
	const sameOrigin = source?.origin === destination.origin;
	// strict-origin-when-cross-origin：跨源不转发路径或查询串，HTTPS → HTTP 不转发 Referer。
	if (source && !(source.protocol === 'https:' && destination.protocol === 'http:')) {
		headers.set('Referer', sameOrigin ? source.href : source.origin + '/');
	}
	if (request.headers.has('Origin')) headers.set('Origin', source?.origin ?? 'null');
	const fetchSite = headers.get('Sec-Fetch-Site')?.trim().toLowerCase();
	if (fetchSite === 'same-origin' || fetchSite === 'same-site') {
		headers.set('Sec-Fetch-Site', sameOrigin ? 'same-origin' : 'cross-site');
	}
	return headers;
}

// ============================================================
// WebSocket 代理
// ============================================================

function bridgeWebSockets(upstream, client) {
	const closing = new Set();
	const close = (socket, code, reason) => {
		if (closing.has(socket) || socket.readyState === 3) return;
		closing.add(socket);
		try {
			if (code === 1005 || !code) socket.close();
			else socket.close([1006, 1015].includes(code) ? 1011 : code, reason);
		} catch {
			try { socket.close(1011); } catch { /* 已由运行时终止 */ }
		}
	};
	const pipe = (from, to) => {
		const closeBoth = (code, reason) => { close(to, code, reason); close(from, code, reason); };
		from.addEventListener('message', ev => {
			if (to.readyState !== 1) return;
			try { to.send(ev.data); } catch { closeBoth(1011, 'proxy send failed'); }
		});
		from.addEventListener('close', ev => closeBoth(ev.code, ev.reason));
		from.addEventListener('error', () => closeBoth(1011, 'proxy socket error'));
	};
	pipe(upstream, client);
	pipe(client, upstream);
}

async function handleWebSocket(request, targetUrl, ck, workerOrigin, env) {
	// ws/wss → http/https 供 fetch 建立上游连接
	const upstreamUrl = new URL(targetUrl.href);
	if (upstreamUrl.protocol === 'ws:') upstreamUrl.protocol = 'http:';
	else if (upstreamUrl.protocol === 'wss:') upstreamUrl.protocol = 'https:';

	const headers = buildUpstreamHeaders(request, workerOrigin, upstreamUrl, env);
	applyRequestCookieScope(headers, request, ck.ns);
	// 两段连接分别握手，key、版本和扩展由 Workers 运行时协商。
	for (const name of ['sec-websocket-key', 'sec-websocket-version', 'sec-websocket-extensions', 'sec-websocket-accept']) headers.delete(name);
	headers.set('Connection', 'Upgrade');
	headers.set('Upgrade', 'websocket');

	// 自动跟随重定向可能把手工转发的 Cookie 带到另一个站点。
	// 握手必须到达上游，不能命中同地址的普通 GET 或旧的握手拒绝响应。
	const resp = await fetch(upstreamUrl.href, { headers, redirect: 'manual', signal: request.signal, cache: 'no-store' });
	const upstream = resp.webSocket;
	if (!upstream) {
		if (resp.body) resp.body.cancel().catch(() => {});
		// 上游明确拒绝握手（4xx/5xx）时保留其状态码供排查；重定向不自动跟随，其余情况一律 502。
		const status = resp.status >= 400 && resp.status <= 599 ? resp.status : 502;
		return new Response('上游未完成 WebSocket 握手（不自动跟随重定向）', {
			status, headers: { 'Cache-Control': 'no-store' },
		});
	}
	const pair = new WebSocketPair();
	const client = pair[0];
	upstream.binaryType = 'arraybuffer';
	client.binaryType = 'arraybuffer';
	// 新兼容日期默认自动回复 Close。代理需将关闭码传给另一端并显式确认两段握手。
	upstream.accept({ allowHalfOpen: true });
	client.accept({ allowHalfOpen: true });
	bridgeWebSockets(upstream, client);

	// 转发协商出的子协议及握手 Cookie；不要复用上游的 Accept/Upgrade 头。
	const responseHeaders = new Headers(resp.headers);
	for (const name of [...responseHeaders.keys()]) {
		if (!['sec-websocket-protocol', 'set-cookie'].includes(name.toLowerCase())) responseHeaders.delete(name);
	}
	if (ck) rescopeSetCookies(responseHeaders, ck.ns, ck.isHttps);
	return new Response(null, { status: 101, webSocket: pair[1], headers: responseHeaders });
}

// ============================================================
// 主入口
// ============================================================

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const workerOrigin = url.origin;

		// 不仅隐藏 CORS 响应头：在回源前拒绝外站 Origin（也覆盖 WebSocket）。
		const origin = request.headers.get('origin');
		if (origin && origin !== workerOrigin) {
			return new Response('不允许跨源访问此代理', {
				status: 403, headers: { 'Cache-Control': 'no-store', 'Vary': 'Origin' },
			});
		}

		// 浏览器发出的 Service Worker 脚本请求必须在服务端拒绝。
		// 仅覆盖 navigator.serviceWorker.register 可被干净的 iframe realm 绕过。
		if ((request.headers.get('service-worker') || '').toLowerCase() === 'script' ||
			(request.headers.get('sec-fetch-dest') || '').toLowerCase() === 'serviceworker') {
			return new Response('代理域不允许注册 Service Worker', {
				status: 403, headers: { 'Cache-Control': 'no-store' },
			});
		}

		// ---- CORS 预检 ----
		if (request.method === 'OPTIONS' && request.headers.has('access-control-request-method')) {
			const headers = new Headers();
			applyCors(headers, request);
			return new Response(null, { status: 204, headers });
		}

		const isWebSocket = (request.headers.get('Upgrade') || '').toLowerCase() === 'websocket';

		// ---- robots.txt：允许收录首页，禁止抓取代理目标路径以防耗尽 Worker 配额 ----
		if (!isWebSocket && url.pathname === '/robots.txt') {
			return new Response(request.method === 'HEAD' ? null :
`User-agent: *
Allow: /$
Disallow: /
`,
				{ headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=86400' } }
			);
		}

		// ---- 漏网的站内相对请求：innerHTML、location.href = '/x'、Worker 内请求、默认 /favicon.ico 等未经改写的地址
		//      会直接落到代理域。路径不带协议而 Referer 是代理页面时，按来源页的目标站点还原并重定向 ----
		const usesRefererRoute = !isProxiedPath(url.pathname) && !/^(?:https?|wss?):\/\//i.test(trimUrlSpace(decodeProxyPath(url.pathname)).replace(/^\/+/, ''));
		let refererRouted = null;
		if (usesRefererRoute) {
			const refTarget = refererTarget(request, workerOrigin, env);
			if (refTarget) {
				const leaked = new URL(refTarget.origin + url.pathname + urlSuffix(url).split('#', 1)[0]);
				// 浏览器不跟随 WebSocket 握手的重定向（如无 shim 的 Worker 内相对地址），直接按来源页目标转发。
				if (isWebSocket) refererRouted = leaked;
				else return new Response(null, {
					status: 307,
					headers: { 'Location': toProxyUrl(leaked.href, workerOrigin), 'Cache-Control': 'no-store' },
				});
			}
		}

		// ---- 首页：代理页面发出的 "/"（location.href = '/'、fetch('/') 等）已在上面还原为目标站根路径 ----
		if (!isWebSocket && (url.pathname === '/' || url.pathname === '')) {
			return new Response(request.method === 'HEAD' ? null : getRootHtml(), {
				headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
			});
		}

		// ---- favicon 等杂项，避免被当成目标域名 ----
		if (!refererRouted && (url.pathname === '/robots.txt' || /^\/(favicon\.ico|sitemap\.xml|apple-touch-icon.*\.png|\.well-known\/.*)$/i.test(url.pathname))) {
			return new Response(null, { status: 404, headers: { 'Cache-Control': 'no-store' } });
		}

		// ---- 解析目标 URL ----
		const targetUrl = refererRouted || parseTarget(url);
		if (!targetUrl) {
			return invalidTargetPage(url);
		}
		const policyError = targetPolicyError(targetUrl, env);
		if (policyError) return new Response(policyError.message, {
			status: policyError.status, headers: { 'Cache-Control': 'no-store' },
		});
		// 防环：不允许代理 Worker 自身（比较规范化主机名与端口）
		if (normalizeHostname(targetUrl.hostname) === normalizeHostname(url.hostname) &&
			targetUrl.port === url.port) {
			return invalidTargetPage(url, '不允许代理本站自身');
		}

		// 本请求的 cookie 来源作用域（WebSocket 与其对应 HTTP 来源共享）
		const ck = {
			ns: cookieNamespace(targetUrl),
			varyOnReferer: usesRefererRoute,
			isHttps: url.protocol === 'https:' && ['https:', 'wss:'].includes(targetUrl.protocol),
		};

		// WebSocket 请求走独立通道
		if (isWebSocket) {
			if (request.method !== 'GET') return new Response('WebSocket 握手需要 GET', {
				status: 405, headers: { Allow: 'GET', 'Cache-Control': 'no-store' },
			});
			try {
				return await handleWebSocket(request, targetUrl, ck, workerOrigin, env);
			} catch {
				return new Response('WebSocket 代理失败：无法连接上游', {
					status: 502, headers: { 'Cache-Control': 'no-store' },
				});
			}
		}

		// ---- 构造转发请求 ----
		if (targetUrl.protocol === 'ws:' || targetUrl.protocol === 'wss:') {
			targetUrl.protocol = targetUrl.protocol === 'ws:' ? 'http:' : 'https:';
		}
		const fetchUrl = targetUrl.href;

		const fwdHeaders = buildUpstreamHeaders(request, workerOrigin, targetUrl, env);
		// 交由 Workers 协商编码，而不是转发运行时未必能解码的客户端编码。
		fwdHeaders.delete('Accept-Encoding');
		// Cookie 按站点隔离：只回传属于当前目标站点的那部分，并剥掉命名空间前缀
		applyRequestCookieScope(fwdHeaders, request, ck.ns);
		// 记录是否真的带 Cookie 回源，供缓存策略判断
		ck.hasCookie = fwdHeaders.has('cookie');

		let upstream;
		try {
			upstream = await fetch(fetchUrl, {
				method: request.method,
				signal: request.signal,
				headers: fwdHeaders,
				body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
				redirect: 'manual',
				// 响应的 no-store 无法阻止 fetch 先命中 Cloudflare 的上游缓存。
				cache: ck.hasCookie || fwdHeaders.has('authorization') ? 'no-store' : undefined,
			});
		} catch {
			return errorPage();
		}

		// Response 构造器只接受 200–599。LinkedIn 的 999 这类状态无法转发，统一按上游失败处理，
		// 否则 try 之外的 HEAD/重定向分支会抛出未捕获的 RangeError。
		if (upstream.status < 200 || upstream.status > 599) {
			if (upstream.body) upstream.body.cancel().catch(() => {});
			return errorPage();
		}

		// ---- 重定向 ----
		if (REDIRECT_STATUS.has(upstream.status) && upstream.headers.get('Location')) {
			const resp = buildResponse(upstream, request, ck, fetchUrl);
			// 丢弃重定向正文时显式取消上游流，且原正文长度/编码/摘要不再有效。
			if (resp.body) resp.body.cancel().catch(() => {});
			// 浏览器只看到同一个代理源，不会像真正的跨源重定向那样删除 Authorization。
			const nextLocation = resp.headers.get('Location');
			if (nextLocation && fwdHeaders.has('Authorization')) {
				const next = parseTarget(new URL(nextLocation, workerOrigin));
				if (!next || next.origin !== targetUrl.origin) {
					return new Response('不能跨目标来源重定向带 Authorization 的请求', {
						status: 502, headers: { 'Cache-Control': 'no-store' },
					});
				}
			}
			stripTransformedHeaders(resp.headers);
			return new Response(null, resp);
		}

		// ---- 204 / 205 / 304 无正文 ----
		if ([204, 205, 304].includes(upstream.status) || request.method === 'HEAD') {
			const resp = buildResponse(upstream, request, ck, fetchUrl);
			if (resp.body) resp.body.cancel().catch(() => {});
			// 这些字段描述的是原始字节；没有正文时无法判断是否触发大小限制，
			// 因而不能冒充下游 GET 的长度、编码、摘要或验证器。
			const kind = [204, 205, 206].includes(upstream.status) || hasNoTransform(request.headers.get('Cache-Control'))
				? null : transformKind(upstream.headers, request);
			// 声明长度超过上限且无需解码的正文必然原样透传，HEAD 可沿用与 GET 相同的表示元数据。
			const declaredLength = Number(upstream.headers.get('Content-Length'));
			const passthrough = kind !== null && kind !== 'html' && request.method === 'HEAD' &&
				declaredLength > MAX_TRANSFORM_BYTES && contentCoding(upstream.headers) === 'identity';
			if (kind && !passthrough) {
				stripTransformedHeaders(resp.headers);
				// 304 不重复声明媒体类型。HEAD 必须保留它：HTML 总会流式改写为 UTF-8；
				// 其它类型的 charset 取决于正文大小是否触发透传，只保留不含参数的媒体类型。
				if (upstream.status === 304) resp.headers.delete('Content-Type');
				else {
					const mime = mimeType(upstream.headers.get('Content-Type'));
					resp.headers.set('Content-Type', kind === 'html' ? `${mime}; charset=UTF-8` : mime);
				}
			}
			return new Response(null, resp);
		}

		// 局部正文不能安全重写：保留原始字节、Content-Range 与验证器。
		if (upstream.status === 206) return buildResponse(upstream, request, ck, fetchUrl);

		try {
			// 非目标媒体、附件或禁止变换的表示不会被读取或转码。
			const kind = transformKind(upstream.headers, request);
			if (!kind || hasNoTransform(request.headers.get('Cache-Control'))) {
				return buildResponse(upstream, request, ck, fetchUrl);
			}
			const contentType = upstream.headers.get('Content-Type');
			const baseUrl = documentBase(targetUrl);
			const charset = getCharset(contentType);
			if (kind === 'html') {
				// BOM 优先于 HTTP charset，最后才读文档内声明。
				const isXml = mimeType(contentType) === 'application/xhtml+xml';
				const sniffed = await sniffHtmlCharset(upstream.body, charset, isXml);
				let body = sniffed.body;
				if (body && (isXml || !isUtf8Charset(sniffed.charset))) {
					try {
						const decoder = new TextDecoderStream(sniffed.charset || 'utf-8');
						const encoder = new TextEncoderStream();
						let text = body.pipeThrough(decoder);
						if (isXml) text = normalizeXhtmlProlog(text);
						body = text.pipeThrough(encoder);
					} catch { /* 保留当前流供 UTF-8 宽松解码 */ }
				}
				const interim = new Response(body, upstream);
				stripResponseHeaders(interim.headers, request, baseUrl);
				stripHopByHop(interim.headers);
				stripTransformedHeaders(interim.headers);
				interim.headers.set('Content-Type', mimeType(contentType) + '; charset=UTF-8');
				return applyCommon(transformHtml(interim, baseUrl, workerOrigin, ck), request, ck);
			}
			return applyCommon(await transformText(upstream, baseUrl, workerOrigin, kind, request, charset), request, ck);
		} catch {
			return errorPage();
		}
	},
};

/** 所有回源 HTTP 响应（含流式 HTML）共用相同的下游策略。 */
function applyCommon(resp, request, ck) {
	stripHopByHop(resp.headers);
	if (ENABLE_PROXY_NOINDEX) {
		resp.headers.set('X-Robots-Tag', 'noindex, nofollow');
	}
	applyCors(resp.headers, request);
	applyCachePolicy(resp, request, ck);
	if (ck) rescopeSetCookies(resp.headers, ck.ns, ck.isHttps);
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

function errorPage() {
	return new Response(renderErrorPage(
		'请求上游失败',
		'无法处理上游响应。目标站点可能拒绝了来自 Cloudflare 的请求，或暂时不可用。'
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
  var dark=(saved==='dark'||saved==='light')?saved==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;
  root.setAttribute('data-theme',dark?'dark':'light');
  var h=null;
  try{h=localStorage.getItem('pe-hue');}catch(e){}
  var hn=parseFloat(h);
  if(Number.isFinite(hn)){hn=((hn%360)+360)%360;root.style.setProperty('--hue',String(hn));root.style.setProperty('--hue3',String((hn+60)%360));}
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
    if(saved!=='dark'&&saved!=='light')document.documentElement.setAttribute('data-theme',e.matches?'dark':'light');
  });
}catch(e){}
/* 涟漪 */
document.addEventListener('pointerdown',function(e){
  var t=e.target;
  if(t&&!t.closest)t=t.parentElement;
  var el=t&&t.closest?t.closest('.md-ripple'):null;
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
/* 加载态（含 bfcache 返回时自动复位遮罩） */
window.__peBusy=function(on){
  var el=$('busy');if(el)el.classList.toggle('show',!!on);
};
window.addEventListener('pageshow',function(){window.__peBusy(false);});
/* 种子色（Material You 动态色） */
var HUES=[285,250,200,155,35,330];
var row=$('hueRow');
if(row){
  var cur=getComputedStyle(document.documentElement).getPropertyValue('--hue').trim()||'285';
  var selected=HUES.findIndex(function(h){return Math.abs(parseFloat(cur)-h)<1;});
  var radios=[];
  HUES.forEach(function(h,index){
    var b=document.createElement('button');
    b.type='button';b.className='hue-dot';b.style.setProperty('--h',h);
    b.setAttribute('role','radio');
    b.setAttribute('aria-checked',String(index===selected));
    b.tabIndex=index===Math.max(0,selected)?0:-1;
    b.setAttribute('aria-label','主题色 '+h);
    b.addEventListener('click',function(){
      var root=document.documentElement;
      root.style.setProperty('--hue',String(h));
      root.style.setProperty('--hue3',String((h+60)%360));
      try{localStorage.setItem('pe-hue',String(h));}catch(e){}
      radios.forEach(function(x){x.setAttribute('aria-checked',String(x===b));x.tabIndex=x===b?0:-1;});
    });
    radios.push(b);
    row.appendChild(b);
  });
  row.addEventListener('keydown',function(e){
    var i=radios.indexOf(e.target);
    if(i<0)return;
    var delta=e.key==='ArrowRight'||e.key==='ArrowDown'?1:e.key==='ArrowLeft'||e.key==='ArrowUp'?-1:0;
    if(!delta)return;
    e.preventDefault();
    var next=radios[(i+delta+radios.length)%radios.length];
    next.click();
    next.focus();
  });
}
})();`;

// ---- 页面骨架公共部分 ----
function md3Head(title, desc, robots = 'index, follow') {
	return `<!DOCTYPE html>
<html lang="zh-CN" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<meta name="description" content="${escapeHtml(desc)}">
${robots ? `<meta name="robots" content="${escapeHtml(robots)}">\n` : ''}<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌐</text></svg>">
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

  <p class="t-body-sm muted footer enter d2">Made with ❤️ by lingyicute</p>
</main>
${md3Overlays()}
<script>${MD3_JS}
(function(){
${browserPathHelpers()}
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
    var selfH=location.hostname.toLowerCase().replace(/\\.+$/,'');
    if(/^(?:https?:)?\\/\\//i.test(v)){
      try{
        var u0=new URL(v,location.href);
        if(u0.hostname.toLowerCase().replace(/\\.+$/,'')===selfH&&u0.port===location.port&&
           isProxiedPath(u0.pathname)){
          v=u0.pathname+urlSuffix(u0);
        }
      }catch(_){}
    }
    var qIdx=v.search(/[?#]/);
    var pPart=qIdx>=0?v.slice(0,qIdx):v;
    var sPart=qIdx>=0?v.slice(qIdx):'';
    if(!/^(?:https?|wss?):\\/\\//i.test(pPart)&&isProxiedPath('/'+pPart.replace(/^\\/+/,'') )){
      var dec=decodeProxyPath(pPart).replace(/^ws(s?):\\/\\//i,'http$1://');
      if(dec){
        var hIdx=dec.indexOf('#');
        if(hIdx>=0)dec=dec.slice(0,hIdx);
        if(sPart.charAt(0)==='?'&&dec.indexOf('?')>=0)sPart='&'+sPart.slice(1);
        v=dec+sPart;
      }
    }
    if(/^[a-z][a-z0-9+.-]*:/i.test(v)&&!/^https?:\\/\\//i.test(v)&&!/^(?:localhost\\.?|[a-z0-9_-]+\\.[a-z0-9_.-]+):\\d+(?:[/?#]|$)/i.test(v)){
      window.__peSnack('仅支持 http:// 或 https:// 网址');
      input.focus();
      return;
    }
    if(!/^https?:\\/\\//i.test(v))v='https://'+v.replace(/^\\/+/,'');
    var u=null;
    try{u=new URL(v);}catch(_){}
    var rawH=u&&u.hostname?u.hostname.toLowerCase():'';
    var h=rawH.replace(/\\.+$/,'');
    if(u&&h){try{u.hostname=h;h=u.hostname.toLowerCase().replace(/\\.+$/,'');}catch(_){u=null;}}
    if(!u||u.username||u.password||!h||rawH.charAt(0)==='.'||rawH.indexOf('..')>=0||(h.indexOf('.')<0&&h!=='localhost'&&h.charAt(0)!=='[')){
      window.__peSnack('请输入有效的网址，例如 example.com');
      input.focus();
      return;
    }
    if(/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(h)||h.charAt(0)==='['||h==='localhost'||/\\.(localhost|local|internal)$/.test(h)){
      window.__peSnack('不允许代理 IP 字面量或本地目标名称');
      input.focus();
      return;
    }
    if(h===selfH&&u.port===location.port){
      window.__peSnack('不允许代理本站自身');
      input.focus();
      return;
    }
    var nextHref=encodeProxyPath(u);
    window.__peBusy(true);
    setTimeout(function(){
      location.href=nextHref;
    },260);
  });
})();
</script>
</body>
</html>`;
}

// ---- 错误页 ----
// “返回首页”不带 Referer：来自代理页面的 "/" 会被还原为目标站根路径。
function renderErrorPage(title, message) {
	return md3Head(title + ' · ProxyEverything', 'ProxyEverything 错误提示', 'noindex, nofollow') + `
<body>
<div class="err-wrap">
  <section class="card dialog enter" role="alertdialog" aria-labelledby="errTitle">
    <div class="err-icon">${ICON.warn}</div>
    <h1 class="t-headline-sm" id="errTitle">${escapeHtml(title)}</h1>
    <p class="t-body-md muted">${message}</p>
    <div class="actions">
      <button class="text-btn md-ripple" type="button" onclick="location.reload()"><span class="t-label-lg">重试</span></button>
      <a class="tonal-btn md-ripple" href="/" rel="noreferrer"><span class="t-label-lg">返回首页</span></a>
    </div>
  </section>
</div>
<script>${MD3_JS}</script>
</body>
</html>`;
}
