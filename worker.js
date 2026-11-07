/**
 * ProxyEverything — 通用网页反向代理 Cloudflare Worker
 *
 * URL 方案：
 *   https://proxy-any.92li.uk/<encodeURIComponent(目标URL的路径部分)>?目标查询串
 *   例：https://example.com/page?a=1
 *     → https://proxy-any.92li.uk/https%3A%2F%2Fexample.com%2Fpage?a=1
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
	'clear-site-data',    // 上游不能清空整个代理域的 Cookie/存储/缓存
	'service-worker-allowed', // 上游不能扩大代理域上的 Service Worker 作用域
	'speculation-rules',  // 预取/预渲染规则头指向原站路径，剥除以防绕过代理
	'www-authenticate',   // 原生 HTTP 认证会把不同目标折叠进代理域同一个保护空间
	'authentication-info',
	'referrer-policy',    // 防止上游策略剥除同源代理路径导致回源 Referer 丢失目标地址
	'reporting-endpoints',
];

// 仅正文变换时移除；透传响应必须保留其表示元数据。
const TRANSFORMED_HEADERS = [
	'content-encoding', 'content-length', 'etag', 'last-modified',
	'content-md5', 'digest', 'content-digest', 'repr-digest',
	'content-range', 'accept-ranges',
];
const MAX_TRANSFORM_BYTES = 2 * 1024 * 1024;
const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

// 禁止 Connection 头夹带并借机剥除端到端关键语义头（RFC 9110 §7.6.1）
const PROTECTED_END_TO_END = new Set([
	'content-type', 'content-length', 'content-encoding', 'content-range', 'content-language',
	'set-cookie', 'cookie', 'location', 'cache-control', 'vary',
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

function stripTransformedHeaders(headers) {
	for (const name of TRANSFORMED_HEADERS) headers.delete(name);
}

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

/**
 * 目标绝对 URL → 代理 URL（同源相对地址，可安全写入 href/src）
 * 查询串保持明文（与原实现兼容），哈希原样保留。
 */
function toProxyUrl(targetUrl, workerOrigin) {
	const u = new URL(targetUrl);
	if (u.protocol !== 'http:' && u.protocol !== 'https:' &&
		u.protocol !== 'ws:' && u.protocol !== 'wss:') return targetUrl;
	const host = normalizeHostname(u.hostname);
	if (host) {
		try { u.hostname = host; } catch {}
	}
	return `${workerOrigin}/${encodeURIComponent(u.protocol + '//' + u.host + u.pathname)}${u.search}${u.hash}`;
}

/**
 * 任意形式的 URL（绝对/协议相对/根相对/相对/已代理）→ 代理 URL。
 * 解析失败或不可代理的 scheme（data:、javascript:、mailto: 等）原样返回。
 */
function isProxiedPath(pathname) {
	return /^\/(https?|wss?)(?:%3A|:)(?:%2F|\/){2}/i.test(pathname);
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

function rewriteUrl(value, baseUrl, workerOrigin) {
	if (value == null) return value;
	let v = String(value).trim();
	if (!v) return v;
	// 页内锚点（#foo、url(#gradient)）保持原样
	if (v.startsWith('#')) return v;
	// 已经是本站代理 URL
	if (isProxiedPath(v)) return v;
	if (v.startsWith(workerOrigin + '/') && isProxiedPath(v.slice(workerOrigin.length))) return v;
	try {
		const abs = new URL(v, baseUrl);
		if (abs.protocol !== 'http:' && abs.protocol !== 'https:' &&
			abs.protocol !== 'ws:' && abs.protocol !== 'wss:') {
			return v;
		}
		if (isWorkerHost(abs, workerOrigin)) {
			// 已代理（同源主机且路径是编码后的目标 URL）
			if (isProxiedPath(abs.pathname)) {
				if (!/^([a-z][a-z0-9+.-]*:)?\/\//i.test(v)) {
					return abs.pathname + abs.search + abs.hash;
				}
				const origin = abs.protocol === 'ws:' || abs.protocol === 'wss:'
					? `${abs.protocol}//${new URL(workerOrigin).host}`
					: workerOrigin;
				return `${origin}${abs.pathname}${abs.search}${abs.hash}`;
			}
			// 落到代理域自身的非代理路径：回退按目标基地址解析，避免触发自代理拦截
			const rebound = new URL(abs.pathname + abs.search + abs.hash, baseUrl);
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
function isSrcsetSpace(ch) {
	return ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\f';
}

function rewriteSrcset(value, baseUrl, workerOrigin) {
	const s = String(value);
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
		let url = s.slice(urlStart, i);
		let trailing = '';
		const m = /,+$/.exec(url);
		if (m) {
			trailing = m[0];
			url = url.slice(0, url.length - trailing.length);
		}
		if (url) out += rewriteUrl(url, baseUrl, workerOrigin);
		out += trailing;
		if (trailing) continue; // 该候选项没有描述符，直接进入下一轮

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

/** CSS 字符串不能直接沿用源引号：解析相对地址后可能从基地址继承 ' 或括号。 */
function quoteCssString(value) {
	return '"' + String(value).replace(/["\\\x00-\x1f\x7f]/g, ch =>
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
		if (/[\n\r\f]/.test(css[i])) break; // bad-string-token
		if (css[i] === '\\') i = cssEscapeEnd(css, i);
		else i++;
	}
	return { end: i, value: null };
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
	let i = skipCssSpace(css, start, true);
	if (css[i] === '"' || css[i] === "'") {
		const str = readCssString(css, i);
		i = skipCssSpace(css, str.end, true);
		if (str.value !== null && css[i] === ')') return { end: i + 1, value: str.value };
		while (i < css.length && css[i] !== ')') {
			if (css[i] === '"' || css[i] === "'") { i = readCssString(css, i).end; continue; }
			if (css.startsWith('/*', i)) { i = skipCssSpace(css, i, true); continue; }
			i = isValidCssEscape(css, i) ? cssEscapeEnd(css, i) : i + 1;
		}
		return { end: Math.min(i + 1, css.length), value: null };
	} else {
		i = skipCssSpace(css, start);
		const valueStart = i;
		while (i < css.length) {
			if (css[i] === ')') return { end: i + 1, value: decodeCssEscapes(css.slice(valueStart, i)) };
			if (isSrcsetSpace(css[i])) {
				const end = skipCssSpace(css, i);
				if (css[end] === ')') return { end: end + 1, value: decodeCssEscapes(css.slice(valueStart, i)) };
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

/**
 * 线性扫描 CSS URL token 与 @import 字符串，不匹配注释/普通字符串。
 * 这不是完整 CSS AST：仅改写 URL 载荷，其余源码（包括 media/layer 条件）保持原样。
 */
function rewriteCss(css, baseUrl, workerOrigin) {
	const source = String(css);
	const parts = [];
	let cursor = 0;
	let i = 0;
	let parenDepth = 0;
	const imageSetDepths = [];
	let expectImageSetOption = false;
	const isName = ch => !!ch && /[a-z0-9_\-\u0080-\uffff]/i.test(ch);
	const replace = (start, end, value, wrapUrl = false) => {
		if (value === null || !value) return;
		const rewritten = rewriteUrl(value, baseUrl, workerOrigin);
		if (rewritten === value) return;
		const quoted = quoteCssString(rewritten);
		parts.push(source.slice(cursor, start), wrapUrl ? `url(${quoted})` : quoted);
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
		while (isName(source[i]) || isValidCssEscape(source, i)) {
			i = source[i] === '\\' ? cssEscapeEnd(source, i) : i + 1;
		}
		if (i === nameStart) { i = Math.max(i, start + 1); continue; }
		const name = decodeCssEscapes(source.slice(nameStart, i)).toLowerCase();
		if (prefix === '@' && name === 'import') {
			const valueStart = skipCssSpace(source, i, true);
			if (source[valueStart] === '"' || source[valueStart] === "'") {
				const str = readCssString(source, valueStart);
				replace(valueStart, str.end, str.value);
				i = str.end;
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
	parts.push(source.slice(cursor));
	return parts.join('');
}

/** 重写内联 style / CSS 字符串中的 url() */
function rewriteStyleAttr(style, baseUrl, workerOrigin) {
	return rewriteCss(style, baseUrl, workerOrigin);
}

/** 重写 <meta http-equiv="refresh" content="0; url=...">（兼容省略 url= 的规范写法，避免误匹配查询串内 url= 或空 url= 回溯） */
function rewriteRefreshContent(content, baseUrl, workerOrigin) {
	const stripQuotes = s => s.trim().replace(/^(['"])([\s\S]*?)\1[\s\S]*$/, '$2').replace(/^['"]|['"]$/g, '').trim();
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

/**
 * 改写上游 Set-Cookie：加命名空间前缀、强制 Path=/、去掉 Domain，
 * 并按 Worker 自身协议修正 Secure / SameSite。
 * 返回 null 表示这条 cookie 无效、应丢弃。
 */
function scopeSetCookie(c, ns, workerIsHttps) {
	const parts = String(c).split(';');
	const head = parts[0];
	const eq = head.indexOf('=');
	if (eq < 0) return null;
	const name = head.slice(0, eq).trim();
	if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(name)) return null;
	const value = head.slice(eq + 1).trim();

	const out = [`${ns}${name}=${value}`];
	let sameSiteNone = false;
	let hasSecure = false;
	let hasPartitioned = false;

	for (const raw of parts.slice(1)) {
		const part = raw.trim();
		if (!part) continue;
		const attr = part.slice(0, part.indexOf('=') === -1 ? undefined : part.indexOf('=')).trim().toLowerCase();
		// Domain / Path 一律由我们接管
		if (attr === 'domain' || attr === 'path') continue;
		if (attr === 'secure') {
			// Worker 跑在 http 上时保留 Secure 会让浏览器直接丢弃这条 cookie
			if (workerIsHttps && !hasSecure) { out.push('Secure'); hasSecure = true; }
			continue;
		}
		if (attr === 'partitioned') {
			// CHIPS Partitioned 属性同样要求 Secure，HTTP 下必须剥除
			if (workerIsHttps && !hasPartitioned) { out.push('Partitioned'); hasPartitioned = true; sameSiteNone = true; }
			continue;
		}
		if (attr === 'samesite') {
			// SameSite 必须带值；遇到 `Set-Cookie: a=b; SameSite` 这种无值写法，
			// 直接丢弃，否则会拼出 SameSite=SameSite 这种垃圾属性
			const eqi = part.indexOf('=');
			if (eqi < 0) continue;
			const val = part.slice(eqi + 1).trim();
			if (!val) continue;
			const isNone = val.toLowerCase() === 'none';
			sameSiteNone = sameSiteNone || isNone;
			if (!isNone || workerIsHttps) out.push(`SameSite=${val}`);
			continue;
		}
		out.push(part);
	}

	out.push('Path=/');
	// SameSite=None / Partitioned 必须伴随 Secure，否则现代浏览器拒绝写入
	if (sameSiteNone && workerIsHttps && !hasSecure) out.push('Secure');
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
		.filter(([n]) => n.startsWith(ns))
		.map(([n, v]) => [n.slice(ns.length), v])
		.filter(([n]) => /^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(n));
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
	// getSetCookie 才能拿到多条 Set-Cookie；退化成 get 时只会有一条
	const list = headers.getSetCookie
		? headers.getSetCookie()
		: (headers.get('set-cookie') ? [headers.get('set-cookie')] : []);
	if (!list.length) return;
	headers.delete('set-cookie');
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
	let cs = String(label).trim().toLowerCase();
	if (!cs) return null;
	if (fromMetaOrCss) {
		// HTML / CSS 规范：meta 或 @charset 声明的 UTF-16 视为 UTF-8，x-user-defined 视为 windows-1252。
		if (/^utf-16(?:le|be)?$/.test(cs)) cs = 'utf-8';
		else if (cs === 'x-user-defined') cs = 'windows-1252';
	}
	if (isUtf8Charset(cs)) return 'utf-8';
	try {
		new TextDecoder(cs);
		return cs;
	} catch {
		return null;
	}
}

/** 从 Content-Type 中提取受支持的 charset 标签（非法标签忽略以便回退嗅探） */
function getCharset(contentType) {
	const m = /(?:^|;)\s*charset\s*=\s*(?:"\s*([\w\-:.]+)\s*"|'\s*([\w\-:.]+)\s*'|([\w\-:.]+)\s*(?=$|;))/i.exec(contentType || '');
	return m ? normalizeCharsetLabel(m[1] || m[2] || m[3], false) : null;
}

/**
 * HTML 编码优先级：BOM > HTTP charset > 完整的 meta / XML 声明。
 * 一旦确定编码就停止嗅探，不必等到 4096 字节/EOF 才开始向浏览器输出。
 * tee 的另一支保留全部字节；只在固定大小的前缀缓冲中检查声明。
 */
async function sniffHtmlCharset(body, declaredCharset = null) {
	if (!body) return { charset: declaredCharset, body };
	const [a, b] = body.tee();
	const reader = a.getReader();
	const head = new Uint8Array(4096);
	let total = 0;
	let charset = declaredCharset;
	try {
		while (total < head.length) {
			const { done, value } = await reader.read();
			if (done) break;
			const prefix = value.subarray(0, head.length - total);
			head.set(prefix, total);
			total += prefix.length;
			if (total >= 2 && head[0] === 0xff && head[1] === 0xfe) { charset = 'utf-16le'; break; }
			if (total >= 2 && head[0] === 0xfe && head[1] === 0xff) { charset = 'utf-16be'; break; }
			if (total < 3) continue;
			if (head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf) { charset = 'utf-8'; break; }
			if (declaredCharset) break;
			// 剥除 HTML 注释后再扫描 meta，避免被注释掉的旧版编码声明误导。
			const text = new TextDecoder().decode(head.subarray(0, total)).replace(/<!--[\s\S]*?(?:-->|$)/g, '');
			const xml = /^\s*<\?xml\b[^>]{0,200}?\bencoding\s*=\s*(["'])\s*([a-z0-9_\-:.]+)\s*\1[^>]*\?>/i.exec(text);
			if (xml) {
				const valid = normalizeCharsetLabel(xml[2], false);
				if (valid) { charset = valid; break; }
			}
			// 不把分片边界处尚未闭合的属性值当成完整编码名；仅采纳直接 charset 属性或 http-equiv=content-type 的 content。
			for (const [, rawAttrs] of text.matchAll(/<meta\b((?:[^>"']|"[^"]*"|'[^']*'){0,500}?)\s*\/?>/gi)) {
				const attrs = {};
				for (const [, k, dq, sq, uq] of rawAttrs.matchAll(/([a-z0-9_-]+)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`]+)))?/gi)) {
					const name = k.toLowerCase();
					if (!(name in attrs)) attrs[name] = dq ?? sq ?? uq ?? '';
				}
				if (attrs.charset) {
					const valid = normalizeCharsetLabel(attrs.charset.replace(/\/+$/, ''), true);
					if (valid) { charset = valid; break; }
				}
				if ((attrs['http-equiv'] || '').trim().toLowerCase() === 'content-type' && attrs.content) {
					const m = /(?:^|;)\s*charset\s*=\s*(?:"\s*([a-z0-9_\-:.]+)\s*"|'\s*([a-z0-9_\-:.]+)\s*'|([a-z0-9_\-:.]+)\s*(?=$|[\s;]))/i.exec(attrs.content);
					if (m) {
						const valid = normalizeCharsetLabel(m[1] || m[2] || m[3], true);
						if (valid) { charset = valid; break; }
					}
				}
			}
			if (charset) break;
		}
	} finally {
		// 不 await：tee 另一支消费完之前 cancel 可能不 resolve。
		reader.cancel().catch(() => {});
		reader.releaseLock();
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

/** 构造透传 Response（headers 可变），并做统一清洗 */
function buildResponse(upstream, request, ck) {
	const resp = new Response(upstream.body, upstream);
	for (const h of STRIP_RESPONSE_HEADERS) resp.headers.delete(h);
	stripHopByHop(resp.headers);
	if (ENABLE_PROXY_NOINDEX) {
		resp.headers.set('X-Robots-Tag', 'noindex, nofollow');
	}
	applyCors(resp.headers, request);
	// Set-Cookie 添加来源命名空间，避免回源时意外混用
	if (ck) rescopeSetCookies(resp.headers, ck.ns, ck.isHttps);
	applyCachePolicy(resp, request);
	return resp;
}

function isCacheableMethod(m) { return m === 'GET' || m === 'HEAD'; }

/** 代理把不同会话映射到同一 URL；有凭证或 Set-Cookie 时不允许共享缓存。 */
function applyCachePolicy(response, request) {
	if (response.status >= 500 || response.headers.has('set-cookie') ||
		(request && (!isCacheableMethod(request.method) || request.headers.has('cookie') ||
		request.headers.has('authorization')))) {
		response.headers.set('Cache-Control', 'no-store');
		response.headers.delete('cdn-cache-control');
		response.headers.delete('cloudflare-cdn-cache-control');
		response.headers.delete('surrogate-control');
	}
}

// ============================================================
// 运行时注入脚本（浏览器端 shim）
// 让 JS 动态发起的请求（fetch/XHR/WebSocket/img.src 等）也走代理
// ============================================================

function getShimScript(workerOrigin, cookieNs) {
	return `<script>(function(){
try{
var WO=${JSON.stringify(workerOrigin)};
var WOU=new URL(WO);
var WOH=WOU.hostname.toLowerCase().replace(/\\.+$/,'');
var WOP=WOU.port||'';
var CK=${JSON.stringify(cookieNs || '')};
function decSafe(s){
  try{return decodeURIComponent(s);}catch(e){
    try{return decodeURIComponent(String(s).replace(/%(?![0-9a-f]{2})/gi,'%25'));}catch(_){return s;}
  }
}
function isSelfHost(u){
  var h=(u&&u.hostname||'').toLowerCase().replace(/\\.+$/,'');
  if(!h)return false;
  var p=u.port||'';
  var lh=(location.hostname||'').toLowerCase().replace(/\\.+$/,'');
  return (h===WOH&&p===WOP)||(Boolean(lh)&&h===lh&&p===(location.port||''));
}
function currentTarget(){
var RAW=location.pathname.substring(1);
var DEC=decSafe(RAW).trim().replace(/^\\/+/,'');
if(!/^[a-z][a-z0-9+.-]*:\\/\\//i.test(DEC))DEC='https://'+DEC;
var hIdx=DEC.indexOf('#');if(hIdx>=0)DEC=DEC.substring(0,hIdx);
var full=DEC+(location.search?(DEC.indexOf('?')>=0?'&':'?')+location.search.substring(1):'');
try{var u=new URL(full);if(u.protocol==='ws:')u.protocol='http:';else if(u.protocol==='wss:')u.protocol='https:';u.username='';u.password='';u.hostname=u.hostname.toLowerCase().replace(/\\.+$/,'');return u.href;}catch(e){return full;}
}
var TARGET=currentTarget();
var ABS_RE=/^[a-z][a-z0-9+.-]*:\\/\\//i;
var SKIP_RE=/^(data:|blob:|javascript:|mailto:|tel:|sms:|about:|#)/i;
var PROXY_RE=/^\\/(https?|wss?)(?:%3A|:)(?:%2F|\\/){2}/i;
function base(){
  var target=currentTarget();
  var list=document.querySelectorAll?document.querySelectorAll('base[data-pe-base],base[href]'):[];
  if(!list.length&&document.querySelector){var b0=document.querySelector('base[data-pe-base],base[href]');if(b0)list=[b0];}
  for(var i=0;i<list.length;i++){
    var b=list[i];
    var h=b.getAttribute('data-pe-base')||b.getAttribute('href');
    if(h){try{var u=new URL(h,target);if(u.protocol==='http:'||u.protocol==='https:')return u.href;}catch(e){}}
  }
  return target;
}
function rp(v){
  if(v==null)return v;
  if(typeof v==='object'){
    if(v instanceof URL)return rp(v.href);
    return v;
  }
  var s=String(v).trim();
  if(!s||SKIP_RE.test(s))return s;
  if(PROXY_RE.test(s))return s;
  var forcedWs='';
  try{
    if(s===WO)s='/';
    else if(ABS_RE.test(s)||s.indexOf('//')===0){
      var pu=new URL(s,WO);
      if(isSelfHost(pu)){
        if(PROXY_RE.test(pu.pathname)){
          if(pu.protocol==='ws:'||pu.protocol==='wss:'){
            var canonH=location.hostname||WOU.hostname;
            if(canonH&&pu.hostname!==canonH)pu.hostname=canonH;
            return pu.href;
          }
          return WO+pu.pathname+pu.search+pu.hash;
        }
        if(pu.protocol==='ws:'||pu.protocol==='wss:')forcedWs=pu.protocol;
        s=pu.pathname+pu.search+pu.hash;
      }
    }
  }catch(e){}
  var u;try{u=new URL(s,base());}catch(e){return s;}
  if(u.origin===WO&&PROXY_RE.test(u.pathname))return u.href;
  var p=forcedWs?(u.protocol==='http:'?'ws:':'wss:'):u.protocol;
  if(p!=='http:'&&p!=='https:'&&p!=='ws:'&&p!=='wss:')return s;
  var uh=u.hostname.toLowerCase().replace(/\\.+$/,'');
  if(uh){try{u.hostname=uh;}catch(e){}}
  return WO+'/'+encodeURIComponent(p+'//'+u.host+u.pathname)+u.search+u.hash;
}
function rwUrlArg(a){
  if(typeof a==='string')return rp(a);
  if(a instanceof URL)return new URL(rp(a.href),location.href||WO);
  return a;
}
function rpBase(a){
  if(typeof a==='string'&&!a.trim())return rp(base());
  return rwUrlArg(a);
}
function rwInit(init){
  if(!init||typeof init!=='object')return init;
  var ref=init.referrer;
  var refStr=ref instanceof URL?ref.href:typeof ref==='string'?ref:'';
  if(refStr&&refStr!=='about:client'){
    var nr=rp(refStr);
    if(nr&&nr!==ref)return Object.assign({},init,{referrer:nr});
  }
  return init;
}
window.__PE__={get target(){return currentTarget();},rp:rp};
/* Request 必须在浏览器把相对地址解析到代理域之前改写；流式/POST Request 重建时需声明 duplex: 'half'，
   且 ReadableStream 正文在 Fetch 规范下不允许与 keepalive: true 或 mode: 'no-cors' 并存。 */
var oRequest=window.Request;
function buildReq(u,r){
  var m=r.method||'GET';
  var mUp=String(m).toUpperCase();
  var b=mUp!=='GET'&&mUp!=='HEAD'?r.body:undefined;
  var md=r.mode==='navigate'||(b&&r.mode==='no-cors')?'same-origin':r.mode;
  var ref=r.referrer;
  if(typeof ref==='string'&&ref&&ref!=='about:client')ref=rp(ref);
  return new oRequest(u,{
    method:m,headers:r.headers,
    body:b,
    mode:md,
    credentials:r.credentials,cache:r.cache,redirect:r.redirect,
    referrer:ref,referrerPolicy:r.referrerPolicy,
    integrity:r.integrity,keepalive:b?false:r.keepalive,signal:r.signal,
    duplex:'half'
  });
}
function mergeReq(input,init){
  if(init===undefined)return input;
  try{return new oRequest(input,init);}catch(e){
    var merged={};
    ['method','headers','body','mode','credentials','cache','redirect','referrer','referrerPolicy','integrity','keepalive','signal'].forEach(function(k){
      merged[k]=init[k]!==undefined?init[k]:input[k];
    });
    return buildReq(input.url,merged);
  }
}
function rwReq(input,init){
  init=rwInit(init);
  var nu=rp(input.url);
  if(!nu||nu===input.url)return mergeReq(input,init);
  var r=mergeReq(input,init);
  return buildReq(nu,r);
}
if(oRequest){
  var ProxyRequest=function(input,init){
    if(!new.target)throw new TypeError('Request requires new');
    init=rwInit(init);
    if(input&&typeof input==='object'&&'url'in input)return rwReq(input,init);
    input=rpBase(input);
    try{return Reflect.construct(oRequest,[input,init],new.target);}catch(e){
      if(init&&typeof init==='object')return buildReq(input instanceof URL?input.href:input,init);
      throw e;
    }
  };
  ProxyRequest.prototype=oRequest.prototype;
  Object.setPrototypeOf(ProxyRequest,oRequest);
  window.Request=ProxyRequest;
}
/* ---- fetch ---- */
var of_=window.fetch;
if(of_)window.fetch=function(input,init){
  try{
    init=rwInit(init);
    if(typeof input==='string')input=rpBase(input);
    else if(input instanceof URL)input=rp(input.href);
    else if(input&&typeof input==='object'&&'url'in input&&oRequest){input=rwReq(input,init);init=undefined;}
  }catch(e){}
  return of_.call(this,input,init);
};
/* ---- XMLHttpRequest ---- */
var oOpen=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){
  try{arguments[1]=rpBase(u);}catch(e){}
  return oOpen.apply(this,arguments);
};
/* ---- EventSource / sendBeacon / Worker / Audio / WebSocket ---- */
if(window.EventSource){var oES=window.EventSource;var ES=function(u,c){var nu=rpBase(u);return arguments.length>1?new oES(nu,c):new oES(nu);};ES.prototype=oES.prototype;try{Object.setPrototypeOf(ES,oES);}catch(e){}window.EventSource=ES;}
if(navigator.sendBeacon){var oSB=navigator.sendBeacon.bind(navigator);navigator.sendBeacon=function(u,d){try{u=typeof u==='string'&&!u.trim()?rp(base()):rp(u);}catch(e){}return arguments.length>1?oSB(u,d):oSB(u);};}
if(window.Worker){var oWk=window.Worker;var Wk=function(u,o){var nu=rpBase(u);return arguments.length>1?new oWk(nu,o):new oWk(nu);};Wk.prototype=oWk.prototype;try{Object.setPrototypeOf(Wk,oWk);}catch(e){}window.Worker=Wk;}
try{if(window.SharedWorker){var oSW=window.SharedWorker;var SW=function(u,o){var nu=rpBase(u);return arguments.length>1?new oSW(nu,o):new oSW(nu);};SW.prototype=oSW.prototype;try{Object.setPrototypeOf(SW,oSW);}catch(e){}window.SharedWorker=SW;}}catch(e){}
try{if(window.Audio){var oAu=window.Audio;var Au=function(u){return u!==undefined?new oAu(rp(u)):new oAu();};Au.prototype=oAu.prototype;try{Object.setPrototypeOf(Au,oAu);}catch(e){}window.Audio=Au;}}catch(e){}
/* Service Worker 无法在代理路径下正确工作，直接禁用注册以免站点异常 */
try{if(navigator.serviceWorker)navigator.serviceWorker.register=function(){return Promise.reject(new Error('[ProxyEverything] service worker disabled'));};}catch(e){}
/* ---- WebSocket：目标地址已在路径内，无需污染目标查询串 ---- */
if(window.WebSocket){
  var oWS=window.WebSocket;
  var WS=function(u,protos){
    var nu=u;
    try{
      if(typeof u==='string')nu=rp(u);
      else if(u instanceof URL)nu=rp(u.href);
      if(typeof nu==='string'){
        var au=new URL(nu,location.href||WO);
        if(au.origin===WO||au.origin===location.origin||isSelfHost(au)){
          au.protocol=(location.protocol||au.protocol)==='https:'?'wss:':'ws:';
          nu=au.href;
        }
      }
    }catch(e){}
    return protos===undefined?new oWS(nu):new oWS(nu,protos);
  };
  WS.prototype=oWS.prototype;
  try{Object.setPrototypeOf(WS,oWS);}catch(e){}
  ['CONNECTING','OPEN','CLOSING','CLOSED'].forEach(function(k,i){try{WS[k]=i;}catch(e){}});
  window.WebSocket=WS;
}
/* ---- history / window.open / location.assign ---- */
function wrapHistory(fn){return function(st,t,u){try{if(u!=null)arguments[2]=rp(u);}catch(e){}return fn.apply(this,arguments);};}
if(history.pushState)history.pushState=wrapHistory(history.pushState);
if(history.replaceState)history.replaceState=wrapHistory(history.replaceState);
var oWo=window.open;
if(oWo)window.open=function(u){try{if(arguments.length&&u!=null)arguments[0]=rwUrlArg(u);}catch(e){}return oWo.apply(this,arguments);};
try{var oAs=location.assign.bind(location);location.assign=function(u){return oAs(typeof u==='string'&&!u.trim()?rp(base()):rp(u));};}catch(e){}
try{var oRe=location.replace.bind(location);location.replace=function(u){return oRe(typeof u==='string'&&!u.trim()?rp(base()):rp(u));};}catch(e){}
/* ---- DOM 属性 setter 拦截：img.src = "..." 等动态赋值 ---- */
function rwPing(v){
  if(typeof v!=='string')return v;
  var t=v.trim();
  return t?t.split(/\\s+/).map(rp).join(' '):v;
}
function patchSetter(ctor,prop,ss){
  try{
    if(!ctor||!ctor.prototype)return;
    var d=Object.getOwnPropertyDescriptor(ctor.prototype,prop);
    if(!d||!d.set||!d.configurable)return;
    var orig=d.set;
    Object.defineProperty(ctor.prototype,prop,{
      configurable:true,enumerable:d.enumerable,get:d.get,
      set:function(v){try{v=ss===1?rwSrcset(v):ss===2?rwPing(v):rwUrlArg(v);}catch(e){}return orig.call(this,v);}
    });
  }catch(e){}
}
/* 与服务端 rewriteSrcset 同一套规则：URL 内部允许出现逗号
   （data:image/gif;base64,......），因此不能简单按 "," 切分 */
function rwsIsW(c){return c===' '||c==='\\t'||c==='\\n'||c==='\\r'||c==='\\f';}
function rwSrcset(v){
  if(typeof v!=='string')return v;
  var s=v,n=s.length,out='',i=0,c,tr,m,url,ss,us,ds,d;
  while(i<n){
    ss=i;
    while(i<n&&(rwsIsW(s.charAt(i))||s.charAt(i)===','))i++;
    out+=s.substring(ss,i);
    if(i>=n)break;
    us=i;
    while(i<n&&!rwsIsW(s.charAt(i)))i++;
    url=s.substring(us,i);tr='';
    m=/,+$/.exec(url);
    if(m){tr=m[0];url=url.substring(0,url.length-tr.length);}
    if(url)out+=rp(url);
    out+=tr;
    if(tr)continue;
    ds=i;d=0;
    while(i<n){
      c=s.charAt(i);
      if(c==='(')d++;
      else if(c===')'){if(d>0)d--;}
      else if(c===','&&d===0)break;
      i++;
    }
    out+=s.substring(ds,i);
  }
  return out;
}
var I=window.HTMLImageElement;
patchSetter(I,'src');patchSetter(I,'srcset',1);
patchSetter(window.HTMLScriptElement,'src');
patchSetter(window.HTMLIFrameElement,'src');
patchSetter(window.HTMLFrameElement,'src');
patchSetter(window.HTMLLinkElement,'href');patchSetter(window.HTMLLinkElement,'imageSrcset',1);
patchSetter(window.HTMLAnchorElement,'href');patchSetter(window.HTMLAnchorElement,'ping',2);
patchSetter(window.HTMLAreaElement,'href');patchSetter(window.HTMLAreaElement,'ping',2);
patchSetter(window.HTMLSourceElement,'src');patchSetter(window.HTMLSourceElement,'srcset',1);
patchSetter(window.HTMLMediaElement,'src');
patchSetter(window.HTMLVideoElement,'poster');
patchSetter(window.HTMLFormElement,'action');
patchSetter(window.HTMLObjectElement,'data');
patchSetter(window.HTMLEmbedElement,'src');
patchSetter(window.HTMLInputElement,'src');
patchSetter(window.HTMLInputElement,'formAction');
patchSetter(window.HTMLButtonElement,'formAction');
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
          var h=this.getAttribute('data-pe-base')||this.getAttribute('href');
          if(h){try{var u=new URL(h,currentTarget());if(u.protocol==='http:'||u.protocol==='https:')return u.href;}catch(e){}}
          return base();
        },
        set:function(v){this.setAttribute('href',v);}
      });
    }
  }
}catch(e){}
/* setAttribute / setAttributeNS 兜底（src/srcset/imagesrcset/action/formaction/poster/data/href/xlink:href/ping） */
var ATTRS={src:0,srcset:1,imagesrcset:1,action:0,formaction:0,poster:0,data:0,href:0,'xlink:href':0,ping:2};
var HREF_TAGS={A:1,LINK:1,AREA:1,SCRIPT:1,IMAGE:1,USE:1,FEIMAGE:1,MPATH:1,TEXTPATH:1,PATTERN:1,FILTER:1,LINEARGRADIENT:1,RADIALGRADIENT:1};
function normTag(el){
  var raw=(el&&(el.localName||el.tagName)||'').toUpperCase();
  var idx=raw.indexOf(':');
  return idx>=0?raw.slice(idx+1):raw;
}
function rwAttrVal(el,tag,attr,kind,sv){
  if(kind===1)return rwSrcset(sv);
  if(kind===2)return rwPing(sv);
  if(!sv.trim()){
    var fm=(el&&el.getAttribute&&(el.getAttribute(attr==='formaction'?'formmethod':'method')||'')||'').trim().toLowerCase();
    var hasBase=Boolean(document.querySelector&&document.querySelector('base[data-pe-base],base[href]'));
    if((tag==='FORM'&&attr==='action'&&fm!=='dialog')||(attr==='formaction'&&fm!=='dialog')||(hasBase&&(attr==='href'||attr==='xlink:href'))){
      return rp(base());
    }
  }
  return rp(sv);
}
if(window.Element){
  var oSA=Element.prototype.setAttribute;
  var oRA=Element.prototype.removeAttribute;
  var oRANS=Element.prototype.removeAttributeNS;
  Element.prototype.setAttribute=function(n,v){
    try{
      if(typeof n==='string'&&v!=null){
        var ln=n.toLowerCase();
        var sv=v instanceof URL?v.href:String(v);
        var tag=normTag(this);
        if(ln==='integrity'&&(tag==='SCRIPT'||tag==='LINK')){
          if(oRA)oRA.call(this,'integrity');
          return;
        }
        if(ln==='href'&&tag==='BASE'){
          var bOk=false;
          try{
            var bUrl=new URL(sv,currentTarget());
            if(bUrl.protocol==='http:'||bUrl.protocol==='https:'){
              oSA.call(this,'data-pe-base',bUrl.href);
              bOk=true;
            }
          }catch(e){}
          if(!bOk&&oRA)oRA.call(this,'data-pe-base');
          if(oRA)oRA.call(this,'href');
          return;
        }
        if(Object.prototype.hasOwnProperty.call(ATTRS,ln)){
          if((ln!=='href'||HREF_TAGS[tag])&&(ln!=='ping'||tag==='A'||tag==='AREA')){
            arguments[1]=rwAttrVal(this,tag,ln,ATTRS[ln],sv);
          }
        }
      }
    }catch(e){}
    return oSA.apply(this,arguments);
  };
  var oSANS=Element.prototype.setAttributeNS;
  if(oSANS)Element.prototype.setAttributeNS=function(ns,n,v){
    try{
      if(typeof n==='string'&&v!=null){
        var ln=n.toLowerCase();
        var colon=ln.indexOf(':');
        var prefix=colon>=0?ln.slice(0,colon):'';
        var local=colon>=0?(prefix==='xlink'||ns?ln.slice(colon+1):ln):ln;
        var sv=v instanceof URL?v.href:String(v);
        var tag=normTag(this);
        if(local==='integrity'&&(tag==='SCRIPT'||tag==='LINK')){
          if(oRA)oRA.call(this,'integrity');
          return;
        }
        if(local==='href'&&tag==='BASE'){
          var bOk=false;
          try{
            var bUrl=new URL(sv,currentTarget());
            if(bUrl.protocol==='http:'||bUrl.protocol==='https:'){
              oSA.call(this,'data-pe-base',bUrl.href);
              bOk=true;
            }
          }catch(e){}
          if(!bOk&&oRA)oRA.call(this,'data-pe-base');
          if(oRA)oRA.call(this,'href');
          return;
        }
        var kind=Object.prototype.hasOwnProperty.call(ATTRS,local)?ATTRS[local]:ATTRS[ln];
        if(kind!==undefined&&(local!=='href'||HREF_TAGS[tag])&&(local!=='ping'||tag==='A'||tag==='AREA')){
          arguments[2]=rwAttrVal(this,tag,local,kind,sv);
        }
      }
    }catch(e){}
    return oSANS.apply(this,arguments);
  };
  if(oRA)Element.prototype.removeAttribute=function(n){
    try{
      if(typeof n==='string'&&n.toLowerCase()==='href'&&normTag(this)==='BASE'){
        oRA.call(this,'data-pe-base');
      }
    }catch(e){}
    return oRA.apply(this,arguments);
  };
  if(oRANS)Element.prototype.removeAttributeNS=function(ns,n){
    try{
      if(typeof n==='string'){
        var ln=n.toLowerCase();
        var local=ln.indexOf(':')>=0?ln.slice(ln.indexOf(':')+1):ln;
        if(local==='href'&&normTag(this)==='BASE'&&oRA){
          oRA.call(this,'data-pe-base');
        }
      }
    }catch(e){}
    return oRANS.apply(this,arguments);
  };
}
/* ---- document.cookie：读写都按站点命名空间转换 ----
   服务端下发的 cookie 名带 CK 前缀；页面脚本应当只看到原始名字。 */
try{
if(CK){
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
          if(p.indexOf(CK)===0){
            var rest=p.substring(CK.length);
            if(rest.indexOf('=')>0)out.push(rest);
          }
        }
        return out.join('; ');
      },
      set:function(v){
        var scoped=scopeCookie(v,CK,location.protocol==='https:');
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
    if(h!==null){var p=rp(h.trim()||base());if(p&&p!==h)el.setAttribute('href',p);}
    var xh=el.getAttribute('xlink:href');
    if(xh!==null){var px=rp(xh.trim()||base());if(px&&px!==xh)el.setAttribute('xlink:href',px);}
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
    var m=(f.getAttribute('method')||'').trim().toLowerCase();
    var a=f.getAttribute('action');
    var at=a!==null?a.trim():null;
    if(at){var p=rp(at);if(p&&p!==a)f.setAttribute('action',p);}
    else if(m!=='dialog'&&(at===''||document.querySelector('base[data-pe-base],base[href]'))){
      f.setAttribute('action',rp(base()));
    }
    if(sub&&sub.getAttribute){
      var sfm=(sub.getAttribute('formmethod')||'').trim().toLowerCase();
      var fa=sub.getAttribute('formaction');
      if(fa!==null&&(fa.trim()||sfm!=='dialog')){
        var pfa=rp(fa.trim()||base());
        if(pfa&&pfa!==fa)sub.setAttribute('formaction',pfa);
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
})();</script>`;
}

// ============================================================
// HTML 重写（基于 HTMLRewriter，流式处理）
// ============================================================

const HANDLERS = {
	a:            { href: 'url', 'xlink:href': 'url', ping: 'ping' },
	area:         { href: 'url', 'xlink:href': 'url', ping: 'ping' },
	link:         { href: 'url', imagesrcset: 'srcset' },
	script:       { src: 'url', href: 'url', 'xlink:href': 'url' },
	img:          { src: 'url', srcset: 'srcset' },
	image:        { href: 'url', 'xlink:href': 'url' },
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
	let baseHref = baseUrl;
	let hasBaseHref = false;
	let injected = false;
	const shim = getShimScript(workerOrigin, ck ? ck.ns : '');
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

	// 只采纳第一个合法 HTTP(S) href；保留 target 与原始基地址供 shim 使用，移除原生 href。
	rewriter.on('base', {
		element(el) {
			const h = el.getAttribute('href');
			if (h != null && !hasBaseHref) {
				try {
					const u = new URL(h, baseUrl);
					if (u.protocol === 'http:' || u.protocol === 'https:') {
						hasBaseHref = true;
						baseHref = u.href;
						el.setAttribute('data-pe-base', baseHref);
					} else {
						el.removeAttribute('data-pe-base');
					}
				} catch {
					el.removeAttribute('data-pe-base');
				}
			} else {
				el.removeAttribute('data-pe-base');
			}
			el.removeAttribute('href');
		},
	});

	// CSP/Set-Cookie/X-Frame-Options/referrer meta 标签直接移除；refresh meta 重写目标；charset meta 对齐为 UTF-8
	rewriter.on('meta', {
		element(el) {
			const he = (el.getAttribute('http-equiv') || '').trim().toLowerCase();
			const name = (el.getAttribute('name') || '').trim().toLowerCase();
			if (he === 'content-security-policy' || he === 'content-security-policy-report-only' ||
				he === 'set-cookie' || he === 'x-frame-options' || name === 'referrer') {
				el.remove();
				return;
			}
			if (he === 'refresh') {
				const c = el.getAttribute('content');
				if (c) el.setAttribute('content', rewriteRefreshContent(c, baseHref, workerOrigin));
			}
			if (he === 'content-type') {
				const c = el.getAttribute('content');
				if (c) el.setAttribute('content', c.replace(/charset\s*=\s*[^;]*/i, 'charset=UTF-8'));
			}
			if (el.getAttribute('charset') != null) {
				el.setAttribute('charset', 'UTF-8');
			}
		},
	});

	// 对 style、内联 ES module、importmap 与 speculationrules 使用同一个有界缓冲器；其它脚本原样保留。
	rewriter.on('style', bufferedTextHandler(css => rewriteCss(css, baseHref, workerOrigin)));
	rewriter.on('script', bufferedTextHandler(
		(text, kind) => kind === 'importmap'
			? rewriteImportMap(text, baseHref, workerOrigin)
			: kind === 'speculationrules'
				? rewriteSpeculationRules(text, baseHref, workerOrigin, baseUrl)
				: rewriteJsModuleSpecifiers(text, baseHref, workerOrigin),
		el => {
			if (el.hasAttribute('src') || el.hasAttribute('href') || el.hasAttribute('xlink:href')) return null;
			const type = (el.getAttribute('type') || '').trim().toLowerCase();
			return type === 'module' || type === 'importmap' || type === 'speculationrules' ? type : null;
		}
	));

	// 具体标签的 URL 属性
	for (const [tag, attrs] of Object.entries(HANDLERS)) {
		rewriter.on(tag, {
			element(el) {
				// 内容被我们改写过的资源必须去掉 SRI，否则哈希校验失败被浏览器拦截
				if (tag === 'script' || tag === 'link') el.removeAttribute('integrity');
				const isDialogForm = tag === 'form' &&
					(el.getAttribute('method') || '').trim().toLowerCase() === 'dialog';
				if (tag === 'form' && !isDialogForm && hasBaseHref && !el.hasAttribute('action')) {
					el.setAttribute('action', rw(baseHref));
				}
				for (const [attr, kind] of Object.entries(attrs)) {
					const v = el.getAttribute(attr);
					if (v == null) continue;
					const isDialogSub = attr === 'formaction' &&
						(el.getAttribute('formmethod') || '').trim().toLowerCase() === 'dialog';
					if (kind === 'srcset') {
						el.setAttribute(attr, rewriteSrcset(v, baseHref, workerOrigin));
					} else if (kind === 'ping') {
						const trimmed = v.trim();
						if (trimmed) el.setAttribute(attr, trimmed.split(/\s+/).map(rw).join(' '));
					} else if (!v.trim() && ((tag === 'form' && !isDialogForm) || (attr === 'formaction' && !isDialogSub) ||
						(hasBaseHref && (attr === 'href' || attr === 'xlink:href' || attr === 'action')))) {
						el.setAttribute(attr, rw(baseHref));
					} else {
						el.setAttribute(attr, rw(v));
					}
				}
				// script 标签上的内联 srcset 不存在；但懒加载属性可能出现在任意标签上（下面统一处理）
			},
		});
	}

	const BG_TAGS = new Set(['body', 'table', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th']);
	const SVG_URL_ATTRS = [
		'fill', 'stroke', 'filter', 'clip-path', 'mask',
		'marker', 'marker-start', 'marker-mid', 'marker-end', 'cursor',
	];

	// 通配：style 属性、表格/页面 background、SVG url() 表现属性、懒加载 data-* 属性
	rewriter.on('*', {
		element(el) {
			// 兜底注入：源文档既没有 <head> 也没有 <body> 起始标签时
			// （XHR 拉回的 HTML 片段、<frameset> 老页面等），上面的两个 handler
			// 都不会触发，shim 就丢了。这里插到文档第一个非容器元素之前，
			// 保证它仍然先于页面自身脚本执行。
			const tag = (el.tagName || '').toLowerCase();
			if (!injected && tag !== 'html' && tag !== 'head' && tag !== 'body') {
				injected = true;
				el.before(shim, { html: true });
			}

			const st = el.getAttribute('style');
			if (st) {
				el.setAttribute('style', rewriteStyleAttr(st, baseHref, workerOrigin));
			}
			if (BG_TAGS.has(tag)) {
				const bg = el.getAttribute('background');
				if (bg) el.setAttribute('background', rw(bg));
			}
			for (const attr of SVG_URL_ATTRS) {
				const v = el.getAttribute(attr);
				if (v && /(?:url|-webkit-image-set|image-set)\s*\(/i.test(v)) {
					el.setAttribute(attr, rewriteStyleAttr(v, baseHref, workerOrigin));
				}
			}
			for (const attr of LAZY_ATTRS) {
				const v = el.getAttribute(attr);
				if (v == null) continue;
				el.setAttribute(attr, /(?:srcset|-set)$/.test(attr) ? rewriteSrcset(v, baseHref, workerOrigin) : rw(v));
			}
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

/**
 * 限制整体缓冲的解码后输入量；不信任 Content-Length（可缺失/虚报）。
 * 超过 2 MiB 上限时不再抛错返回 502 HTML，而是把已读分片与剩余流无缝拼接后流式透传。
 */
function sniffTextChunkCharset(chunks, kind, declaredCharset = null) {
	const head = new Uint8Array(256);
	let total = 0;
	for (const c of chunks) {
		const sub = c.subarray(0, head.length - total);
		head.set(sub, total);
		total += sub.length;
		if (total >= head.length) break;
	}
	if (total >= 2 && head[0] === 0xff && head[1] === 0xfe) return 'utf-16le';
	if (total >= 2 && head[0] === 0xfe && head[1] === 0xff) return 'utf-16be';
	if (total >= 3 && head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf) return 'utf-8';
	if (declaredCharset) return declaredCharset;
	if (kind === 'css' && total >= 12) {
		const ascii = new TextDecoder().decode(head.subarray(0, total));
		const m = /^@charset\s+(?:"([^"]{1,64})"|'([^']{1,64})')\s*;/i.exec(ascii);
		if (m) return normalizeCharsetLabel(m[1] || m[2], true) || 'utf-8';
	}
	if (kind === 'svg' && total >= 20) {
		const ascii = new TextDecoder().decode(head.subarray(0, total));
		const m = /^\s*<\?xml\b[^>]{0,200}?\bencoding\s*=\s*(["'])\s*([^"'\s]{1,64})\s*\1[^>]*\?>/i.exec(ascii);
		if (m) return normalizeCharsetLabel(m[2], false) || 'utf-8';
	}
	return 'utf-8';
}

async function readTransformText(body, kind = '', declaredCharset = null) {
	if (!body) return { text: '', passthrough: null, charset: declaredCharset || 'utf-8' };
	const reader = body.getReader();
	const chunks = [];
	let bytes = 0;
	let handedOff = false;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			bytes += value.byteLength;
			if (bytes > MAX_TRANSFORM_BYTES) {
				handedOff = true;
				const effectiveCharset = sniffTextChunkCharset([...chunks, value], kind, declaredCharset);
				const passthrough = new ReadableStream({
					start(controller) {
						for (const c of chunks) controller.enqueue(c);
						chunks.length = 0;
						controller.enqueue(value);
					},
					async pull(controller) {
						const next = await reader.read();
						if (next.done) {
							reader.releaseLock();
							controller.close();
						} else {
							controller.enqueue(next.value);
						}
					},
					cancel(reason) {
						reader.cancel(reason).catch(() => {});
						try { reader.releaseLock(); } catch {}
					},
				});
				return { text: null, passthrough, charset: effectiveCharset };
			}
			chunks.push(value);
		}
		const effectiveCharset = sniffTextChunkCharset(chunks, kind, declaredCharset);
		const decoder = new TextDecoder(effectiveCharset);
		const parts = [];
		for (const c of chunks) parts.push(decoder.decode(c, { stream: true }));
		parts.push(decoder.decode());
		return { text: parts.join(''), passthrough: null, charset: effectiveCharset };
	} catch (error) {
		reader.cancel(error).catch(() => {});
		throw error;
	} finally {
		if (!handedOff) {
			try { reader.releaseLock(); } catch {}
		}
	}
}

async function transformText(response, baseUrl, workerOrigin, kind, request, declaredCharset = null) {
	const charset = declaredCharset || getCharset(response.headers.get('content-type'));
	const { text: rawText, passthrough, charset: effectiveCharset } = await readTransformText(response.body, kind, charset);
	let bodyOut = passthrough;
	if (bodyOut === null) {
		let text = rawText;
		try {
			if (kind === 'css') {
				text = rewriteCss(text, baseUrl, workerOrigin).replace(/^@charset\s+(?:"[^"]*"|'[^']*')\s*;/i, '@charset "UTF-8";');
			} else if (kind === 'js') {
				text = rewriteJsModuleSpecifiers(text, baseUrl, workerOrigin);
			} else if (kind === 'svg') {
				text = rewriteSvg(text, baseUrl, workerOrigin);
			} else if (kind === 'json' || kind === 'manifest') {
				text = rewriteJsonUrls(text, baseUrl, workerOrigin);
			}
		} catch { /* 重写失败则回退原文 */ }
		bodyOut = text;
	} else if (effectiveCharset && !isUtf8Charset(effectiveCharset)) {
		try {
			bodyOut = bodyOut.pipeThrough(new TextDecoderStream(effectiveCharset)).pipeThrough(new TextEncoderStream());
		} catch {}
	}

	const resp = new Response(bodyOut, response);
	for (const h of STRIP_RESPONSE_HEADERS) resp.headers.delete(h);
	stripTransformedHeaders(resp.headers);
	const ct = (response.headers.get('content-type') || '').split(';')[0].trim();
	resp.headers.set('content-type', (ct || 'text/plain') + '; charset=UTF-8');
	if (ENABLE_PROXY_NOINDEX) {
		resp.headers.set('X-Robots-Tag', 'noindex, nofollow');
	}
	applyCors(resp.headers, request);
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

/**
 * 只改写真正的模块说明符，保留注释、字符串、正则及 import attributes。
 * lexer 的 n 已解码 JS 转义；重新序列化整段字符串，不能直接拼回原引号。
 * 无法静态确定的动态 import、裸说明符和 import.meta 保持原样。
 * 解析失败时原样返回，避免对新语法/无效源码进行部分改写。
 */
function rewriteJsModuleSpecifiers(js, baseUrl, workerOrigin) {
	const source = String(js);
	let imports;
	try { [imports] = parseModuleImports(source); } catch { return source; }
	const parts = [];
	let cursor = 0;
	for (const item of imports) {
		const spec = item.n;
		if (typeof spec !== 'string' ||
			!(/^(?:\.\.?\/|\/|https?:\/\/)/i.test(spec))) continue;
		const rewritten = rewriteUrl(spec, baseUrl, workerOrigin);
		if (rewritten === spec) continue;
		// 静态说明符 s/e 不含引号；动态说明符 s/e 包含整个字面量。
		const start = item.d === -1 ? item.s - 1 : item.s;
		const end = item.d === -1 ? item.e + 1 : item.e;
		parts.push(source.slice(cursor, start), JSON.stringify(rewritten));
		cursor = end;
	}
	parts.push(source.slice(cursor));
	return parts.join('');
}

/** 重写 <script type="importmap">：按 HTML 规范以文档基地址解析映射并移除失效的 integrity */
function rewriteImportMap(text, baseUrl, workerOrigin) {
	let map;
	try { map = JSON.parse(text); } catch { return text; }
	if (!map || typeof map !== 'object' || Array.isArray(map)) return text;
	const isUrlLike = s => /^(?:\.\.?\/|\/|[a-z][a-z0-9+.-]*:)/i.test(s);
	const rewriteSpecMap = (specMap) => {
		if (!specMap || typeof specMap !== 'object' || Array.isArray(specMap)) return specMap;
		const next = {};
		for (const [k, v] of Object.entries(specMap)) {
			if (k.endsWith('/')) {
				next[k] = v;
				continue;
			}
			const rwKey = /^(?:\.\.?\/|\/|https?:\/\/)/i.test(k)
				? rewriteUrl(k, baseUrl, workerOrigin)
				: k;
			next[rwKey] = typeof v === 'string' && isUrlLike(v)
				? rewriteUrl(v, baseUrl, workerOrigin)
				: v;
		}
		return next;
	};
	if (map.imports && typeof map.imports === 'object' && !Array.isArray(map.imports)) {
		map.imports = rewriteSpecMap(map.imports);
	}
	if (map.scopes && typeof map.scopes === 'object' && !Array.isArray(map.scopes)) {
		const nextScopes = {};
		for (const [scopeKey, specMap] of Object.entries(map.scopes)) {
			const rwKey = scopeKey.endsWith('/') ? scopeKey : rewriteUrl(scopeKey, baseUrl, workerOrigin);
			nextScopes[rwKey] = rewriteSpecMap(specMap);
		}
		map.scopes = nextScopes;
	}
	delete map.integrity;
	return JSON.stringify(map);
}

/** 重写 <script type="speculationrules"> 中的预取/预渲染 URL 列表 */
function rewriteSpeculationRules(text, baseUrl, workerOrigin, docUrl = baseUrl) {
	let spec;
	try { spec = JSON.parse(text); } catch { return text; }
	if (!spec || typeof spec !== 'object' || Array.isArray(spec)) return text;
	for (const key of ['prefetch', 'prerender', 'prefetch_with_subresources', 'prerender_until_script']) {
		const rules = spec[key];
		if (!Array.isArray(rules)) continue;
		for (const rule of rules) {
			if (rule && Array.isArray(rule.urls)) {
				const ruleBase = rule.relative_to === 'document' ? docUrl : baseUrl;
				rule.urls = rule.urls.map(u => typeof u === 'string' ? rewriteUrl(u, ruleBase, workerOrigin) : u);
			}
		}
	}
	return JSON.stringify(spec);
}

function isValidXmlCodePoint(code) {
	return code > 0 && code <= 0x10ffff && (code < 0xd800 || code > 0xdfff) && code !== 0xfffe && code !== 0xffff;
}

function decodeXmlEntities(s) {
	return String(s).replace(/&(?:#(\d+)|#x([0-9a-f]+)|(amp|lt|gt|quot|apos));/gi, (m, dec, hex, named) => {
		if (dec) {
			const code = parseInt(dec, 10);
			return isValidXmlCodePoint(code) ? String.fromCodePoint(code) : m;
		}
		if (hex) {
			const code = parseInt(hex, 16);
			return isValidXmlCodePoint(code) ? String.fromCodePoint(code) : m;
		}
		switch (named.toLowerCase()) {
			case 'amp': return '&';
			case 'lt': return '<';
			case 'gt': return '>';
			case 'quot': return '"';
			case 'apos': return "'";
		}
		return m;
	});
}

function escapeXmlAttr(s) {
	return String(s).replace(/[&"<>]/g, c => ({ '&': '&amp;', '"': '&quot;', '<': '&lt;', '>': '&gt;' }[c]));
}

/** 独立 SVG 文档：重写引用属性与内嵌样式，保持 XML 实体良构性 */
function rewriteSvg(svg, baseUrl, workerOrigin) {
	const rw = (v) => rewriteUrl(v, baseUrl, workerOrigin);
	const rewriteTagAttrs = (tag) => {
		let out = tag;
		if (/^<(?:[a-z0-9_-]+:)?(?:script|link)\b/i.test(out)) {
			out = out.replace(/\s+(?<![\w:-])integrity\s*=\s*(?:"[^"]*"|'[^']*')/gi, '');
		}
		return out
			.replace(
				/(?<![\w:-])(href|xlink:href|src|action|formaction|poster)\s*=\s*("([^"]*)"|'([^']*)')/gi,
				(m, attr, _q, dq, sq) => {
					const raw = dq !== undefined ? dq : sq;
					const r = rw(decodeXmlEntities(raw));
					return `${attr}="${escapeXmlAttr(r)}"`;
				}
			)
			.replace(
				/(?<![\w:-])(srcset|imagesrcset)\s*=\s*("([^"]*)"|'([^']*)')/gi,
				(m, attr, _q, dq, sq) => {
					const raw = dq !== undefined ? dq : sq;
					const r = rewriteSrcset(decodeXmlEntities(raw), baseUrl, workerOrigin);
					return `${attr}="${escapeXmlAttr(r)}"`;
				}
			)
			.replace(
				/(?<![\w:-])ping\s*=\s*("([^"]*)"|'([^']*)')/gi,
				(m, _q, dq, sq) => {
					const raw = dq !== undefined ? dq : sq;
					const trimmed = decodeXmlEntities(raw).trim();
					if (!trimmed) return m;
					return `ping="${escapeXmlAttr(trimmed.split(/\s+/).map(rw).join(' '))}"`;
				}
			)
			.replace(
				/(?<![\w:-])(style|fill|stroke|filter|clip-path|mask|marker(?:-start|-mid|-end)?|cursor)\s*=\s*("([^"]*)"|'([^']*)')/gi,
				(m, attr, _q, dq, sq) => {
					const raw = dq !== undefined ? dq : sq;
					const decoded = decodeXmlEntities(raw);
					const rewritten = rewriteStyleAttr(decoded, baseUrl, workerOrigin);
					if (rewritten === decoded) return m;
					return `${attr}="${escapeXmlAttr(rewritten)}"`;
				}
			);
	};
	return String(svg).replace(
		/<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|(<style\b(?:[^>"']|"[^"]*"|'[^']*')*(?<!\/)>)([\s\S]*?)(<\/style\s*>)|(<script\b(?:[^>"']|"[^"]*"|'[^']*')*(?<!\/)>)([\s\S]*?)(<\/script\s*>)|<[?a-zA-Z](?:[^>"']|"[^"]*"|'[^']*')*>/gi,
		(m, styleOpen, css, styleClose, scriptOpen, scriptBody, scriptClose) => {
			if (styleOpen) {
				const open = rewriteTagAttrs(styleOpen);
				const rewriteXmlCss = part => rewriteCss(decodeXmlEntities(part), baseUrl, workerOrigin)
					.replace(/&/g, '&amp;').replace(/</g, '&lt;');
				if (css.includes('<![CDATA[')) {
					let out = '';
					let last = 0;
					for (const cm of css.matchAll(/<!\[CDATA\[([\s\S]*?)\]\]>/g)) {
						if (cm.index > last) out += rewriteXmlCss(css.slice(last, cm.index));
						out += `<![CDATA[${rewriteCss(cm[1], baseUrl, workerOrigin)}]]>`;
						last = cm.index + cm[0].length;
					}
					if (last < css.length) out += rewriteXmlCss(css.slice(last));
					return open + out + styleClose;
				}
				return open + rewriteXmlCss(css) + styleClose;
			}
			if (scriptOpen) {
				const open = rewriteTagAttrs(scriptOpen);
				const isInlineModule = !/\s(?:src|href|xlink:href)\s*=/i.test(scriptOpen) &&
					/\stype\s*=\s*(?:"\s*module\s*"|'\s*module\s*'|module(?=[\s/>]))/i.test(scriptOpen);
				if (!isInlineModule) return open + scriptBody + scriptClose;
				const rewriteXmlJs = part => rewriteJsModuleSpecifiers(decodeXmlEntities(part), baseUrl, workerOrigin)
					.replace(/&/g, '&amp;').replace(/</g, '&lt;');
				if (scriptBody.includes('<![CDATA[')) {
					let out = '';
					let last = 0;
					for (const cm of scriptBody.matchAll(/<!\[CDATA\[([\s\S]*?)\]\]>/g)) {
						if (cm.index > last) out += rewriteXmlJs(scriptBody.slice(last, cm.index));
						out += `<![CDATA[${rewriteJsModuleSpecifiers(cm[1], baseUrl, workerOrigin)}]]>`;
						last = cm.index + cm[0].length;
					}
					if (last < scriptBody.length) out += rewriteXmlJs(scriptBody.slice(last));
					return open + out + scriptClose;
				}
				return open + rewriteXmlJs(scriptBody) + scriptClose;
			}
			if (m.startsWith('<!--') || m.startsWith('<![CDATA[')) return m;
			if (/^<\?xml(?![\w:-])/i.test(m)) {
				return m.replace(/(?<![\w:-])encoding\s*=\s*("[^"]*"|'[^']*')/i, 'encoding="UTF-8"');
			}
			return rewriteTagAttrs(m);
		}
	);
}

/** Manifest：解析 JSON，仅改写规范中的 URL 字段，不触碰名称/键/任意业务字符串。 */
function rewriteJsonUrls(text, baseUrl, workerOrigin) {
	let manifest;
	try { manifest = JSON.parse(text); } catch { return text; }
	if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) return text;
	const fields = (obj, names) => {
		if (!obj || typeof obj !== 'object') return;
		for (const name of names) {
			if (typeof obj[name] === 'string') obj[name] = rewriteUrl(obj[name], baseUrl, workerOrigin);
		}
	};
	const images = (list) => {
		if (Array.isArray(list)) for (const item of list) fields(item, ['src']);
	};
	fields(manifest, ['id', 'start_url', 'scope']);
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
}

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
	const raw = safeDecode(url.pathname.substring(1));
	if (!raw) return null;
	const trimmed = raw.trim().replace(/^\/+/, '');
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
	const search = url.search;
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
	u.username = ''; u.password = '';
	u.hash = '';
	return u;
}

/**
 * 部署防护：拒绝 IP 字面量/明显本地名称；可选精确 HTTP(S) 来源允许列表。
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
	const configured = env && env.ALLOWED_TARGET_ORIGINS;
	if (configured === undefined) return null;
	try {
		if (typeof configured !== 'string' || !configured.trim()) throw new Error();
		const origins = configured.split(',').map(value => {
			const u = new URL(value.trim());
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
	'x-forwarded-host', 'x-forwarded-server', 'x-forwarded-proto',
	'x-forwarded-port', 'x-forwarded-for', 'x-real-ip', 'true-client-ip', 'forwarded',
	'x-original-host', 'x-original-url', 'x-rewrite-url', 'x-client-ip', 'via',
	'cdn-loop', 'x-real-port', 'x-scheme', 'x-forwarded-ssl', 'front-end-https', 'fastly-client-ip',
]);

/** 重写转发请求中的 Referer 头，避免将代理域名泄露给源站 */
function resolveUpstreamReferer(request, workerOrigin, fallbackUrl) {
	const referer = request.headers.get('referer');
	if (!referer) return fallbackUrl;
	try {
		const rUrl = new URL(referer);
		const rTarget = isWorkerHost(rUrl, workerOrigin) ? parseTarget(rUrl) : null;
		if (rTarget && !isWorkerHost(rTarget, workerOrigin) && !targetPolicyError(rTarget)) {
			if (rTarget.protocol === 'ws:') rTarget.protocol = 'http:';
			else if (rTarget.protocol === 'wss:') rTarget.protocol = 'https:';
			return rTarget.href;
		}
	} catch {}
	return fallbackUrl;
}

// ============================================================
// WebSocket 代理
// ============================================================

async function handleWebSocket(request, targetUrl, ck, workerOrigin) {
	// ws/wss → http/https 供 fetch 建立上游连接
	const upstreamUrl = new URL(targetUrl.href);
	if (upstreamUrl.protocol === 'ws:') upstreamUrl.protocol = 'http:';
	else if (upstreamUrl.protocol === 'wss:') upstreamUrl.protocol = 'https:';

	// 构造转发请求：带上原始头（去掉宿主相关）
	const headers = new Headers();
	for (const [k, v] of request.headers) {
		const lk = k.toLowerCase();
		if (lk.startsWith('cf-') || STRIP_FORWARDED_HEADERS.has(lk)) continue;
		headers.set(k, v);
	}
	stripHopByHop(headers);
	headers.delete('host');
	if (ck) applyRequestCookieScope(headers, request, ck.ns);
	headers.set('Origin', upstreamUrl.origin);
	if (headers.has('referer')) {
		headers.set('Referer', resolveUpstreamReferer(request, workerOrigin, upstreamUrl.href));
	}
	headers.set('Connection', 'Upgrade');
	headers.set('Upgrade', 'websocket');

	// 自动跟随重定向可能把手工转发的 Cookie 带到另一个站点。
	const resp = await fetch(upstreamUrl.href, { headers, redirect: 'manual' });
	const upstream = resp.webSocket;
	if (!upstream) {
		if (resp.body) resp.body.cancel().catch(() => {});
		return new Response('上游不支持 WebSocket（不自动跟随重定向）', { status: 502 });
	}
	// 新兼容日期下 binaryType 可以默认是 blob；send(Blob) 可能被转为字符串。
	// 两个方向都显式使用 ArrayBuffer，保留二进制帧而不引入异步转换/乱序。
	upstream.binaryType = 'arraybuffer';
	upstream.accept();

	const pair = new WebSocketPair();
	const client = pair[0];
	client.binaryType = 'arraybuffer';
	client.accept();

	const pipe = (from, to) => {
		from.addEventListener('message', ev => {
			try { to.send(ev.data); } catch {}
		});
		from.addEventListener('close', ev => {
			// 1005/1006/1015 是状态标记，不允许写入关闭帧；若状态码或超长 reason 被拒绝则优先保留状态码，再回退 1000。
			const code = ev.code === 1005 ? 1000 : [1006, 1015].includes(ev.code) ? 1011 : ev.code;
			try { to.close(code, ev.reason); } catch {
				try { to.close(code); } catch {
					try { to.close(1000, ev.reason); } catch { try { to.close(1000); } catch {} }
				}
			}
		});
		from.addEventListener('error', () => {
			try { to.close(1011, 'upstream error'); } catch { try { to.close(1000); } catch {} }
		});
	};
	pipe(upstream, client);
	pipe(client, upstream);

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

		// ---- 首页 ----
		if (url.pathname === '/' || url.pathname === '') {
			return new Response(request.method === 'HEAD' ? null : getRootHtml(), {
				headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
			});
		}

		// ---- robots.txt：允许收录首页，禁止抓取代理目标路径以防耗尽 Worker 配额 ----
		if (url.pathname === '/robots.txt') {
			return new Response(request.method === 'HEAD' ? null :
`User-agent: *
Allow: /
Disallow: /http:
Disallow: /https:
Disallow: /http%3A
Disallow: /https%3A
Disallow: /ws:
Disallow: /wss:
Disallow: /ws%3A
Disallow: /wss%3A
`,
				{ headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=86400' } }
			);
		}

		// ---- favicon 等杂项，避免被当成目标域名 ----
		if (/^\/(favicon\.ico|sitemap\.xml|apple-touch-icon.*\.png|\.well-known\/.*)$/i.test(url.pathname)) {
			return new Response(null, { status: 404 });
		}

		// ---- 解析目标 URL ----
		const targetUrl = parseTarget(url);
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
		const ck = { ns: cookieNamespace(targetUrl), isHttps: url.protocol === 'https:' };

		// WebSocket 请求走独立通道
		if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
			try {
				return await handleWebSocket(request, targetUrl, ck, workerOrigin);
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
			if (lk.startsWith('cf-') || STRIP_FORWARDED_HEADERS.has(lk)) continue;
			fwdHeaders.set(k, v);
		}
		stripHopByHop(fwdHeaders);
		// 伪装成直连访问：重写 Origin / Referer
		fwdHeaders.set('Origin', targetUrl.origin);
		fwdHeaders.set('Referer', resolveUpstreamReferer(request, workerOrigin, fetchUrl));
		fwdHeaders.delete('host');
		// Cookie 按站点隔离：只回传属于当前目标站点的那部分，并剥掉命名空间前缀
		applyRequestCookieScope(fwdHeaders, request, ck.ns);

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
			const resp = buildResponse(upstream, request, ck);
			const loc = upstream.headers.get('location');
			if (loc) {
				try {
					const abs = new URL(loc, fetchUrl);
					if (!['http:', 'https:'].includes(abs.protocol)) throw new Error('无效重定向协议');
					if (isWorkerHost(abs, workerOrigin)) {
						if (isProxiedPath(abs.pathname)) {
							resp.headers.set('Location', `${workerOrigin}${abs.pathname}${abs.search}${abs.hash}`);
						} else {
							const rebound = new URL(abs.pathname + abs.search + abs.hash, fetchUrl);
							resp.headers.set('Location', toProxyUrl(rebound.href, workerOrigin));
						}
					} else {
						resp.headers.set('Location', toProxyUrl(abs.href, workerOrigin));
					}
				} catch {
					resp.headers.delete('Location');
				}
			}
			// 丢弃重定向正文时显式取消上游流，且原正文长度/编码/摘要不再有效。
			if (resp.body) resp.body.cancel().catch(() => {});
			stripTransformedHeaders(resp.headers);
			return new Response(null, resp);
		}

		// ---- 204 / 205 / 304 无正文 ----
		if ([204, 205, 304].includes(upstream.status) || request.method === 'HEAD') {
			const resp = buildResponse(upstream, request, ck);
			if (resp.body) resp.body.cancel().catch(() => {});
			// HEAD/304 可以合法携带所选表示的长度与验证器，不按正文变换清洗。
			return new Response(null, resp);
		}

		// 局部正文不能安全重写：保留原始字节、Content-Range 与验证器。
		if (upstream.status === 206) return buildResponse(upstream, request, ck);

		try {
		// ---- 按内容类型处理 ----
		const contentType = (upstream.headers.get('content-type') || '').toLowerCase();
		const mime = contentType.split(';')[0].trim();
		const fetchDest = (request.headers.get('sec-fetch-dest') || '').toLowerCase();
		const baseUrl = documentBase(targetUrl);
		const isHtml = mime.includes('text/html') || mime.includes('application/xhtml+xml');
		const isManifest = mime.includes('manifest+json') ||
			(mime.includes('json') && fetchDest === 'manifest');
		const isTextual = isHtml || mime.includes('text/css') || mime.includes('javascript') ||
			mime.includes('ecmascript') || isManifest ||
			mime.includes('image/svg+xml');
		// 透传分支不应建立转码管线，否则 upstream.body 会被锁定却仍被复用。
		if (!isTextual) return buildResponse(upstream, request, ck);

		let bodySource = upstream.body;
		let charset = getCharset(contentType);

		// HTML 的 BOM 优先于 HTTP charset；无显式编码时再嗅探 meta/XML 声明，并流式转码为 UTF-8 供 HTMLRewriter 处理。
		// 外部 CSS/JS/SVG/Manifest 交由 readTransformText 按 BOM > HTTP charset > 内联声明单次解码，避免二次解码乱码。
		if (isHtml) {
			const sniffed = await sniffHtmlCharset(upstream.body, charset);
			charset = sniffed.charset;
			bodySource = sniffed.body;
			if (bodySource && charset && !isUtf8Charset(charset)) {
				try {
					// 构造成功后才触碰流；无效 charset 不能回退到已 tee/锁定的 upstream.body。
					const decoder = new TextDecoderStream(charset);
					const encoder = new TextEncoderStream();
					bodySource = bodySource.pipeThrough(decoder).pipeThrough(encoder);
				} catch {
					// 保留当前未消费的 bodySource，以 UTF-8 宽松解码作为回退。
				}
			}
		}

		/**
		 * 构造中间 Response：携带上游全部响应头（剔除会破坏代理的头），
		 * 正文换成（可能已转码的）流，并删除仅适用于上游原字节的验证器/摘要/范围信息。
		 */
		const makeInterim = (ctOverride) => {
			const interim = new Response(bodySource, upstream);
			for (const h of STRIP_RESPONSE_HEADERS) interim.headers.delete(h);
			stripHopByHop(interim.headers);
			stripTransformedHeaders(interim.headers);
			if (ctOverride) interim.headers.set('content-type', ctOverride);
			return interim;
		};

		// HTML：流式重写（输入统一为 UTF-8，Content-Type 同步覆盖，
		// 避免 HTMLRewriter 按 meta 里的旧 charset 重新编码输出）
		if (isHtml) {
			const interim = makeInterim((mime || 'text/html') + '; charset=UTF-8');
			const result = transformHtml(interim, baseUrl, workerOrigin, ck);
			// 补一遍统一头处理
			if (ENABLE_PROXY_NOINDEX) {
				result.headers.set('X-Robots-Tag', 'noindex, nofollow');
			}
			applyCors(result.headers, request);
			rescopeSetCookies(result.headers, ck.ns, ck.isHttps);
			applyCachePolicy(result, request);
			return result;
		}

		// CSS
		if (mime.includes('text/css')) {
			return applyCommon(await transformText(makeInterim(), baseUrl, workerOrigin, 'css', request, charset), upstream, request, ck);
		}

		// JS：基于模块 lexer 的 URL 说明符重写
		if (mime.includes('javascript') || mime.includes('ecmascript')) {
			return applyCommon(await transformText(makeInterim(), baseUrl, workerOrigin, 'js', request, charset), upstream, request, ck);
		}

		// SVG
		if (mime.includes('image/svg+xml')) {
			return applyCommon(await transformText(makeInterim(), baseUrl, workerOrigin, 'svg', request, charset), upstream, request, ck);
		}

		// Web App Manifest（图标、start_url 等）
		if (isManifest) {
			return applyCommon(await transformText(makeInterim(), baseUrl, workerOrigin, 'json', request, charset), upstream, request, ck);
		}

		// 其它（JSON API/图片/字体/媒体/下载等）：流式透传
		// 说明：JSON 内容不重写 —— 动态场景已由浏览器端 shim（fetch/XHR/属性 setter）覆盖，
		// 直接改写 API 数据反而可能破坏业务逻辑。
		return buildResponse(upstream, request, ck);
		} catch (error) {
			return errorPage(targetUrl.href, error);
		}
	},
};

/** transformText 的产物再补一遍统一头处理 */
function applyCommon(resp, upstream, request, ck) {
	stripHopByHop(resp.headers);
	if (ck) rescopeSetCookies(resp.headers, ck.ns, ck.isHttps);
	if (ENABLE_PROXY_NOINDEX) {
		resp.headers.set('X-Robots-Tag', 'noindex, nofollow');
	}
	applyCachePolicy(resp, request);
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
           /^\\/(https?|wss?)(?:%3A|:)(?:%2F|\\/){2}/i.test(u0.pathname)){
          v=u0.pathname+u0.search+u0.hash;
        }
      }catch(_){}
    }
    if(/^(?:\\/+)?(?:https?|wss?)(?:%3A|:)(?:%2F|\\/){2}/i.test(v)){
      var qIdx=v.search(/[?#]/);
      var pPart=qIdx>=0?v.slice(0,qIdx):v;
      var sPart=qIdx>=0?v.slice(qIdx):'';
      try{
        var rawP=pPart.replace(/^\\/+/,'');
        var dec;
        try{dec=decodeURIComponent(rawP);}catch(_){dec=decodeURIComponent(rawP.replace(/%(?![0-9a-f]{2})/gi,'%25'));}
        dec=dec.replace(/^ws(s?):\\/\\//i,'http$1://');
        var hIdx=dec.indexOf('#');
        if(hIdx>=0)dec=dec.slice(0,hIdx);
        if(sPart.charAt(0)==='?'&&dec.indexOf('?')>=0)sPart='&'+sPart.slice(1);
        v=dec+sPart;
      }catch(_){}
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
    var nextHref='/'+encodeURIComponent(u.protocol+'//'+u.host+u.pathname)+u.search+u.hash;
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
      <a class="tonal-btn md-ripple" href="/"><span class="t-label-lg">返回首页</span></a>
    </div>
  </section>
</div>
<script>${MD3_JS}</script>
</body>
</html>`;
}
