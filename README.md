# ProxyEverything

## 回归测试

使用 Node.js 22 或更高版本，在仓库根目录运行 `node --test tests/*.test.mjs`。

测试使用 Node.js 内置测试运行器，无需安装依赖或连接上游站点；覆盖内联 JSON
改写的 HTML 安全序列化、数据保真、URL 解析及文本分片处理，以及 CSS `@namespace`
（含其中 `url()` 内的 `;` 与 `/*`）保真、XHTML 文档中的 shim 注入（CDATA 守卫）、
缓存策略的 Cookie 作用域、无可信来源时的 HTTP 回源头行为，以及 Manifest `id`
相对 `start_url` 来源的解析。还验证 CSS/JS/SVG/Manifest
超出 2 MiB 上限时原始字节、编码与验证器的透传，以及恰好达到上限时的正常重写。
运行时 shim 测试在最小 DOM 桩上验证 `data`/`action`/`formaction` 仅在会加载资源的元素上改写，
以及 shim 被重复执行时不会重复包裹原生 API。
HTML 处理器测试以桩替代 HTMLRewriter，验证 URL 属性仅在改写结果变化时才回写。
响应头测试验证 `Refresh` 头经代理改写而非被丢弃，以及 `Accept-CH` 等按源持久化的头
不会落到共享的代理源上。
这些单元测试不替代 Cloudflare Workers 真实运行时的集成验证。
