# ProxyEverything

## 回归测试

使用 Node.js 22 或更高版本，在仓库根目录运行 `node --test tests/*.test.mjs`。

测试使用 Node.js 内置测试运行器，无需安装依赖或连接上游站点；覆盖内联 JSON
改写的 HTML 安全序列化、数据保真、URL 解析及文本分片处理，以及 CSS `@namespace`
（含其中 `url()` 内的 `;` 与 `/*`）保真、XHTML 文档中的 shim 注入（CDATA 守卫）与缓存策略的 Cookie 作用域。
这些单元测试不替代 Cloudflare Workers 真实运行时的集成验证。
