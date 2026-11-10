# ProxyEverything

## 回归测试

使用 Node.js 22 或更高版本，在仓库根目录运行 `node --test tests/*.test.mjs`。

测试使用 Node.js 内置测试运行器，无需安装依赖或连接上游站点；覆盖内联 JSON
改写的 HTML 安全序列化、数据保真、URL 解析及文本分片处理。
这些单元测试不替代 Cloudflare Workers 真实运行时的集成验证。
