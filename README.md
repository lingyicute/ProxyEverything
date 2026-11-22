# ProxyEverything

基于 Cloudflare Workers 的实验性通用网页反向代理。

## Try

1. 将 `worker.js` 作为 ES Module 部署到 Cloudflare Workers，使用较新的兼容日期（建议 `2026-04-23` 或更新）。
2. 在 Worker 的变量中配置 `ALLOWED_TARGET_ORIGINS`，例如 `https://example.com,https://static.example.com`。列表按精确来源（协议、主机和端口）匹配；跳转目标和需要代理的资源域名也要列入。不配置、留空或配置非法时，Worker 不会回源。
3. 使用独立的 HTTPS 专用域名，建议通过 Cloudflare Access 等设施限制访问并配置限流，然后访问部署域名。不要用缓存规则强制缓存有凭证的请求。

新生成的 `/~…` 链接保留目标路径中的百分号转义；旧版逐段编码和整个地址编码的链接仍可访问。若上游对原始 URL 进行签名，请确认部署域的 URL 规范化规则不会改动这些转义。

**不要把本项目当作隔离浏览器或公共代理。** 列表内的站点会在浏览器中共享代理源，可以互相访问同源页面和浏览器存储。Cookie 名称改写只用于兼容，不提供安全隔离。只允许互信的目标，不要处理敏感登录或数据，也不要与其他应用共用源。代理为了改写内容会移除部分上游 CSP、SRI 等限制；不能依赖原站的浏览器隔离策略。无可靠 Referer 的 WebSocket 不会伪造目标 Origin，要求特定 Origin 的上游可能拒绝握手。此列表不检查 DNS 解析后的 IP，不能替代部署环境的出站网络控制。

Cookie 命名空间保留 `__Secure-`、`__Host-`、`__Http-` 和 `__Host-Http-` 在名称开头，并在改写前校验相应属性。`SameSite=None` 和 `Partitioned` 也必须带有源站或脚本原本声明的 `Secure`；代理不会补写这个属性。旧版已隐藏这些前缀的 Cookie 不再读取；升级后可能需要清理专用代理域的 Cookie 并重新登录。普通 Cookie 的命名格式不变。

## 改写边界

- CSS、JavaScript、SVG 和 Web App Manifest 的正文缓冲上限为 2 MiB；HTML 流式处理，单个受改写的脚本或样式文本也有这个上限。多个相对 URL 可能继承同一个长基路径，因此缓冲文本和部分 URL 列表另有 4 Mi 个 UTF-16 码元的增长预算。超限时保留对应原文，不保证其中的 URL 会走代理。
- 流式 HTML 不会回溯已发出的内容；应把 `<base>` 放在依赖它的资源之前。XHTML 使用 HTMLRewriter，不是完整的 XML/DTD 解析器。
- 浏览器 shim 只覆盖常见 API，不会执行或分析任意脚本来推断 URL，也不会递归改写 iframe 的 `srcdoc`。未改写的站内路径有时可凭代理页的 Referer 恢复，但缺少可靠 Referer 时不保证可用。上游 `no-transform`、附件和部分响应也不会改写正文。

## 回归测试

使用 Node.js 22 或更高版本，在仓库根目录运行 `node --test tests/*.test.mjs`。

默认跳过 Workerd 集成测试。如需验证实际的 `HTMLRewriter`、Cookie、多字节转码和 WebSocket，可在独立临时目录安装 Miniflare，不增加 Worker 的部署依赖：

```sh
npm install --prefix /tmp/pe-runtime --no-save miniflare@4.20260730.0
PE_MINIFLARE=/tmp/pe-runtime/node_modules/miniflare node --test tests/*.test.mjs
```

集成测试使用本地上游 Worker，不需要外部目标站点或 Cloudflare 凭证。

## 🗂️ License

This program is released under the GNU Affero General Public License v3.0 (AGPLv3).

Copyright © 2025-2026 lingyicute.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see https://www.gnu.org/licenses.
