# ProxyEverything

基于 Cloudflare Workers 的实验性通用网页反向代理。

## Try

1. 将 `worker.js` 作为 ES Module 部署到 Cloudflare Workers，使用较新的兼容日期（建议 `2026-04-23` 或更新）。
2. 在 Worker 的变量中配置 `ALLOWED_TARGET_ORIGINS`，例如 `https://example.com,https://static.example.com`。列表按精确来源（协议、主机和端口）匹配；跳转目标和需要代理的资源域名也要列入。不配置、留空或配置非法时，Worker 不会回源。
3. 使用独立的专用域名，建议通过 Cloudflare Access 等设施限制访问并配置限流，然后访问部署域名。

**不要把本项目当作隔离浏览器或公共代理。** 列表内的站点会在浏览器中共享代理源，可以互相访问同源页面和浏览器存储。Cookie 名称改写只用于兼容，不提供安全隔离。只允许互信的目标，不要处理敏感登录或数据，也不要与其他应用共用源。此列表不检查 DNS 解析后的 IP，不能替代部署环境的出站网络控制。

## 回归测试

使用 Node.js 22 或更高版本，在仓库根目录运行 `node --test tests/*.test.mjs`。

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
