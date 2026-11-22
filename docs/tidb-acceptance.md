# TiDB 实际入库验收页（受保护）

生产入口：https://vynalthai.com/__ops/tidb-acceptance

## 权限与安全

- **临时固定密码**：服务端用一次性加盐 PBKDF2-SHA256 派生值验证，源码、浏览器和 GitHub 均无明文密码，不需要额外配置 Cloudflare Secret；与 `/admin/ip` 密码或会话完全隔离。页面使用单独的 `__Host-vynalth-tidb-acceptance` HttpOnly/Secure/SameSite=Strict Cookie，随机 256-bit 会话 Token 仅以 SHA-256 索引保存在现有 `SCHOOL_IP_KV`，20 分钟自动过期。只有管理员登录才能访问状态和测试 API。
- 独立登录 POST 必须同源，密码在 Worker 使用固定盐+25,000 次 PBKDF2-SHA256 校验；验证用盐与派生值存在公开源码中，因此只适用于短期验收（不是永久管理账号的推荐方式）；会话独立于 IP Admin；会话退出时从 KV 撤销。错误登录 5 次/15 分钟限速，Cloudflare WAF 仍是额外的保护。诊断 POST 需要同源 Origin、合法 CSRF token、明确确认字样 `RUN_SINGLE_PROBE`。全局 Workers KV 尝试冷却 300 秒，单 isolate 禁止并发；KV 最终一致性意味着该限制不是严格全局原子计数器。
- 严格限制在 `vynalthai.com` 的页面、静态脚本及五个受控 API 端点内。Cloudflare WAF、临时 IP 限制、设备策略和 School IP Policy 原有拦截仍保留。管理页依照现有 `/admin/ip` 路由，不要求浏览器 GPS 提示；未扩大其他业务路径的 GPS 例外。
- 无公开 SQL 控制台、无任意参数 SQL、无原始 IP、无用户 Cookie、无数据字段回显、无数据库 URL 或明文错误输出。
- 请求结果只返回固定枚举状态和异常类别 `auth/schema/quota/transport/timeout/other`、阶段和随机 UUID 标记。

## 使用步骤

1. 验证当前生产 Worker 的正确版本已经 Ready、100% 流量。
2. **无需额外新增 Cloudflare Secret**。确认现有 `SCHOOL_IP_KV` 仍绑定，生产版本 Ready 且 100% 流量。
3. 访问页面，使用本次验收之前指定的固定临时密码登录（不应把该密码再贴到聊天或 Issue）。连续 5 次失败的登录会按 Cloudflare 已观察来源 IP 暂停 15 分钟；原始 IP 不保存到 KV。
4. 勾选一次性写入确认，点击 **运行真实入库验收**；每次 POST 仅尝试写入一条到现有表。页面返回 `state`、固定错误类型和唯一 `request_path` UUID。
5. 若 `state=failed`：INSERT 未通过，查看 `reason/stage`，而非重复点击或升级付费。
6. 若 `state=insert_acknowledged`：仅说明驱动没有报错，**不算最终 PASS**。复制页面生成的精确 SQL，在 TiDB SQL Editor 运行并核对是否出现同一 UUID 的 `acceptance_probe` 记录。
7. 若独立 SQL readback 返回匹配行，才允许判定端到端 **PASS**。

受控 INSERT 写入固定字段：

```sql
INSERT INTO vynalth_honeypot.honeypot_events
(event_type, source, protocol, source_ip_hash, country_code, request_path, action_taken)
VALUES ('acceptance_probe','cloudflare_worker','HTTP',NULL,NULL,
        '/__ops/tidb-acceptance/<uuid>','logged');
```

其中 `<uuid>` 为安全生成的 UUID，SQL 实际执行使用参数化绑定。

## 页面关闭与临时性

- 管理员在核对 SQL 实际读回并记录结果后，点击页面底部 **完成并关闭临时页面**，再次明确确认。系统通过现有 `SCHOOL_IP_KV` 记录永久关闭标志，此后页面及全部验收 API 返回 **HTTP 410**。由于 KV 最终一致性，跨地区关闭传播可能存在短暂延迟。保护仍由密码、CSRF 和 WAF 共同提供。
- 无论是否点击关闭，**2026-11-25T15:59:59Z（马来西亚时间 11 月 25 日 23:59:59）自动停止页面及验收 API**。
- **关闭或到期并不自动从 GitHub 删除源码。** 用完后必须提交删除代码及路由的清理 commit；保留数据库验收历史记录，不擅自删除生产行。
- 因为临时密码在聊天里曾被提供，建议仅作为短时测试凭据，不应在其他地方复用。

## 可选：自动 SQL 读回

只有配置了单独的、具有 **SELECT-only 最小权限** 的 TiDB 账号时，才把其连接 URL 加密保存为新的 Cloudflare Secret：

`TIDB_HONEYPOT_READONLY_DATABASE_URL`

- 与现有 `TIDB_HONEYPOT_DATABASE_URL`（INSERT-only）保持独立，绝不能使用 root。
- 为保护现有数据库，不会自动创建用户、修改 GRANT、重置 Secret 或部署新付费资源。操作须由数据库拥有者授权执行。
- 自动读回使用参数化 `SELECT id ... WHERE source='cloudflare_worker' AND event_type='acceptance_probe' AND request_path=? LIMIT 1`；只能在确实查到指定 UUID 的行时返回 `verified`。
- 如未配置只读 Secret，或读回失败/返回空，仍显示 `insert_acknowledged` 并指示人工 SQL 核对；永不把连接确认当作持久化成功。

## 发布与验收

- `npm test` 和 `wrangler deploy --dry-run` 是构建检查，不能代替生产 SQL 验收。
- 使用现有 main 构建、无额外 Preview、无自动多次部署、无商业升级。只有经过 GitHub 测试且 Cloudflare Production Ready 后，才请管理员在页面启动 **一次** 验收测试。完成后关闭页面并删除相关源文件，恢复原有路由。
- 如果新的 Worker 版本未部署，不得把旧版结果用于宣称已修复。
- 保持 Issue #107 P0 OPEN，直到出现真实读回证据。
