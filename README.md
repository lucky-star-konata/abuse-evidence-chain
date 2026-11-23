# abuse-evidence-chain

[![CI](https://github.com/lucky-star-konata/abuse-evidence-chain/actions/workflows/ci.yml/badge.svg)](https://github.com/lucky-star-konata/abuse-evidence-chain/actions/workflows/ci.yml)

面向黑灰产治理的**证据链 + 处置链**工具：对可疑站点做最小化公开取证，生成带哈希的证据包，再输出发给注册商、托管商、平台和执法机关的举报材料。

> 只做公开信息取证与合规举报。不做入侵、拖库、DDoS、社工。详见 [DISCLAIMER.md](DISCLAIMER.md)。

## 解决什么

| 痛点 | 本工具的做法 |
| --- | --- |
| 截图存了但说不清来源和时间 | 每条证据记录 URL、采集时间、HTTP 状态、SHA-256 |
| 证据被质疑篡改 | `verify_chain.py` 重算哈希，逐项比对 |
| 举报信不知道怎么写 | 按对象生成注册商 / 托管商 / 平台 / 执法四类草稿 |
| 团伙换壳后证据对不上 | 用证书、收款方式、页面模板做聚类字段，便于关联 |

## 链路

```
case.json ──> evidence_collect.py ──> cases/<case_id>/
                                      ├── manifest.json     证据清单与哈希
                                      ├── 01-<host>/         页面快照、响应头、证书、WHOIS
                                      └── ...
                                            │
                    verify_chain.py ────────┤ 完整性校验
                                            │
                    report_builder.py ──────┴──> report.md
                                                  drafts/registrar-abuse.md
                                                  drafts/hosting-abuse.md
                                                  drafts/platform-report.md
                                                  drafts/law-enforcement.md
```

## 快速开始

```bash
# 1. 复制案件模板并填写
cp skills/abuse-evidence-chain/templates/case.example.json case.json

# 2. 预览采集计划（不发请求）
python skills/abuse-evidence-chain/scripts/evidence_collect.py \
  --case case.json --confirm-legal --dry-run

# 3. 采集（单个页面只发一次 GET，不爬取）
python skills/abuse-evidence-chain/scripts/evidence_collect.py \
  --case case.json --confirm-legal

# 4. 校验证据完整性
python skills/abuse-evidence-chain/scripts/verify_chain.py \
  --case cases/CASE-2026-001

# 5. 生成报告与举报草稿
python skills/abuse-evidence-chain/scripts/report_builder.py \
  --case cases/CASE-2026-001
```

## 采集内容

| 证据 | 说明 |
| --- | --- |
| `page.html` | 页面原始字节，不超过 2MB，超出截断并标注 |
| `headers.txt` | 响应头、HTTP 状态、最终 URL、跳转链 |
| `cert.json` | TLS 证书主体、签发者、有效期、序列号（HTTPS） |
| `whois.txt` | 系统已安装 `whois` 时保存原始结果 |
| `meta.json` | 目标标签、时间、DNS 解析结果、错误信息 |
| `manifest.json` | 全部文件的大小与 SHA-256，按时间排序的采集日志 |

## 设计原则

- **最小化**：每个目标只发一次 GET，不执行 JS、不登录、不爬站、不探测目录
- **可验证**：所有证据文件都有 SHA-256，校验脚本可随时重算
- **可复用**：举报草稿只写事实与请求，不写情绪化指控
- **可追溯**：案件元信息、采集器版本、时间线全部落盘
- **隐私优先**：涉个人信息默认打码，原始文件单独存放并限制分发
- **防误伤**：默认拒绝解析到内网 / 回环 / 保留地址的目标（含 30x 跳转），
  避免被来源不明的案件文件诱导探测内网；隔离实验环境可用 `--allow-private` 显式放行
- **防越界**：`case_id` 仅允许字母、数字、点、下划线和短横线，证据校验只读取案件目录内的文件

## 适用与不适用

适用：仿冒站、诈骗落地页、博彩/跑分引流页、恶意 App 下载页的公开取证与举报。

不适用：需要登录才能看到的页面、内部系统、需要漏洞验证的目标；这些场景请走授权渗透或司法取证流程。

## License

[MIT](LICENSE)
