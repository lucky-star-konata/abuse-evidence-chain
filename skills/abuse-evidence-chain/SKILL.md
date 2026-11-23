---
name: abuse-evidence-chain
description: Build a verifiable evidence pack and abuse reports for fraudulent or gray-market websites. Use when preserving public evidence of a scam landing page, verifying SHA-256 integrity of collected evidence, drafting registrar, hosting, platform or law-enforcement complaints, or linking related fraud infrastructure.
---

# abuse-evidence-chain

把可疑站点的公开信息固化成可校验的证据包，再生成对应处置对象的举报材料。

## 何时使用

- 发现仿冒、诈骗、赌博、跑分引流站点，需要先固定证据再举报
- 需要向注册商、托管商、CDN、平台或执法机关提交材料
- 已有证据被质疑真实性和时间，需要补哈希与时间线
- 多个站点疑似同一团伙，需要做基础设施关联

## 前置条件

- 只访问**无需登录的公开页面**
- 遵守当地法律与平台规则，不进行任何侵入性操作
- 确认参与 `--confirm-legal` 后再采集

## 标准流程

| 步骤 | 命令 / 动作 | 产出 |
| --- | --- | --- |
| 1. 建案 | 复制 `templates/case.example.json` 填写案件信息 | `case.json` |
| 2. 采集 | `evidence_collect.py --case case.json --confirm-legal` | `cases/<id>/` 证据目录 |
| 3. 校验 | `verify_chain.py --case cases/<id>` | 哈希比对结果 |
| 4. 出报告 | `report_builder.py --case cases/<id>` | `report.md` |
| 5. 出草稿 | 同上，自动生成 `drafts/` 四类举报材料 | 注册商 / 托管商 / 平台 / 执法 |
| 6. 提交与跟踪 | 人工核对后通过官方渠道提交 | 受理编号与时间 |

## 采集边界

允许：访问公开页面、保存响应、读取 TLS 证书公开字段、查询 WHOIS/DNS。

禁止：登录后台、目录爆破、漏洞验证、口令猜测、批量爬取、任何写操作、任何拒绝服务行为。

默认拒绝解析到内网 / 回环 / 保留地址的目标（包括 30x 跳转后的地址）；仅在隔离实验环境中才可加 `--allow-private` 显式放行。

## 输出契约

- `manifest.json`：案件信息、采集时间线、每个文件的路径、大小、SHA-256
- 每个目标目录：`page.html`、`headers.txt`、`cert.json`、`meta.json`，有 `whois` 时附 `whois.txt`
- `report.md`：事实、证据清单、初步判断、处置建议
- `drafts/*.md`：只写事实与请求，不写推测性指控
- 校验失败时明确列出缺失、篡改、多余文件

## 处置渠道

按对象选择，不群发：

| 对象 | 适合场景 | 材料 |
| --- | --- | --- |
| 域名注册商 | 域名用于诈骗、仿冒 | 证据包 + 域名 + 请求暂停解析 |
| 托管商 / CDN | 站点内容违法 | 证据包 + URL + 请求下架 |
| 平台 / 应用商店 | 引流页、恶意 App | 证据包 + 页面与下载链接 |
| 执法 / 反诈中心 | 涉案金额、受害人 | 报案材料 + 时间线 + 证据清单 |

具体渠道见 [docs/disposal-channels.md](../../docs/disposal-channels.md)，提交前核对最新官方入口。

## 红线

- 不入侵、不拖库、不购买数据、不“黑吃黑”
- 不公开未打码的个人信息
- 不只凭截图就认定团伙关系；关联结论必须写依据
- 不伪造时间、来源或哈希

## 坑点

- 页面会换壳，采集时间与最终 URL 必须和截图一起记录
- HTTP 跳转链要完整保留，否则举报时说不清落地页
- `whois` 结果可能被隐私保护遮蔽，这不影响提交，但要如实说明
- 证据目录默认被 `.gitignore` 排除，避免误把案件数据推到公开仓库
