#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""report_builder — 根据证据包生成报告与四类举报材料草稿。

用法:
    python report_builder.py --case cases/CASE-2026-001
    python report_builder.py --case cases/CASE-2026-001 --no-drafts
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION_FILE = ROOT / "VERSION"


def get_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def load_manifest(case_dir: Path):
    path = case_dir / "manifest.json"
    if not path.is_file():
        raise ValueError(f"未找到 manifest.json: {case_dir}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifest.json 解析失败: {exc}")


def collect_facts(manifest):
    facts = []
    for item in manifest.get("targets") or []:
        if item.get("status") != "ok":
            facts.append(
                f"{item.get('label', 'target')}：{item.get('url')} 采集失败（{item.get('error', 'unknown')}）"
            )
            continue
        line = (
            f"{item.get('label', 'target')}：{item.get('url')} 返回 HTTP {item.get('http_status')}"
            f"，最终地址 {item.get('final_url')}"
        )
        if item.get("title"):
            line += f"，页面标题「{item['title']}」"
        facts.append(line)
    return facts


def collect_domains(manifest):
    domains = []
    for item in manifest.get("targets") or []:
        host = (item.get("final_url") or item.get("url") or "").split("//")[-1].split("/")[0]
        if host and host not in domains:
            domains.append(host)
    return domains


def build_report(manifest, case_dir: Path):
    case = manifest.get("case") or {}
    targets = manifest.get("targets") or []
    artifacts = manifest.get("artifacts") or []
    domains = collect_domains(manifest)

    lines = [
        f"# 证据报告：{case.get('title', '未命名案件')}",
        "",
        "| 项目 | 内容 |",
        "| --- | --- |",
        f"| 案件编号 | {case.get('case_id', '')} |",
        f"| 类别 | {case.get('category', '')} |",
        f"| 采集时间 | {manifest.get('collected_at', '')} |",
        f"| 采集人 | {case.get('operator', '')} |",
        f"| 用途 | {case.get('purpose', '')} |",
        f"| 工具版本 | {manifest.get('tool', '')} {manifest.get('version', '')} |",
        "",
        "## 一、事实概述",
        "",
        case.get("notes") or "（未填写补充说明）",
        "",
    ]
    for fact in collect_facts(manifest):
        lines.append(f"- {fact}")
    lines.append("")

    lines += [
        "## 二、目标明细",
        "",
        "| # | 标签 | 原始 URL | 最终 URL | HTTP | 页面标题 | 采集时间 |",
        "| ---: | --- | --- | --- | ---: | --- | --- |",
    ]
    for index, item in enumerate(targets, 1):
        lines.append(
            f"| {index} | {item.get('label', '')} | {item.get('url', '')} "
            f"| {item.get('final_url', '')} | {item.get('http_status') or '-'} "
            f"| {str(item.get('title', '')).replace('|', chr(92) + '|')} | {item.get('collected_at', '')} |"
        )
    lines.append("")

    lines += [
        "## 三、证据清单",
        "",
        "| # | 文件 | 大小 | SHA-256 |",
        "| ---: | --- | ---: | --- |",
    ]
    for index, item in enumerate(artifacts, 1):
        lines.append(
            f"| {index} | `{item['path']}` | {human_size(item.get('size', 0))} | `{item.get('sha256', '')}` |"
        )
    lines.append("")

    lines += ["## 四、时间线", ""]
    for item in manifest.get("timeline") or []:
        lines.append(f"- {item.get('at', '')} {item.get('event', '')}")
    lines.append("")

    lines += ["## 五、基础设施线索", ""]
    for item in targets:
        dns = item.get("dns") or []
        if dns:
            lines.append(f"- {item.get('label', 'target')} 解析到：{', '.join(dns)}")
    certs = []
    for item in targets:
        cert = item.get("cert") or {}
        issuer = (cert.get("issuer") or {}).get("organizationName") if isinstance(cert, dict) else None
        if issuer and issuer not in certs:
            certs.append(issuer)
    if certs:
        lines.append(f"- 证书签发组织：{', '.join(certs)}")
    lines.append("- 以上仅为采集时点的公开信息，是否同一团伙需结合更多证据判断。")
    lines.append("")

    lines += [
        "## 六、处置建议",
        "",
        "| 对象 | 建议动作 | 依据 |",
        "| --- | --- | --- |",
        "| 域名注册商 | 核实并暂停解析，或转交域名持有人处理 | WHOIS / RDAP 与页面证据 |",
        "| 托管商 / CDN | 核实并下架违规内容 | 响应头、IP 与页面快照 |",
        "| 平台 / 应用商店 | 封禁引流账号与下载链接 | 页面中的跳转与下载入口 |",
        "| 执法 / 反诈中心 | 提交报案材料 | 时间线、证据清单、影响说明 |",
        "",
        "具体渠道与材料要求见 `docs/disposal-channels.md`。",
        "",
        "## 七、声明",
        "",
        "- 本报告仅基于公开可访问页面的采集结果，未进行任何侵入性操作。",
        "- 证据文件均记录 SHA-256，可用 `verify_chain.py` 复算校验。",
        "- 结论部分区分事实与推断，未验证的内容不作为定性依据。",
        "",
    ]
    return "\n".join(lines)


def draft_header(manifest, recipient, subject):
    case = manifest.get("case") or {}
    facts = collect_facts(manifest)
    domains = collect_domains(manifest)
    attachments = [item["path"] for item in manifest.get("artifacts") or []]
    lines = [
        f"收件人：{recipient}",
        f"主题：{subject}",
        "",
        "尊敬的团队：",
        "",
        f"我方于 {manifest.get('collected_at', '')} 对以下公开页面进行取证，"
        f"发现其涉嫌 {case.get('category', '违法违规')} 类违规内容，现提交证据并请求核实处理。",
        "",
        "## 事实",
        "",
    ]
    for fact in facts:
        lines.append(f"- {fact}")
    lines += ["", "## 证据", ""]
    for path in attachments:
        lines.append(f"- {path}")
    lines += [
        "",
        "完整证据包包含 manifest.json（记录每个文件的 SHA-256 与采集时间），可复算校验。",
        "",
        "## 请求",
        "",
    ]
    return lines, domains, attachments


def build_registrar_draft(manifest):
    case = manifest.get("case") or {}
    domains = collect_domains(manifest)
    lines, domains, attachments = draft_header(
        manifest,
        "[注册商 abuse 邮箱，可通过 RDAP 查询]",
        f"滥用举报：{', '.join(domains)} 涉嫌 {case.get('category', '违法违规')} 类违规",
    )
    lines += [
        "- 核实该域名注册信息与当前使用情况",
        "- 依据服务条款暂停解析，或要求域名持有人限期整改",
        "- 保留相关解析与访问日志以备调查",
        "",
        f"涉及域名：{', '.join(domains)}",
        "",
        "此致",
        "",
        "[提交人姓名]",
        "[联系方式 / 邮箱]",
        "[提交日期]",
        "",
        "> 请在提交前核对注册商与 abuse 邮箱，并只附必要证据。",
    ]
    return "\n".join(lines) + "\n"


def build_hosting_draft(manifest):
    case = manifest.get("case") or {}
    domains = collect_domains(manifest)
    lines, _, _ = draft_header(
        manifest,
        "[托管商 / CDN abuse 邮箱，可通过 IP 的 RDAP 查询]",
        f"违规内容下架请求：{', '.join(domains)}",
    )
    lines += [
        "- 核实对应 IP / 站点托管的违规内容",
        "- 依据服务条款下架相关页面，或停止为该站点提供服务",
        "- 保留访问日志以备调查",
        "",
        "涉及的解析地址与响应信息见证据包中的 headers.txt 与 meta.json。",
        "",
        "此致",
        "",
        "[提交人姓名]",
        "[联系方式 / 邮箱]",
        "[提交日期]",
        "",
        "> 请在提交前确认实际托管商与 abuse 渠道。",
    ]
    return "\n".join(lines) + "\n"


def build_platform_draft(manifest):
    case = manifest.get("case") or {}
    lines, domains, _ = draft_header(
        manifest,
        "[平台举报入口 / 应用商店审核团队]",
        f"举报涉嫌{case.get('category', '违法违规')}的页面与下载链接",
    )
    lines += [
        "- 屏蔽相关页面与下载链接",
        "- 封禁用于引流的账号或群组（如有）",
        "- 保留举报回执并反馈处理结果",
        "",
        "如页面包含 App 下载，请在附件中注明安装包名称与下载地址（不要附带安装包本体）。",
        "",
        "此致",
        "",
        "[提交人姓名]",
        "[联系方式 / 邮箱]",
        "[提交日期]",
    ]
    return "\n".join(lines) + "\n"


def build_law_enforcement_draft(manifest):
    case = manifest.get("case") or {}
    lines, domains, _ = draft_header(
        manifest,
        "[属地公安机关 / 反诈中心 / 网络违法犯罪举报网站]",
        f"报案材料：{case.get('title', '')}（{case.get('case_id', '')}）",
    )
    lines += [
        "- 对涉案域名与服务器开展调查",
        "- 调取注册、解析与支付相关记录",
        "- 如涉及受害人，协助开展止付与预警",
        "",
        "## 需补充的信息",
        "",
        "- 受害人数量与涉案金额（有依据再填）",
        "- 资金流向与收款账户",
        "- 引流渠道与聊天记录（脱敏后附）",
        "",
        "此致",
        "",
        "[报案人姓名]",
        "[证件号 / 单位]",
        "[联系方式]",
        "[报案日期]",
        "",
        "> 本材料仅为事实整理，不替代正式报案文书；提交前请按当地要求补充签字与身份材料。",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="生成证据报告与举报材料草稿")
    parser.add_argument("--case", required=True, help="案件目录（含 manifest.json）")
    parser.add_argument("--out", help="报告输出路径，默认 <case>/report.md")
    parser.add_argument("--no-drafts", action="store_true", help="不生成举报草稿")
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    args = parser.parse_args(argv)

    case_dir = Path(args.case)
    try:
        manifest = load_manifest(case_dir)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    report = build_report(manifest, case_dir)
    out_path = Path(args.out) if args.out else case_dir / "report.md"
    out_path.write_text(report, encoding="utf-8")
    print(f"[OK] 报告: {out_path}")

    if not args.no_drafts:
        drafts_dir = case_dir / "drafts"
        drafts_dir.mkdir(exist_ok=True)
        drafts = {
            "registrar-abuse.md": build_registrar_draft(manifest),
            "hosting-abuse.md": build_hosting_draft(manifest),
            "platform-report.md": build_platform_draft(manifest),
            "law-enforcement.md": build_law_enforcement_draft(manifest),
        }
        for name, content in drafts.items():
            (drafts_dir / name).write_text(content, encoding="utf-8")
        print(f"[OK] 举报草稿: {drafts_dir}（{len(drafts)} 份）")

    print(f"[NEXT] 提交前运行 python scripts/verify_chain.py --case {case_dir}")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    raise SystemExit(main())
