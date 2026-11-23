#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evidence_collect — 对可疑站点做最小化公开取证，生成带哈希的证据包。

每个目标只发一次 GET，不执行 JS、不登录、不爬取、不探测。

用法:
    python evidence_collect.py --case case.json --confirm-legal
    python evidence_collect.py --case case.json --out-dir cases --timeout 20
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[3]
VERSION_FILE = ROOT / "VERSION"
DEFAULT_OUT = ROOT / "cases"
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
HOST_RE = re.compile(r"[^a-zA-Z0-9._-]+")
CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def get_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 128), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_case_id(value) -> str:
    """case_id 会作为目录名，必须限制字符集，防止路径穿越。"""
    case_id = str(value).strip()
    if not CASE_ID_RE.match(case_id):
        raise ValueError(
            "case_id 只能由字母、数字、点、下划线和短横线组成，"
            "且必须以字母或数字开头，长度不超过 64"
        )
    return case_id


def ensure_public_target(url: str, allow_private: bool) -> None:
    """默认拒绝解析到内网 / 回环 / 保留地址的目标，避免被案件文件诱导内网探测。"""
    if allow_private:
        return
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError(f"URL 缺少主机名: {url}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"无法解析目标主机 {host}: {exc}")
    for info in infos:
        address = info[4][0].split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not ip.is_global:
            raise ValueError(
                f"目标 {host} 解析到非公网地址 {address}，已拒绝采集"
                "（确需内网取证时显式加 --allow-private）"
            )


class _PublicOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """跳转目标同样执行公网校验，防止 302 到内网地址。"""

    def __init__(self, allow_private: bool):
        self.allow_private = allow_private

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        ensure_public_target(newurl, self.allow_private)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def load_case(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise ValueError(f"无法读取案件文件: {exc}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"案件 JSON 解析失败: 第 {exc.lineno} 行 {exc.msg}")
    if not isinstance(data, dict):
        raise ValueError("案件根节点必须是对象")
    if not data.get("case_id"):
        raise ValueError("缺少 case_id")
    data["case_id"] = validate_case_id(data["case_id"])
    if not data.get("title"):
        raise ValueError("缺少 title")
    targets = data.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("targets 必须是非空数组")
    for index, target in enumerate(targets, 1):
        if not isinstance(target, dict) or not target.get("url"):
            raise ValueError(f"第 {index} 个 target 缺少 url")
        scheme = urlparse(target["url"]).scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"只支持 http/https: {target['url']}")
    return data


def host_label(url: str) -> str:
    host = urlparse(url).hostname or "unknown"
    return HOST_RE.sub("_", host)


def resolve_dns(host: str):
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({item[4][0] for item in infos})
    except OSError:
        return []


def get_certificate(host: str, port: int, timeout: int):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except Exception as exc:  # noqa: BLE001 - 证书获取失败属于可记录结果
        return {"error": str(exc)}
    if not cert:
        return {"error": "未获取到证书"}
    to_dict = lambda pairs: {key: value for key, value in pairs}  # noqa: E731
    return {
        "subject": to_dict(cert.get("subject", ())),
        "issuer": to_dict(cert.get("issuer", ())),
        "notBefore": cert.get("notBefore"),
        "notAfter": cert.get("notAfter"),
        "serialNumber": cert.get("serialNumber"),
        "subjectAltName": [value for _, value in cert.get("subjectAltName", ())],
    }


def get_whois(host: str, out_dir: Path, timeout: int):
    binary = shutil.which("whois")
    if not binary:
        return {"available": False, "reason": "系统未安装 whois"}
    try:
        proc = subprocess.run(
            [binary, host], capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace",
        )
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": str(exc)}
    content = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
    if content.strip():
        (out_dir / "whois.txt").write_text(content, encoding="utf-8")
        return {"available": True, "chars": len(content)}
    return {"available": False, "reason": "whois 无返回"}


def fetch_target(url: str, target_dir: Path, timeout: int, max_bytes: int, ua: str,
                 allow_private: bool = False):
    target_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "url": url,
        "collected_at": now_iso(),
        "status": "failed",
        "final_url": "",
        "http_status": None,
        "truncated": False,
        "title": "",
        "dns": [],
        "files": [],
    }

    request = urllib.request.Request(url, headers={
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    opener = urllib.request.build_opener(_PublicOnlyRedirectHandler(allow_private))
    try:
        ensure_public_target(url, allow_private)
        with opener.open(request, timeout=timeout) as response:
            status = getattr(response, "status", None) or response.getcode()
            final_url = response.geturl()
            headers = list(response.headers.items())
            raw = response.read(max_bytes + 1)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
        meta["error"] = str(exc)
        (target_dir / "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return meta

    truncated = len(raw) > max_bytes
    if truncated:
        raw = raw[:max_bytes]

    (target_dir / "page.html").write_bytes(raw)
    header_lines = [f"HTTP {status} {final_url}", ""]
    header_lines += [f"{key}: {value}" for key, value in headers]
    (target_dir / "headers.txt").write_text("\n".join(header_lines) + "\n", encoding="utf-8")

    charset = "utf-8"
    for key, value in headers:
        if key.lower() == "content-type" and "charset=" in value.lower():
            charset = value.lower().split("charset=", 1)[1].split(";")[0].strip()
            break
    try:
        text = raw.decode(charset, errors="replace")
    except LookupError:
        text = raw.decode("utf-8", errors="replace")
    match = TITLE_RE.search(text)
    title = re.sub(r"\s+", " ", match.group(1)).strip() if match else ""

    host = urlparse(final_url or url).hostname or ""
    meta.update({
        "status": "ok",
        "final_url": final_url,
        "http_status": status,
        "truncated": truncated,
        "title": title[:200],
        "dns": resolve_dns(host) if host else [],
        "files": ["page.html", "headers.txt"],
    })

    final_parsed = urlparse(final_url or url)
    if final_parsed.scheme == "https" and host:
        cert = get_certificate(host, final_parsed.port or 443, timeout)
        meta["cert"] = cert
        (target_dir / "cert.json").write_text(
            json.dumps(cert, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        meta["files"].append("cert.json")

    whois_info = get_whois(host, target_dir, timeout) if host else {"available": False}
    meta["whois"] = whois_info
    if whois_info.get("available"):
        meta["files"].append("whois.txt")

    (target_dir / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    meta["files"].append("meta.json")
    return meta


def build_manual(case_dir: Path):
    artifacts = []
    for path in sorted(case_dir.rglob("*")):
        if not path.is_file() or path.name == "manifest.json":
            continue
        artifacts.append({
            "path": path.relative_to(case_dir).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    return artifacts


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="可疑站点最小化公开取证")
    parser.add_argument("--case", required=True, help="案件 JSON 文件")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT), help="案件输出根目录，默认 cases/")
    parser.add_argument("--timeout", type=int, default=20, help="单次请求超时秒数，默认 20")
    parser.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024, help="单页最大保存字节，默认 2MB")
    parser.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (compatible; abuse-evidence-chain/1.0)",
        help="请求 User-Agent",
    )
    parser.add_argument("--confirm-legal", action="store_true", help="确认本次采集合法且仅访问公开页面")
    parser.add_argument(
        "--allow-private", action="store_true",
        help="允许采集解析到内网 / 回环地址的目标（默认拒绝，仅限隔离实验环境）",
    )
    parser.add_argument("--dry-run", action="store_true", help="只打印采集计划，不发起任何请求")
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    args = parser.parse_args(argv)

    if not args.confirm_legal:
        print("[DENY] 需要 --confirm-legal 确认本次采集仅针对公开页面且符合当地法律", file=sys.stderr)
        return 2

    try:
        case = load_case(Path(args.case))
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    out_root = Path(args.out_dir).resolve()
    case_dir = (out_root / case["case_id"]).resolve()
    if case_dir.parent != out_root:
        print(f"[!] case_id 解析后的目录越界: {case_dir}", file=sys.stderr)
        return 2

    if args.dry_run:
        print("[DRY-RUN] 以下目标将被采集（不会发起任何请求）：")
        for index, target in enumerate(case["targets"], 1):
            label = target.get("label") or f"target-{index}"
            host = host_label(target["url"])
            target_dir = case_dir / f"{index:02d}-{host}-{HOST_RE.sub('_', str(label))[:30]}"
            print(f"  - {target['url']} -> {target_dir}")
        return 0

    case_dir.mkdir(parents=True, exist_ok=True)

    targets_meta = []
    errors = []
    for index, target in enumerate(case["targets"], 1):
        label = target.get("label") or f"target-{index}"
        host = host_label(target["url"])
        target_dir = case_dir / f"{index:02d}-{host}-{HOST_RE.sub('_', str(label))[:30]}"
        print(f"[COLLECT] {target['url']}")
        meta = fetch_target(
            target["url"], target_dir, args.timeout, args.max_bytes,
            args.user_agent, args.allow_private,
        )
        meta["label"] = label
        meta["dir"] = target_dir.relative_to(case_dir).as_posix()
        targets_meta.append(meta)
        if meta["status"] == "ok":
            print(f"  [OK] {meta['http_status']} {meta['final_url']}")
        else:
            errors.append({"url": target["url"], "error": meta.get("error", "unknown")})
            print(f"  [FAIL] {meta.get('error', 'unknown')}", file=sys.stderr)

    manifest = {
        "tool": "abuse-evidence-chain",
        "version": get_version(),
        "case": {key: case.get(key) for key in ("case_id", "title", "category", "operator", "purpose", "notes")},
        "collected_at": now_iso(),
        "targets": targets_meta,
        "artifacts": build_manual(case_dir),
        "errors": errors,
        "timeline": [
            {"at": item["collected_at"], "event": f"采集 {item['url']} -> {item['status']}"}
            for item in targets_meta
        ],
    }
    (case_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"\n[OK] 证据目录: {case_dir}")
    print(f"[OK] 文件数: {len(manifest['artifacts'])}，失败目标: {len(errors)}")
    print(f"[NEXT] python scripts/verify_chain.py --case {case_dir}")
    return 0 if any(item["status"] == "ok" for item in targets_meta) else 1


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    raise SystemExit(main())
