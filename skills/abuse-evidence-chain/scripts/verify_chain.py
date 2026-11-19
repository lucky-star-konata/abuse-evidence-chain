#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_chain — 校验证据包完整性：重算 SHA-256，检查缺失与多余文件。

用法:
    python verify_chain.py --case cases/CASE-2026-001
    python verify_chain.py --case cases/CASE-2026-001 --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION_FILE = ROOT / "VERSION"


def get_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 128), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(case_dir: Path):
    manifest_path = case_dir / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"未找到 manifest.json: {case_dir}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifest.json 解析失败: {exc}")

    checked = []
    listed = set()
    for item in manifest.get("artifacts") or []:
        rel = item.get("path", "")
        listed.add(rel)
        path = case_dir / rel
        entry = {
            "path": rel,
            "expected": item.get("sha256", ""),
            "actual": "",
            "status": "MISSING",
        }
        if path.is_file():
            entry["actual"] = sha256_file(path)
            entry["status"] = "OK" if entry["actual"] == entry["expected"] else "MISMATCH"
        checked.append(entry)

    extras = []
    for path in sorted(case_dir.rglob("*")):
        if not path.is_file() or path.name in ("manifest.json", "report.md"):
            continue
        rel = path.relative_to(case_dir).as_posix()
        if rel.startswith("drafts/"):
            continue
        if rel not in listed:
            extras.append(rel)

    failed = [item for item in checked if item["status"] != "OK"]
    return {
        "case_dir": str(case_dir),
        "manifest_version": manifest.get("version"),
        "artifacts": checked,
        "extras": extras,
        "ok": not failed and not extras,
        "failures": len(failed),
        "extras_count": len(extras),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="校验证据包完整性")
    parser.add_argument("--case", required=True, help="案件目录（含 manifest.json）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    args = parser.parse_args(argv)

    case_dir = Path(args.case)
    try:
        result = verify(case_dir)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"verify_chain {get_version()} · {result['case_dir']}\n")
        for item in result["artifacts"]:
            print(f"[{item['status']}] {item['path']}")
            if item["status"] == "MISMATCH":
                print(f"  期望: {item['expected']}")
                print(f"  实际: {item['actual']}")
        if result["extras"]:
            print("\n[EXTRA] 未在清单中的文件：")
            for rel in result["extras"]:
                print(f"  - {rel}")
        print(
            f"\n汇总: 校验 {len(result['artifacts'])} 个文件，"
            f"失败 {result['failures']}，多余 {result['extras_count']}"
        )
        print("结论: PASS" if result["ok"] else "结论: FAIL")

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    raise SystemExit(main())
