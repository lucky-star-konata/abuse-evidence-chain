import http.server
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
SCRIPTS = ROOT / "skills" / "abuse-evidence-chain" / "scripts"

BODY = b"<html><head><title>Test Scam Page</title></head><body>demo</body></html>"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


class ChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.case_file = self.base / "case.json"
        self.case_file.write_text(json.dumps({
            "case_id": "CASE-TEST-001",
            "title": "测试案件",
            "category": "test",
            "operator": "tester",
            "purpose": "unit-test",
            "notes": "本地桩页面",
            "targets": [{"url": f"http://127.0.0.1:{self.port}/", "label": "landing"}],
        }, ensure_ascii=False), encoding="utf-8")
        self.case_dir = self.base / "cases" / "CASE-TEST-001"

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, script, *args):
        return subprocess.run(
            [PY, str(SCRIPTS / script), *args], cwd=ROOT, capture_output=True,
            text=True, encoding="utf-8", errors="replace",
        )

    def test_requires_legal_confirmation(self):
        result = self.run_cli("evidence_collect.py", "--case", str(self.case_file),
                              "--out-dir", str(self.base / "cases"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("confirm-legal", result.stderr)

    def test_full_chain(self):
        collect = self.run_cli(
            "evidence_collect.py", "--case", str(self.case_file),
            "--out-dir", str(self.base / "cases"), "--confirm-legal",
        )
        self.assertEqual(collect.returncode, 0, collect.stderr)
        self.assertTrue((self.case_dir / "manifest.json").is_file())

        verify = self.run_cli("verify_chain.py", "--case", str(self.case_dir))
        self.assertEqual(verify.returncode, 0, verify.stdout)

        page = next(self.case_dir.glob("*/page.html"))
        original = page.read_bytes()
        page.write_bytes(original + b"tampered")
        tampered = self.run_cli("verify_chain.py", "--case", str(self.case_dir))
        self.assertEqual(tampered.returncode, 1)
        self.assertIn("MISMATCH", tampered.stdout)
        page.write_bytes(original)

        report = self.run_cli("report_builder.py", "--case", str(self.case_dir))
        self.assertEqual(report.returncode, 0, report.stderr)
        text = (self.case_dir / "report.md").read_text(encoding="utf-8")
        self.assertIn("测试案件", text)
        self.assertIn("证据清单", text)
        drafts = self.case_dir / "drafts"
        self.assertEqual(len(list(drafts.glob("*.md"))), 4)

        final_verify = self.run_cli("verify_chain.py", "--case", str(self.case_dir))
        self.assertEqual(final_verify.returncode, 0, final_verify.stdout)


if __name__ == "__main__":
    unittest.main()
