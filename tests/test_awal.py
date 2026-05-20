import json
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from awal.cli import main
from awal.scanner import scan_path
from awal.web import AwalHandler


class AwalTests(unittest.TestCase):
    def test_clean_example_passes(self):
        report = scan_path("examples/clean-app")

        self.assertEqual(report.status, "pass")
        self.assertEqual(report.findings, ())

    def test_broken_example_blocks(self):
        report = scan_path("examples/broken-app")
        categories = {finding.category for finding in report.findings}

        self.assertEqual(report.status, "block")
        self.assertIn("missing_package_script", categories)
        self.assertIn("placeholder_test_script", categories)
        self.assertIn("missing_compose_file", categories)
        self.assertIn("missing_env_example", categories)
        self.assertIn("package_manager_drift", categories)
        self.assertIn("port_drift", categories)

    def test_undocumented_env_var_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("```bash\nnpm run dev\n```", encoding="utf-8")
            (root / "package.json").write_text('{"scripts":{"dev":"vite"}}', encoding="utf-8")
            (root / ".env.example").write_text("DATABASE_URL=postgres://localhost/app\n", encoding="utf-8")
            src = root / "src"
            src.mkdir()
            (src / "app.js").write_text("const token = process.env.API_TOKEN;\n", encoding="utf-8")

            report = scan_path(root)

        self.assertEqual(report.status, "block")
        self.assertIn("undocumented_env_var", {finding.category for finding in report.findings})

    def test_env_example_secret_is_critical(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("```bash\nnpm run dev\n```", encoding="utf-8")
            (root / "package.json").write_text('{"scripts":{"dev":"vite"}}', encoding="utf-8")
            (root / ".env.example").write_text("API_TOKEN=sk-live-real-looking-token-123456\n", encoding="utf-8")

            report = scan_path(root)

        self.assertEqual(report.status, "block")
        self.assertIn("env_example_secret", {finding.category for finding in report.findings})

    def test_cli_writes_json(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"

            exit_code = main(["examples/broken-app", "--format", "json", "--output", str(output)])
            data = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 2)
        self.assertEqual(data["status"], "block")
        self.assertGreater(data["summary"]["total"], 0)

    def test_ui_api_scans_path(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), AwalHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/api/scan"
            payload = json.dumps({"path": "examples/broken-app", "fail_on": "high"}).encode("utf-8")
            request = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertEqual(data["status"], "block")
        self.assertGreater(data["summary"]["total"], 0)

    def test_action_metadata_exists(self):
        action = Path("action.yml").read_text(encoding="utf-8")
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertIn("using: composite", action)
        self.assertIn("awal \"${{ inputs.path }}\"", action)
        self.assertIn("Action blocks broken example", workflow)


if __name__ == "__main__":
    unittest.main()
