from __future__ import annotations

import json
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .models import SEVERITY_RANK
from .scanner import scan_path


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8774
MAX_REQUEST_BYTES = 500_000


HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Awal</title>
  <style>
    :root {
      --bg: #f4f1e8;
      --panel: #fffdf8;
      --soft: #efe8d8;
      --ink: #161f19;
      --muted: #657166;
      --line: #d8cfbd;
      --accent: #115f42;
      --accent-dark: #0a472f;
      --danger: #9a3023;
      --warn: #7b5806;
      --note: #455966;
      --shadow: 0 18px 42px rgba(22, 31, 25, 0.08);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      padding: 20px;
      background: var(--bg);
      color: var(--ink);
      font: 15px/1.45 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }

    button, input, select {
      font: inherit;
      letter-spacing: 0;
    }

    .shell {
      max-width: 1180px;
      margin: 0 auto;
    }

    header {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 16px;
      align-items: end;
      padding-bottom: 16px;
      margin-bottom: 16px;
      border-bottom: 1px solid var(--line);
    }

    h1 {
      margin: 0;
      font-size: 32px;
      line-height: 1;
      font-weight: 880;
    }

    .tagline {
      margin: 8px 0 0;
      max-width: 780px;
      color: var(--muted);
    }

    .controls {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }

    input, select, button {
      min-height: 40px;
      border-radius: 8px;
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--ink);
      padding: 0 12px;
    }

    input {
      width: min(560px, 100%);
    }

    button {
      cursor: pointer;
      font-weight: 760;
    }

    button:hover, select:hover, input:focus {
      border-color: var(--accent);
    }

    button.primary {
      background: var(--accent);
      border-color: var(--accent);
      color: white;
    }

    button.primary:hover {
      background: var(--accent-dark);
      border-color: var(--accent-dark);
    }

    .layout {
      display: grid;
      grid-template-columns: minmax(0, 0.9fr) minmax(420px, 1.1fr);
      gap: 16px;
      align-items: start;
    }

    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }

    .decision {
      padding: 16px;
      display: grid;
      gap: 12px;
    }

    .decision-top {
      display: grid;
      grid-template-columns: 96px 1fr;
      gap: 14px;
      align-items: center;
    }

    .score {
      width: 96px;
      height: 96px;
      border-radius: 50%;
      border: 10px solid var(--line);
      display: grid;
      place-items: center;
      background: var(--soft);
      font-size: 24px;
      font-weight: 880;
    }

    .score.pass { border-color: var(--accent); }
    .score.review { border-color: var(--warn); }
    .score.block { border-color: var(--danger); }

    .decision h2 {
      margin: 0 0 4px;
      font-size: 23px;
      line-height: 1.1;
    }

    .decision p {
      margin: 0;
      color: var(--muted);
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 8px;
    }

    .metric {
      min-height: 58px;
      padding: 9px;
      border-radius: 8px;
      border: 1px solid var(--line);
      background: var(--soft);
    }

    .metric strong {
      display: block;
      font-size: 18px;
      line-height: 1;
    }

    .metric span {
      color: var(--muted);
      font-size: 12px;
    }

    .surface {
      display: grid;
      gap: 8px;
      padding: 0 16px 16px;
    }

    .surface-row {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 9px 0;
      border-top: 1px solid var(--line);
      color: var(--muted);
    }

    .surface-row strong {
      color: var(--ink);
    }

    .panel-head {
      min-height: 52px;
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
    }

    .panel-head h2 {
      margin: 0;
      font-size: 15px;
    }

    .findings {
      padding: 12px;
      display: grid;
      gap: 10px;
      max-height: 680px;
      overflow: auto;
    }

    .finding {
      padding: 11px;
      border-radius: 8px;
      border: 1px solid var(--line);
      border-left: 5px solid var(--note);
      background: #fffefa;
    }

    .finding.high, .finding.critical { border-left-color: var(--danger); }
    .finding.medium { border-left-color: var(--warn); }

    .finding-top {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 8px;
    }

    .badge {
      border: 1px solid currentColor;
      border-radius: 999px;
      padding: 3px 8px;
      color: var(--note);
      font-size: 12px;
      font-weight: 820;
      white-space: nowrap;
    }

    .high .badge, .critical .badge { color: var(--danger); }
    .medium .badge { color: var(--warn); }

    .location {
      color: var(--muted);
      font-size: 12px;
      overflow-wrap: anywhere;
      text-align: right;
    }

    pre {
      margin: 0 0 8px;
      padding: 9px;
      border-radius: 6px;
      background: #f1ebdd;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      font: 12px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    .finding p {
      margin: 0;
      color: var(--muted);
    }

    .finding p + p {
      margin-top: 6px;
    }

    .empty, .error {
      padding: 18px;
      color: var(--muted);
    }

    .error { color: var(--danger); }

    @media (max-width: 920px) {
      body { padding: 12px; }
      header, .layout { display: block; }
      .controls { justify-content: flex-start; margin-top: 12px; }
      .panel + .panel { margin-top: 14px; }
      .metrics { grid-template-columns: repeat(2, 1fr); }
    }
  </style>
</head>
<body>
  <main class="shell">
    <header>
      <div>
        <h1>Awal</h1>
        <p class="tagline">A local fresh-clone checker. It compares the README promise with package scripts, env examples, Docker files, ports, and repo setup evidence.</p>
      </div>
      <div class="controls">
        <input id="path" value="." aria-label="Repository path">
        <select id="failOn" aria-label="Block threshold">
          <option value="high">Block on high</option>
          <option value="medium">Block on medium</option>
          <option value="critical">Block on critical</option>
          <option value="low">Block on low</option>
        </select>
        <button type="button" class="primary" id="scan">Scan</button>
      </div>
    </header>

    <section class="layout">
      <section class="panel">
        <div class="decision">
          <div class="decision-top">
            <div id="score" class="score">0</div>
            <div>
              <h2 id="status">Ready</h2>
              <p id="help">Scan a local repo to see if the README can survive a fresh clone.</p>
            </div>
          </div>
          <div class="metrics">
            <div class="metric"><strong id="critical">0</strong><span>critical</span></div>
            <div class="metric"><strong id="high">0</strong><span>high</span></div>
            <div class="metric"><strong id="medium">0</strong><span>medium</span></div>
            <div class="metric"><strong id="low">0</strong><span>low</span></div>
          </div>
        </div>
        <div class="surface">
          <div class="surface-row"><span>README</span><strong id="readme">-</strong></div>
          <div class="surface-row"><span>Commands found</span><strong id="commands">0</strong></div>
          <div class="surface-row"><span>Package manager</span><strong id="manager">-</strong></div>
          <div class="surface-row"><span>Env keys used in code</span><strong id="envUsages">0</strong></div>
        </div>
      </section>

      <section class="panel">
        <div class="panel-head">
          <h2>Fresh-clone blockers</h2>
          <button type="button" id="download" disabled>Save JSON</button>
        </div>
        <div id="findings" class="findings">
          <div class="empty">No scan yet.</div>
        </div>
      </section>
    </section>
  </main>

  <script>
    const els = {
      path: document.getElementById("path"),
      failOn: document.getElementById("failOn"),
      scan: document.getElementById("scan"),
      score: document.getElementById("score"),
      status: document.getElementById("status"),
      help: document.getElementById("help"),
      critical: document.getElementById("critical"),
      high: document.getElementById("high"),
      medium: document.getElementById("medium"),
      low: document.getElementById("low"),
      readme: document.getElementById("readme"),
      commands: document.getElementById("commands"),
      manager: document.getElementById("manager"),
      envUsages: document.getElementById("envUsages"),
      findings: document.getElementById("findings"),
      download: document.getElementById("download")
    };
    let lastReport = null;

    els.scan.addEventListener("click", scan);
    els.download.addEventListener("click", downloadJson);
    els.path.addEventListener("keydown", (event) => {
      if (event.key === "Enter") scan();
    });

    async function scan() {
      els.scan.disabled = true;
      els.scan.textContent = "Scanning";
      try {
        const response = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            path: els.path.value || ".",
            fail_on: els.failOn.value
          })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Scan failed.");
        lastReport = data;
        render(data);
      } catch (error) {
        showError(error.message);
      } finally {
        els.scan.disabled = false;
        els.scan.textContent = "Scan";
      }
    }

    function render(report) {
      const severity = report.summary.by_severity;
      const repo = report.summary.repo || {};
      els.score.textContent = report.risk_score;
      els.score.className = `score ${report.status}`;
      els.status.textContent = label(report.status);
      els.help.textContent = help(report.status);
      els.critical.textContent = severity.critical;
      els.high.textContent = severity.high;
      els.medium.textContent = severity.medium;
      els.low.textContent = severity.low;
      els.readme.textContent = repo.readme || "missing";
      els.commands.textContent = repo.commands || 0;
      els.manager.textContent = repo.package_manager || "-";
      els.envUsages.textContent = (repo.env_usages || []).length;
      els.download.disabled = false;

      if (!report.findings.length) {
        els.findings.innerHTML = '<div class="empty">README looks aligned with this local check.</div>';
        return;
      }
      els.findings.innerHTML = "";
      for (const finding of report.findings) {
        const item = document.createElement("article");
        item.className = `finding ${finding.severity}`;
        item.innerHTML = `
          <div class="finding-top">
            <span class="badge">${escapeHtml(finding.severity)} / ${escapeHtml(finding.category.replaceAll("_", " "))}</span>
            <span class="location">${escapeHtml(finding.file)}:${finding.line}</span>
          </div>
          <pre>${escapeHtml(finding.excerpt)}</pre>
          <p>${escapeHtml(finding.why_it_matters)}</p>
          <p>${escapeHtml(finding.suggested_review)}</p>
        `;
        els.findings.appendChild(item);
      }
    }

    function label(status) {
      if (status === "pass") return "Fresh clone ready";
      if (status === "review") return "Needs cleanup";
      if (status === "block") return "README is lying";
      return "Ready";
    }

    function help(status) {
      if (status === "pass") return "No obvious README drift found.";
      if (status === "review") return "Fix the review items before handing this to a new dev.";
      return "A fresh developer will likely hit a broken setup path.";
    }

    function showError(message) {
      els.status.textContent = "Error";
      els.help.textContent = message;
      els.findings.innerHTML = `<div class="error">${escapeHtml(message)}</div>`;
      els.download.disabled = true;
    }

    function downloadJson() {
      if (!lastReport) return;
      const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "awal-report.json";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    }

    function escapeHtml(value) {
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }
  </script>
</body>
</html>
"""


class AwalHandler(BaseHTTPRequestHandler):
    server_version = "AwalHTTP/0.1"

    def do_GET(self) -> None:
        if self.path in {"/", "/index.html"}:
            self.send_text(HTML, content_type="text/html; charset=utf-8")
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        if self.path != "/api/scan":
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        try:
            payload = self.read_json()
            fail_on = str(payload.get("fail_on") or "high")
            if fail_on not in SEVERITY_RANK:
                raise ValueError("Invalid block threshold.")
            path = Path(str(payload.get("path") or ".")).expanduser()
            report = scan_path(path, fail_on=fail_on)
            self.send_json(report.to_dict())
        except ValueError as error:
            self.send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
        except Exception as error:
            self.send_json({"error": f"Scan failed: {error}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def read_json(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            raise ValueError("Request body is empty.")
        if length > MAX_REQUEST_BYTES:
            raise ValueError("Request body is too large.")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as error:
            raise ValueError("Request body is not valid JSON.") from error
        if not isinstance(data, dict):
            raise ValueError("Request body must be a JSON object.")
        return data

    def send_text(self, body: str, *, content_type: str = "text/plain; charset=utf-8") -> None:
        encoded = body.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def send_json(self, body: dict[str, object], *, status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve_ui(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, *, open_browser: bool = False) -> None:
    server = ThreadingHTTPServer((host, port), AwalHandler)
    url = f"http://{host}:{server.server_port}/"
    print(f"Awal UI running at {url}")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAwal UI stopped.")
    finally:
        server.server_close()
