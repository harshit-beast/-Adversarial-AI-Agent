#!/usr/bin/env python3
"""Clean web UI server for the Adversarial AI Agent project.

This server provides a small JSON API and serves a static frontend.
It is designed for authorized lab environments only.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse, quote

try:
    import requests
except Exception:  # pragma: no cover - optional dependency
    requests = None

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = Path(__file__).resolve().parent / "web"
REPORT_DIR = PROJECT_ROOT / "data" / "reports"

sys.path.insert(0, str(PROJECT_ROOT))

from recon_tools.recon_modules import run_dns, run_port_scan, run_subdomain_scan, run_whois
from exploit_tools.access_simulation import (
    find_admin_panels,
    simulate_data_exfiltration,
    simulate_evasion,
    simulate_privilege_escalation,
    simulate_ransomware_activity,
    simulate_weak_login_attempts,
)
from exploit_tools.cmd_injection_advanced import run_cmd_injection_advanced
from exploit_tools.cmd_injection_tester import run_cmd_injection_test
from exploit_tools.lfi_tester import run_lfi_test
from exploit_tools.rfi_test import run_rfi_test
from exploit_tools.ssrf_detector import run_ssrf_test
try:
    from agents.agent_brain import (
        generate_response as ollama_generate_response,
        is_ollama_running as ollama_is_running,
    )
except Exception:  # pragma: no cover - optional LLM integration
    ollama_generate_response = None
    ollama_is_running = None


RISKY_PORTS = {"21", "22", "23", "3389", "445", "3306", "5432"}
DOMAIN_PATTERN = re.compile(r"^[A-Za-z0-9.-]+$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, indent=2, default=str)
    return str(value)


def normalize_domain(raw_target: str) -> str:
    target = (raw_target or "").strip()
    if not target:
        raise ValueError("Target is required")

    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = (parsed.hostname or "").strip().lower()

    if not host:
        raise ValueError("Could not parse target domain")
    if not DOMAIN_PATTERN.fullmatch(host):
        raise ValueError("Target must be a valid domain or host")

    return host


def normalize_url(raw_url: str) -> str:
    url = (raw_url or "").strip()
    if not url:
        raise ValueError("URL is required")
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    return url


def safe_call(fn: Callable[..., Any], *args: Any) -> dict[str, Any]:
    started = time.time()
    try:
        result = fn(*args)
        return {
            "status": "ok",
            "duration_ms": int((time.time() - started) * 1000),
            "result": _as_text(result),
        }
    except Exception as exc:  # pragma: no cover - network/tool failures
        return {
            "status": "error",
            "duration_ms": int((time.time() - started) * 1000),
            "result": f"Error: {exc}",
        }


def run_ssl_check(target: str) -> str:
    context = ssl.create_default_context()
    with context.wrap_socket(socket.socket(), server_hostname=target) as client:
        client.settimeout(5.0)
        client.connect((target, 443))
        cert = client.getpeercert()

    subject = dict(item[0] for item in cert.get("subject", []))
    issuer = dict(item[0] for item in cert.get("issuer", []))
    return (
        f"Issued To: {subject.get('commonName', 'N/A')}\n"
        f"Issued By: {issuer.get('commonName', 'N/A')}\n"
        f"Valid From: {cert.get('notBefore', 'N/A')}\n"
        f"Valid Until: {cert.get('notAfter', 'N/A')}"
    )


def run_geo_lookup(target: str) -> str:
    if requests is None:
        return "Geo lookup unavailable: requests is not installed"

    ip = socket.gethostbyname(target)
    response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
    data = response.json()
    if data.get("status") != "success":
        return f"Geo lookup failed for {ip}"
    return (
        f"IP: {ip}\nCountry: {data.get('country')}\nRegion: {data.get('regionName')}\n"
        f"City: {data.get('city')}\nISP: {data.get('isp')}"
    )


def run_reverse_dns(target: str) -> str:
    ip = socket.gethostbyname(target)
    host, _, _ = socket.gethostbyaddr(ip)
    return f"IP: {ip}\nPTR: {host}"


def run_header_check(target: str) -> str:
    if requests is None:
        return "Header check unavailable: requests is not installed"

    response = requests.get(f"https://{target}", timeout=8)
    headers = [f"{k}: {v}" for k, v in response.headers.items()]
    return "\n".join(headers) if headers else "No headers received"


def run_reflected_xss_test(url: str) -> str:
    if requests is None:
        return "XSS test unavailable: requests is not installed"

    payload = "<script>alert(1337)</script>"
    if "=" not in url:
        return "URL must include a query parameter placeholder, for example ?q="

    encoded_payload = quote(payload, safe="")
    test_url = f"{url}{encoded_payload}"
    response = requests.get(test_url, timeout=8)

    if payload in response.text:
        return f"Potential reflected XSS: payload reflected in response.\nTest URL: {test_url}"
    if "alert(1337)" in response.text:
        return f"Potential reflected XSS indicator found in response.\nTest URL: {test_url}"
    return f"No reflected XSS indicators found.\nTest URL: {test_url}"


RECON_HANDLERS: dict[str, Callable[[str], Any]] = {
    "dns": run_dns,
    "whois": run_whois,
    "ssl": run_ssl_check,
    "ports": run_port_scan,
    "subdomains": run_subdomain_scan,
    "headers": run_header_check,
    "geo": run_geo_lookup,
    "reverse_dns": run_reverse_dns,
    "admin_panels": lambda target: "\n".join(find_admin_panels(target)) or "No admin panels found.",
}

SIMULATION_HANDLERS: dict[str, Callable[[str], Any]] = {
    "gaining_access": simulate_weak_login_attempts,
    "privilege_escalation": simulate_privilege_escalation,
    "evasion": lambda _target: simulate_evasion(),
    "impact_exfiltration": simulate_data_exfiltration,
    "impact_ransomware": simulate_ransomware_activity,
}

WEBTEST_HANDLERS: dict[str, Callable[[str], Any]] = {
    "xss": run_reflected_xss_test,
    "lfi": run_lfi_test,
    "rfi": run_rfi_test,
    "ssrf": run_ssrf_test,
    "cmd_injection_basic": run_cmd_injection_test,
    "cmd_injection_advanced": run_cmd_injection_advanced,
}


def _extract_risk_score(report: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []

    recon = report.get("recon", {})
    webtests = report.get("webtests", {})

    ports = _as_text(recon.get("ports", {}).get("result", ""))
    if any(p in ports for p in RISKY_PORTS):
        score += 2
        reasons.append("High-risk ports detected")

    admin = _as_text(recon.get("admin_panels", {}).get("result", ""))
    if admin and "No admin panels found" not in admin:
        score += 2
        reasons.append("Potential admin panel exposure")

    if "headers" in recon:
        headers_text = _as_text(recon.get("headers", {}).get("result", ""))
        for sec_header in ("X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options"):
            if sec_header not in headers_text:
                score += 1
                reasons.append(f"Missing recommended security header: {sec_header}")

    for test_name, test_data in webtests.items():
        result = _as_text(test_data.get("result", "")).lower()
        negative_markers = (
            "no vulnerabilities found",
            "not vulnerable",
            "no reflected xss",
            "no rfi indicators found",
            "no command injection",
            "no lfi",
            "no dom xss",
            "no stored xss",
        )
        positive_markers = ("vulnerable", "confirmed", "potential", "possible", "detected", "exploit")

        if any(marker in result for marker in negative_markers):
            continue
        if any(marker in result for marker in positive_markers):
            score += 2
            reasons.append(f"Potential issue from web test: {test_name}")

    score = min(score, 10)
    if score >= 8:
        level = "critical"
    elif score >= 6:
        level = "high"
    elif score >= 3:
        level = "medium"
    else:
        level = "low"

    return {"score": score, "level": level, "reasons": reasons}


def _looks_like_issue(result_text: str) -> bool:
    lowered = result_text.lower()
    negative_markers = (
        "no vulnerabilities found",
        "not vulnerable",
        "no reflected xss",
        "no rfi indicators found",
        "no command injection",
        "no lfi",
        "not vulnerable at",
        "no admin panels found",
        "no open ports found",
    )
    positive_markers = ("vulnerable", "confirmed", "potential", "possible", "detected", "exploit", "found")
    if any(marker in lowered for marker in negative_markers):
        return False
    return any(marker in lowered for marker in positive_markers)


def _fallback_ai_report(report: dict[str, Any]) -> str:
    risk = report.get("risk", {})
    recon = report.get("recon", {})
    webtests = report.get("webtests", {})
    simulation = report.get("simulation", {})
    reasons = risk.get("reasons", [])

    total_recon = len(recon)
    total_webtests = len(webtests)
    total_sim = len(simulation)

    issue_lines: list[str] = []
    for section_name, section_data in (
        ("recon", recon),
        ("webtest", webtests),
        ("simulation", simulation),
    ):
        for module_name, module_data in section_data.items():
            result = _as_text(module_data.get("result", ""))
            if _looks_like_issue(result):
                issue_lines.append(f"- [{section_name}] {module_name}: possible risk indicator detected.")

    if not issue_lines:
        issue_lines.append("- No high-confidence issues were auto-detected from current module outputs.")

    reason_lines = "\n".join(f"- {reason}" for reason in reasons) if reasons else "- No specific risk reasons were generated."

    return (
        "Executive Summary\n"
        f"- Overall risk: {str(risk.get('level', 'low')).upper()} ({risk.get('score', 0)}/10)\n"
        f"- Coverage: recon={total_recon}, webtests={total_webtests}, simulation={total_sim}\n\n"
        "Risk Drivers\n"
        f"{reason_lines}\n\n"
        "Potential Findings\n"
        f"{chr(10).join(issue_lines)}\n\n"
        "Recommended Next Steps\n"
        "- Re-run only modules that showed potential indicators and validate manually.\n"
        "- Confirm security headers, exposed admin panels, and risky ports.\n"
        "- Track fixes and re-test to verify risk reduction.\n"
    )


def _build_ai_prompt(report: dict[str, Any]) -> str:
    return (
        "You are a cybersecurity reporting assistant for authorized lab assessments.\n"
        "Create a concise report using these exact sections:\n"
        "1) Executive Summary\n"
        "2) Test Coverage\n"
        "3) Key Risks\n"
        "4) Top Findings\n"
        "5) Recommended Actions (Prioritized)\n\n"
        "Constraints:\n"
        "- Mention only what is supported by the input.\n"
        "- If uncertain, say verification is needed.\n"
        "- Keep it clear and practical.\n\n"
        f"Input JSON:\n{json.dumps(report, indent=2)}"
    )


def _generate_ai_report(report: dict[str, Any], use_ai: bool, model: str = "llama3") -> dict[str, str]:
    if not use_ai:
        return {"engine": "disabled", "summary": _fallback_ai_report(report)}

    if ollama_generate_response and ollama_is_running and ollama_is_running():
        try:
            prompt = _build_ai_prompt(report)
            summary = _as_text(ollama_generate_response(prompt, model=model))
            if summary.strip():
                return {"engine": f"ollama:{model}", "summary": summary}
        except Exception:
            pass

    return {"engine": "fallback", "summary": _fallback_ai_report(report)}


def _slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "-", value.strip().lower()).strip("-")
    return cleaned or "report"


def _build_html_report(title: str, report: dict[str, Any]) -> str:
    risk = report.get("risk", {})
    ai_report = report.get("ai_report", "")
    ai_engine = _as_text(report.get("ai_report_meta", {}).get("engine", "n/a"))

    def section_html(name: str, payload: dict[str, Any]) -> str:
        if not payload:
            return ""

        cards = []
        for key, item in payload.items():
            result = _as_text(item.get("result", ""))
            status = item.get("status", "unknown")
            duration = item.get("duration_ms", 0)
            cards.append(
                f"""
                <article class=\"result-card\">
                  <h4>{key}</h4>
                  <p><strong>Status:</strong> {status} | <strong>Duration:</strong> {duration} ms</p>
                  <pre>{result}</pre>
                </article>
                """
            )

        return f"""
          <section>
            <h3>{name}</h3>
            {''.join(cards)}
          </section>
        """

    reasons = "".join(f"<li>{reason}</li>" for reason in risk.get("reasons", [])) or "<li>No major indicators from selected modules.</li>"

    return f"""
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
  <title>{title}</title>
  <style>
    :root {{
      --bg: #061019;
      --panel: #0e1e2d;
      --panel-soft: #13283c;
      --text: #e8f0ff;
      --muted: #9fb7d3;
      --line: #244160;
      --accent: #3dd6ff;
      --warn: #ffb84c;
      --danger: #ff6b6b;
      --ok: #57d68d;
    }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: radial-gradient(circle at 20% 0%, #12395e 0%, var(--bg) 50%);
      color: var(--text);
      padding: 28px;
      line-height: 1.5;
    }}
    h1, h2, h3, h4 {{ margin: 0 0 10px; }}
    .header {{
      border: 1px solid var(--line);
      background: rgba(7, 20, 32, 0.75);
      border-radius: 16px;
      padding: 20px;
      margin-bottom: 18px;
    }}
    .meta {{ color: var(--muted); }}
    .risk {{
      margin-top: 10px;
      display: inline-block;
      border-radius: 999px;
      padding: 6px 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      background: var(--panel-soft);
      border: 1px solid var(--line);
    }}
    .risk.low {{ color: var(--ok); }}
    .risk.medium {{ color: var(--warn); }}
    .risk.high, .risk.critical {{ color: var(--danger); }}
    section {{
      border: 1px solid var(--line);
      background: rgba(9, 28, 44, 0.78);
      border-radius: 16px;
      padding: 16px;
      margin-bottom: 16px;
    }}
    .result-card {{
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 12px;
      padding: 12px;
      margin: 10px 0;
    }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      margin: 8px 0 0;
      color: #d0e2f8;
      font-size: 13px;
    }}
    li {{ margin-bottom: 4px; color: var(--muted); }}
  </style>
</head>
<body>
  <header class=\"header\">
    <h1>{title}</h1>
    <p class=\"meta\">Generated at {report.get('generated_at', _now_iso())}</p>
    <p class=\"meta\">Target: {report.get('target', 'N/A')}</p>
    <p class=\"risk {risk.get('level', 'low')}\">Risk: {risk.get('level', 'low')} ({risk.get('score', 0)}/10)</p>
  </header>

  <section>
    <h3>Risk Reasons</h3>
    <ul>{reasons}</ul>
  </section>

  <section>
    <h3>AI-Powered Report ({ai_engine})</h3>
    <pre>{ai_report or 'AI report was not generated for this export.'}</pre>
  </section>

  {section_html('Reconnaissance', report.get('recon', {}))}
  {section_html('Web Testing', report.get('webtests', {}))}
  {section_html('Lifecycle Simulation', report.get('simulation', {}))}
</body>
</html>
"""


def run_recon_modules(target: str, selected_modules: list[str]) -> dict[str, Any]:
    selected = selected_modules or list(RECON_HANDLERS.keys())
    output: dict[str, Any] = {}
    for module in selected:
        handler = RECON_HANDLERS.get(module)
        if not handler:
            output[module] = {
                "status": "error",
                "duration_ms": 0,
                "result": "Unknown module",
            }
            continue
        output[module] = safe_call(handler, target)
    return output


def run_simulation_modules(target: str, selected_phases: list[str]) -> dict[str, Any]:
    selected = selected_phases or list(SIMULATION_HANDLERS.keys())
    output: dict[str, Any] = {}
    for phase in selected:
        handler = SIMULATION_HANDLERS.get(phase)
        if not handler:
            output[phase] = {
                "status": "error",
                "duration_ms": 0,
                "result": "Unknown simulation phase",
            }
            continue
        output[phase] = safe_call(handler, target)
    return output


def run_web_tests(url: str, selected_tests: list[str]) -> dict[str, Any]:
    selected = selected_tests or list(WEBTEST_HANDLERS.keys())
    output: dict[str, Any] = {}
    for test in selected:
        handler = WEBTEST_HANDLERS.get(test)
        if not handler:
            output[test] = {
                "status": "error",
                "duration_ms": 0,
                "result": "Unknown test",
            }
            continue
        output[test] = safe_call(handler, url)
    return output


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "AdversarialCleanUI/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep terminal output concise while preserving access logs.
        super().log_message(fmt, *args)

    def _json_response(self, payload: dict[str, Any], status: int = 200) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _serve_file(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        content_type = "text/plain; charset=utf-8"
        if path.suffix == ".html":
            content_type = "text/html; charset=utf-8"
        elif path.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        elif path.suffix == ".js":
            content_type = "application/javascript; charset=utf-8"

        payload = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/":
            self._serve_file(WEB_ROOT / "index.html")
            return
        if self.path == "/assets/styles.css":
            self._serve_file(WEB_ROOT / "styles.css")
            return
        if self.path == "/assets/app.js":
            self._serve_file(WEB_ROOT / "app.js")
            return
        if self.path == "/api/health":
            self._json_response(
                {
                    "ok": True,
                    "service": self.server_version,
                    "generated_at": _now_iso(),
                    "message": "Dashboard API is running",
                }
            )
            return

        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._json_response({"ok": False, "error": "Invalid JSON payload"}, status=400)
            return

        try:
            if self.path == "/api/recon":
                target = normalize_domain(payload.get("target", ""))
                modules = payload.get("modules", [])
                recon = run_recon_modules(target, modules)
                response = {
                    "ok": True,
                    "target": target,
                    "generated_at": _now_iso(),
                    "recon": recon,
                    "risk": _extract_risk_score({"recon": recon}),
                }
                self._json_response(response)
                return

            if self.path == "/api/simulate":
                target = normalize_domain(payload.get("target", ""))
                phases = payload.get("phases", [])
                simulation = run_simulation_modules(target, phases)
                response = {
                    "ok": True,
                    "target": target,
                    "generated_at": _now_iso(),
                    "simulation": simulation,
                }
                self._json_response(response)
                return

            if self.path == "/api/webtest":
                url = normalize_url(payload.get("url", ""))
                tests = payload.get("tests", [])
                webtests = run_web_tests(url, tests)
                response = {
                    "ok": True,
                    "url": url,
                    "generated_at": _now_iso(),
                    "webtests": webtests,
                    "risk": _extract_risk_score({"webtests": webtests}),
                }
                self._json_response(response)
                return

            if self.path == "/api/full-pipeline":
                target = normalize_domain(payload.get("target", ""))
                include_webtests = bool(payload.get("include_webtests", False))
                webtest_url = payload.get("webtest_url", "")

                recon = run_recon_modules(target, payload.get("recon_modules", []))
                simulation = run_simulation_modules(target, payload.get("simulation_phases", []))
                webtests: dict[str, Any] = {}

                if include_webtests and webtest_url:
                    webtests = run_web_tests(normalize_url(webtest_url), payload.get("web_tests", []))

                report = {
                    "ok": True,
                    "target": target,
                    "generated_at": _now_iso(),
                    "recon": recon,
                    "simulation": simulation,
                    "webtests": webtests,
                }
                report["risk"] = _extract_risk_score(report)
                self._json_response(report)
                return

            if self.path == "/api/report":
                title = (payload.get("title") or "AI Cybersecurity Assessment").strip()
                target = (payload.get("target") or "unspecified-target").strip()
                ai_powered = bool(payload.get("ai_powered", False))
                ai_model = _as_text(payload.get("ai_model", "llama3")).strip() or "llama3"

                report: dict[str, Any] = {
                    "title": title,
                    "target": target,
                    "generated_at": _now_iso(),
                    "recon": payload.get("recon", {}),
                    "webtests": payload.get("webtests", {}),
                    "simulation": payload.get("simulation", {}),
                }
                report["risk"] = _extract_risk_score(report)
                ai_summary = _generate_ai_report(report, use_ai=ai_powered, model=ai_model)
                report["ai_report"] = ai_summary["summary"]
                report["ai_report_meta"] = {"engine": ai_summary["engine"], "requested": ai_powered, "model": ai_model}

                REPORT_DIR.mkdir(parents=True, exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                base_name = f"{timestamp}-{_slugify(target)}"
                json_path = REPORT_DIR / f"{base_name}.json"
                html_path = REPORT_DIR / f"{base_name}.html"

                json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
                html_path.write_text(_build_html_report(title, report), encoding="utf-8")

                response = {
                    "ok": True,
                    "message": "Report exported",
                    "generated_at": report["generated_at"],
                    "risk": report["risk"],
                    "json_report": str(json_path),
                    "html_report": str(html_path),
                    "ai_report": report["ai_report"],
                    "ai_engine": report["ai_report_meta"]["engine"],
                }
                self._json_response(response)
                return

            self._json_response({"ok": False, "error": "Unknown endpoint"}, status=404)

        except ValueError as exc:
            self._json_response({"ok": False, "error": str(exc)}, status=400)
        except Exception as exc:  # pragma: no cover - runtime errors
            self._json_response({"ok": False, "error": f"Server error: {exc}"}, status=500)


def run_server(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"[clean-ui] Server started at http://{host}:{port}")
    print("[clean-ui] Authorized lab targets only. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the clean UI dashboard server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", default=8080, type=int, help="Port to bind")
    args = parser.parse_args()

    run_server(args.host, args.port)
