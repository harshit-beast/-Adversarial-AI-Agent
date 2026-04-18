# Project Scope Derived from `AI for cybersecurity.odp`

## Core objective
Build an AI-assisted cybersecurity agent that follows an ethical attack lifecycle in authorized lab environments:

1. Reconnaissance
2. Gaining access (simulated)
3. Privilege escalation (simulated)
4. Impact simulation (exfiltration / ransomware simulation)
5. Evasion simulation
6. Structured reporting

## Functional blocks
- Recon tools: DNS, WHOIS, SSL, ports, subdomains, headers, admin panel checks
- Web pentest checks: XSS, LFI, RFI, SSRF, command injection tests
- AI-oriented workflow orchestration: phase-based execution with reusable modules
- Reporting: JSON + HTML export with risk scoring and findings summary

## Implemented clean UI project
A clean web dashboard is implemented at:
- Backend API server: `ui/clean_ui_server.py`
- Frontend: `ui/web/index.html`, `ui/web/styles.css`, `ui/web/app.js`

### Run
```bash
cd "/Users/harshit/Downloads/ adversarail_agent"
./venv/bin/python ui/clean_ui_server.py --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080`.

## Notes
- Use only on systems you own or are explicitly authorized to test.
- Some modules depend on local tools/network availability; errors are surfaced in the UI per module.
