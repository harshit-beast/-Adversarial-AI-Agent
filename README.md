Adversarial AI Agent

An intelligent offensive security automation framework built for reconnaissance, vulnerability discovery, and controlled exploitation testing.

This project combines modular security tooling with language-model-driven workflows to automate common penetration testing tasks, summarize findings, and streamline security research.

Overview

Adversarial AI Agent is designed to simulate how an attacker approaches a target:

Information gathering
Surface mapping
Misconfiguration detection
Vulnerability testing
Result analysis
Reporting

It supports both manual testing and AI-assisted decision making.

Core Features
Reconnaissance
WHOIS lookup
DNS enumeration
Subdomain discovery
SSL certificate inspection
Reverse DNS
Header fingerprinting
IP geolocation
AI Agent Layer
Natural language commands
Automatic tool selection
Multi-step reasoning workflows
LLM-based summaries
Human-readable outputs
Exploitation Modules
SQL Injection checks
XSS testing
File upload validation
Command injection checks
SSRF testing
LFI / RFI testing
Post-access simulation
Reporting
HTML reports
Structured findings
Risk summaries
Actionable notes
Project Structure
Adversarial_Agent/
│
├── agents/
├── recon_tools/
├── exploit_tools/
├── report_generator/
├── logger/
├── utils/
├── data/
├── tests/
├── ui/
├── requirements.txt
└── README.md
Installation
git clone <repository-url>
cd Adversarial_Agent

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
Run Web Interface
cd "/Users/harshit/Downloads/adversarail_agent"
./venv/bin/python ui/clean_ui_server.py --host 127.0.0.1 --port 8080

Open in browser:

http://127.0.0.1:8080
Run Interactive Agent
cd agents
python3 interactive_agent.py
Example Commands
Recon
run full recon on example.com
find subdomains of tesla.com
check ssl for github.com
get ip info for openai.com
Exploitation
check sql injection on http://target.com/item.php?id=1
check xss on http://target.com/search?q=
check lfi on http://target.com/index.php?file=
check ssrf on http://target.com/fetch?url=
check file upload vulnerability on http://target.com/upload
Agents Directory
File	Purpose
ai_agent.py	Main reasoning logic
agent_brain.py	Workflow controller
interactive_agent.py	CLI assistant
langchain_agent.py	Tool-chaining agent
llm_agent.py	Parsing and summarization
nlp_agent.py	Entity extraction
user_query_agent.py	Command routing
Exploit Modules
Tool	Description
sqlmap/	SQLi automation
xss_tester.py	XSS payload testing
cmd_injection_tester.py	Command injection
file_upload_tester.py	Upload validation
lfi_tester.py	Local file inclusion
rfi_test.py	Remote file inclusion
ssrf_detector.py	SSRF checks
Logging

All module output can be stored for later review.

Examples:

DNS responses
WHOIS data
HTTP headers
Exploit results
Scan summaries
Reporting Engine

Reports can include:

Recon summary
Findings by severity
Screenshots / evidence
Recommendations
AI-generated explanation
Recommended Use Cases
Security labs
Local testing environments
CTF practice
Pentest workflow automation
Research tooling
Bug bounty recon support
Requirements

Typical dependencies include:

langchain
requests
beautifulsoup4
flask
selenium
python-whois
dnspython
sqlmap
ollama

Install everything from:

pip install -r requirements.txt
Notes

This project is modular. New tools can be added easily under:

recon_tools/
exploit_tools/
agents/
Legal Disclaimer

Use only on systems you own or are authorized to test.

The author is not responsible for misuse, unauthorized scanning, or illegal activity.

Future Improvements
Multi-agent coordination
Payload mutation engine
Dashboard analytics
Browser automation
CVE enrichment
Smarter exploit chaining

