# 🤖 Adversarial AI Agent

A powerful, modular AI-powered cybersecurity recon and exploitation framework designed to simulate adversarial attacks using LangChain, NLP, and custom-built tools.  
This project leverages automation and LLMs to identify potential vulnerabilities and simulate real-world attacks for research and educational purposes.

---

## 📌 Features

- 🔍 **Automated Reconnaissance**: WHOIS, DNS, subdomains, SSL certificate checks
- 🧠 **AI Agents**: LangChain-driven agents for dynamic analysis and response
- 🛡️ **Exploitation Modules**: Privilege escalation, access simulation, and credential attacks
- 📊 **HTML Report Generation**: Clean, structured, actionable output
- 🧠 **LLM Summarization**: Converts recon data into human-readable risk summaries

---

## 🗂️ Project Structure

```bash
Adversarial_Agent/
│
├── agents/              # LangChain + NLP AI agents
├── recon_tools/         # DNS, WHOIS, SSL, subdomain scanners
├── exploit_tools/       # Privilege escalation & simulated attacks
├── report_generator/    # Report rendering & risk summary
├── logger/              # Centralized logging
├── utils/               # Graphs, helpers, summaries
├── data/                # Intermediate saved data
├── tests/               # Unit tests for modules
├── terminal_UI.py       # CLI interface
├── requirements.txt     # Dependencies
└── README.md            # Project documentation




🤖 agents
This directory contains modular AI agents and logic-based scripts for automating reconnaissance, analysis, and exploitation decision-making. Each agent is responsible for a specific function within the adversarial pipeline.

Agent Modules
Script Name	Description
ai_agent.py	Core AI decision-making logic using rule-based and LLM-guided recon strategies.
agent_brain.py	Central coordinator that manages interaction between tools and agents.
interactive_agent.py	Interactive CLI-based agent that lets users explore recon and exploit paths dynamically.
langchain_agent.py	Basic agent powered by LangChain for chaining recon queries.
langchain_agent_report.py	Agent that summarizes recon data using LLMs and generates human-readable reports.
llm_agent.py	Utility for LLM-based parsing, summarization, and scoring of recon data.
nlp_agent.py	Performs NLP analysis on collected data to extract entities and key insights.
langchain_ssl_agent.py	SSL-specific agent that uses LangChain and LLM to analyze certificate data.
stored_xss_response.html	Stores output for stored XSS results processed by agents.
user_query_agent.py	Accepts natural language queries (e.g., "check SSL", "find DNS") and routes them to tools .



/////
📜 logger/
This directory manages all logging-related functionality for the Adversarial Agent framework. It handles structured output, log saving, and formatting for various recon and exploitation modules.

 
recon_logger.py	Contains logging functions such as:
• WHOIS lookup logs
• DNS records logging
• IP resolution
• HTTP headers, subdomains, etc.
Logs are formatted and saved for report generation.

recon_log.txt	Plaintext file where recon outputs are stored temporarily. Used by report_generator.py to create HTML reports.


///////
🧨 exploit_tools
This directory contains offensive security scripts used in the exploitation phase of the AI Recon Agent. These tools simulate attacks to identify vulnerabilities in target systems (for educational/research use only).




/////
🛠 UI
The ui/ folder contains the older terminal-based interface where the user is given two options (ONLY FOR RECON PHASE):
Stage 1: Perform a full reconnaissance scan.
Stage 2: Enter a specific query like "check whois" to run a targeted recon tool.

/////
exploit tools
 
upload_php_shell_tool.py	Uploads a PHP reverse shell (e.g., cmd.php) to a target via HTTP POST.
check_shell_tool.py	Verifies whether the uploaded shell is accessible.
cmd_injection_tester.py	Tests for basic command injection using payloads like ; ls.
cmd_injection_advanced.py	Performs advanced command injection with bypasses and chaining.
file_upload_tester.py	Attempts to upload different file types to test for upload vulnerabilities.
lfi_tester.py	Tests for Local File Inclusion (e.g., reading /etc/passwd).
rfi_test.py	Tests for Remote File Inclusion by injecting URLs.
sqlmap/	Contains SQL injection scripts using the sqlmap tool.
ssrf_detector.py	Detects Server-Side Request Forgery vulnerabilities.
privilege_evasion.py	Placeholder for scripts to simulate privilege escalation.
access_simulation.py	Simulates post-exploitation access control testing.