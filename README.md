# 🛡️ AI Recon Cybersecurity Agent (LangChain + LLM)

This project is an **AI-powered Reconnaissance Agent** designed for cybersecurity tasks. It combines powerful recon tools like DNS lookup, WHOIS, SSL check, and CVE scanning with natural language summarization using **LangChain** and **Ollama**.

> ✅ Built with LangChain  
> ⚙️ CLI-based workflow  
> 💡 LLM-powered summaries  
> 🔍 Modular recon tools  
> 📄 Auto-generated reports  

---

## 🚀 Features

- 🔍 **Domain Reconnaissance Tools**
  - WHOIS Lookup
  - DNS Resolution
  - SSL Certificate Checker
  - Port Scanner
  - Subdomain Enumeration
  - Admin Panel Finder
  - IP Geolocation
  - Reverse DNS
  - HTTP Headers Fetcher
  - Technology Stack Detector (placeholder)
  - CVE/Vulnerability Scanner via [Nuclei](https://github.com/projectdiscovery/nuclei)

- 🧠 **Natural Language Summarization**
  - Uses `ChatOllama` with the `llama3` model to explain technical results in simple language.

- 📁 **Modular Design**
  - Each recon task is a separate function/tool.
  - Easily extendable with more tools or API integrations.

- 📄 **Report Generation**
  - Automatically saves recon results and LLM summaries to an HTML file.

---

## 🧱 Project Structure

```bash
Adversarial_AI_Agent/
│
├── terminal_UI.py              # Interactive CLI for users
├── user_query_agent.py         # Tool handler and LLM summarizer
├── recon_modules/              # Port scanner, subdomain finder, etc.
├── access_simulation.py        # Admin panel finder logic
├── report_generator.py         # HTML report generation
├── README.md                   # Project documentation
└── requirements.txt            # Python dependencies
