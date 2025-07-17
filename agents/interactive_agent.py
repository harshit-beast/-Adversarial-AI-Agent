# interactive_agent.py
import sys
import os

# Ensure project root (one level above /agents) is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from recon_tools.run_full_recon import run_full_recon
from langchain_ollama import ChatOllama
from langchain.agents import initialize_agent, AgentType, AgentExecutor
from langchain_core.tools import Tool
from langchain.memory import ConversationBufferMemory
from agents.user_query_agent import run_sqlmap_scan
from agents.user_query_agent import run_xss_test
from exploit_tools.file_upload_tester import run_file_upload_test
from exploit_tools.cmd_injection_tester import run_cmd_injection_test
from exploit_tools.cmd_injection_advanced import run_cmd_injection_advanced 
from user_query_agent import run_path_traversal_test
from exploit_tools.ssrf_detector import run_ssrf_test
from exploit_tools.lfi_tester import run_lfi_test
from exploit_tools.rfi_test import run_rfi_test



# ✅ Import your recon functions
from recon_tools.recon_modules import run_port_scan, run_subdomain_scan
from exploit_tools.access_simulation import find_admin_panels
from agents.user_query_agent import (
    run_dns, run_ssl_check, run_whois, geo_ip, reverse_dns,
    get_headers, tech_stack, run_vulnerability_scan, run_sqlmap_scan, run_xss_test, run_stored_xss_test, run_dom_xss_test
)

# 🧠 Local LLM
llm = ChatOllama(model="llama3")

# 🛠️ Define tools
tools = [
    Tool(name="DNS Lookup", func=run_dns, description="Get DNS A records for a domain"),
    Tool(name="WHOIS Lookup", func=run_whois, description="Get WHOIS info of a domain"),
    Tool(name="SSL Check", func=run_ssl_check, description="Get SSL certificate details"),
    Tool(name="Port Scan", func=run_port_scan, description="Scan open ports"),
    Tool(name="Subdomain Finder", func=run_subdomain_scan, description="Find subdomains"),
    Tool(name="Admin Panel Finder", func=lambda d: "\n".join(find_admin_panels(d)), description="Find admin panels"),
    Tool(name="IP Geolocation", func=geo_ip, description="IP location of domain"),
    Tool(name="Reverse DNS", func=reverse_dns, description="Reverse DNS lookup"),
    Tool(name="HTTP Header Checker", func=get_headers, description="Get HTTP headers"),
    Tool(name="Technology Stack Detector", func=tech_stack, description="Detect tech stack (not implemented)"),
    Tool(name="Vulnerability Scanner", func=run_vulnerability_scan, description="Run Nuclei CVE scan"),
    Tool(
        name="Full Recon",
        func=run_full_recon,
        description="Run full recon on a domain. Triggers all recon tools."
    ),
    Tool(
    name="SQL Injection Tester",
    func=run_sqlmap_scan,
    description="Use SQLMap to test for SQL injection vulnerabilities on a URL with parameters"
    ),
    Tool(
    name="XSS Injection Tester",
    func=run_xss_test,
    description="Check if a URL with query parameters is vulnerable to reflected XSS."
	),
    Tool(
    name="Stored XSS Tester",
    func=run_stored_xss_test,
    description="Detects stored XSS by submitting payloads via POST and checking for reflection"
),
    Tool(
    name="DOM XSS Tester",
    func=run_dom_xss_test,
    description="Detects potential DOM-based XSS via URL hash payload injection"
),

Tool(
    name="File Upload Tester",
    func=run_file_upload_test,
    description="Test for file upload vulnerability and execution"
),
Tool(
    name="Command Injection Tester",
    func=run_cmd_injection_test,
    description="Tests if the URL is vulnerable to command injection using basic payloads"
),
Tool(
    name="Advanced Command Injection Tester",
    func=run_cmd_injection_advanced,
    description="Tests for command injection in POST body and headers"
),
Tool(
    name="Path Traversal Tester",
    func=run_path_traversal_test,
    description="Test for directory traversal vulnerabilities by attempting to read OS-level files"
),
Tool(
    name="SSRF Tester",
    func=run_ssrf_test,
    description="Checks for SSRF by injecting internal IP targets"
),

Tool(
    name="Local File Inclusion Tester",
    func=run_lfi_test,
    description="Detect LFI vulnerability by attempting to read /etc/passwd or other local files"
),

Tool(
    name="RFI Tester",
    func=run_rfi_test,
    description="Detect Remote File Inclusion by injecting remote file URL into parameters."
)



]

# 🧠 Enable memory for multi-turn conversation
memory = ConversationBufferMemory(memory_key="chat_history")

# 🤖 Create agent
agent = initialize_agent(
    tools=tools,
    llm=llm,
    agent=AgentType.CONVERSATIONAL_REACT_DESCRIPTION,
    memory=memory,
    verbose=True
)

# ✅ Wrap it with executor that handles LLM output errors
agent_executor = AgentExecutor.from_agent_and_tools(
    agent=agent.agent,
    tools=tools,
    verbose=True,
    memory=memory,
    handle_parsing_errors=True
)

# 💬 Chat loop
print("💬 Interactive Recon Chat Agent (type 'exit' to quit)\n")

while True:
    user_input = input("👤 You: ")
    if user_input.strip().lower() == "exit":
        print("👋 Exiting agent...")
        break
    try:
        response = agent_executor.run(user_input)
        print("🤖 Agent:", response, "\n")
    except Exception as e:
        print("❌ Error:", e, "\n")
