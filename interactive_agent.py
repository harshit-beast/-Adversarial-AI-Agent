# interactive_agent.py
from run_full_recon import run_full_recon
from langchain_ollama import ChatOllama
from langchain.agents import initialize_agent, AgentType, AgentExecutor
from langchain_core.tools import Tool
from langchain.memory import ConversationBufferMemory
from user_query_agent import run_sqlmap_scan


# ✅ Import your recon functions
from recon_modules import run_port_scan, run_subdomain_scan
from access_simulation import find_admin_panels
from user_query_agent import (
    run_dns, run_ssl_check, run_whois, geo_ip, reverse_dns,
    get_headers, tech_stack, run_vulnerability_scan, run_sqlmap_scan
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
