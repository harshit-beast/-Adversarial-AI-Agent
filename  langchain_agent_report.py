from langchain.agents import initialize_agent, Tool
from langchain.agents.agent_types import AgentType
from langchain.llms import Ollama

import dns.resolver
import whois
import ssl
import socket
from datetime import datetime
import re
from report_generator import generate_report  # ✅ Already exists

# -------- Clean domain -------- #
def clean_domain(domain):
    domain = domain.strip().split()[0]
    domain = domain.replace('@10.', '')
    return domain

# -------- DNS Tool -------- #
def run_dns(domain):
    try:
        domain = clean_domain(domain)
        answers = dns.resolver.resolve(domain, 'A')
        return '\n'.join([str(rdata) for rdata in answers])
    except Exception as e:
        return f"DNS Error: {e}"

# -------- WHOIS Tool -------- #
def run_whois(domain):
    try:
        domain = clean_domain(domain)
        info = whois.whois(domain)
        return str(info)
    except Exception as e:
        return f"WHOIS Error: {e}"

# -------- SSL Check Tool -------- #
def run_ssl_check(domain):
    try:
        domain = clean_domain(domain)
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
            issued_to = cert.get('subject', [('commonName', '')])[0][1]
            issued_by = cert.get('issuer', [('commonName', '')])[0][1]
            expiry_date = cert['notAfter']
            expiry = datetime.strptime(expiry_date, '%b %d %H:%M:%S %Y %Z')
            days_left = (expiry - datetime.utcnow()).days
            return f"""🔐 SSL Certificate Details:
- Issued To: {issued_to}
- Issued By: {issued_by}
- Expiry Date: {expiry_date}
- Days Remaining: {days_left}"""
    except Exception as e:
        return f"SSL Check Error: {e}"

# -------- LangChain LLM -------- #
llm = Ollama(model="llama3")

# -------- Tools -------- #
tools = [
    Tool(name="DNS Lookup", func=run_dns, description="Get A record IPs of domain"),
    Tool(name="WHOIS Lookup", func=run_whois, description="Get WHOIS info of domain"),
    Tool(name="SSL Certificate Check", func=run_ssl_check, description="Get SSL cert details")
]

# -------- LangChain Agent -------- #
agent = initialize_agent(tools, llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION, verbose=True)

# -------- User Query -------- #
query = "Check DNS, WHOIS, and SSL info for openai.com"
response = agent.invoke(query)

# -------- Extract domain (optional) -------- #
match = re.search(r'for\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', query)
domain = match.group(1) if match else "domain"

# -------- Save Report -------- #
report_data = {
    "LangChain Agent Output": response['output']
}
output_file = f"{domain}_agent_report.html"
generate_report(domain, report_data, output_file)

print(f"\n✅ Report saved to: {output_file}")
