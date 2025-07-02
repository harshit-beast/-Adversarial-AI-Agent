from langchain.agents import initialize_agent, Tool
from langchain.agents.agent_types import AgentType
from langchain_community.llms import Ollama  # Updated import

import dns.resolver
import whois
import ssl
import socket
from datetime import datetime

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

# -------- SSL Check Tool (Safe version) -------- #
def run_ssl_check(domain):
    try:
        domain = clean_domain(domain)
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5.0)
            s.connect((domain, 443))
            cert = s.getpeercert()

            # Safe extraction
            issued_to = "Unknown"
            issued_by = "Unknown"

            subject = cert.get('subject', [])
            for item in subject:
                if isinstance(item, tuple):
                    for key, value in item:
                        if key.lower() == 'commonname':
                            issued_to = value

            issuer = cert.get('issuer', [])
            for item in issuer:
                if isinstance(item, tuple):
                    for key, value in item:
                        if key.lower() == 'commonname':
                            issued_by = value

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

# -------- LLM Init -------- #
llm = Ollama(model="llama3")

# -------- Tool List -------- #
tools = [
    Tool(name="DNS Lookup", func=run_dns, description="Get A record IPs of domain"),
    Tool(name="WHOIS Lookup", func=run_whois, description="Get WHOIS registration info"),
    Tool(name="SSL Certificate Check", func=run_ssl_check, description="Get SSL certificate details")
]

# -------- Agent Init -------- #
agent = initialize_agent(tools, llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION, verbose=True)

# -------- Ask Agent -------- #
query = "Check DNS, WHOIS, and SSL info for openai.com"
response = agent.invoke(query)

print("\n🧠 Final Output:\n", response)
