from langchain.agents import initialize_agent, Tool
from langchain.agents.agent_types import AgentType
from langchain.llms import Ollama

import dns.resolver
import whois
import ssl
import socket
from datetime import datetime

# ----------------- Clean Domain ----------------- #
def clean_domain(domain):
    return domain.strip().split()[0].replace('@10.', '')

# ----------------- DNS Tool ----------------- #
def run_dns(domain):
    try:
        domain = clean_domain(domain)
        answers = dns.resolver.resolve(domain, 'A')
        return '\n'.join(str(rdata) for rdata in answers)
    except Exception as e:
        return f"DNS Error: {e}"

# ----------------- WHOIS Tool ----------------- #
def run_whois(domain):
    try:
        domain = clean_domain(domain)
        info = whois.whois(domain)
        return str(info)
    except Exception as e:
        return f"WHOIS Error: {e}"

# ----------------- SSL Cert Tool ----------------- #
def run_ssl_check(domain):
    try:
        domain = clean_domain(domain)
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            issued_to = cert.get('subject', [(('commonName', ''),)])[0][0][1]
            issued_by = cert.get('issuer', [(('commonName', ''),)])[0][0][1]
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

# ----------------- LLM + Tools ----------------- #
llm = Ollama(model="llama3")

tools = [
    Tool(name="DNS Lookup", func=run_dns, description="Find A records for a domain"),
    Tool(name="WHOIS Lookup", func=run_whois, description="Fetch WHOIS info of a domain"),
    Tool(name="SSL Certificate Check", func=run_ssl_check, description="Get SSL certificate info"),
]

agent = initialize_agent(tools, llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION, verbose=True)

# ----------------- User Interaction ----------------- #
while True:
    query = input("\n💬 Enter your query (type 'exit' to quit): ")
    if query.lower() == 'exit':
        break
    response = agent.invoke(query)
    print("\n🧠 Agent Response:\n", response)
