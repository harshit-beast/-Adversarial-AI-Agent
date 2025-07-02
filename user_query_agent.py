import argparse
import re
import subprocess
import dns.resolver
import whois
import ssl
import socket
import requests
from datetime import datetime

from langchain_ollama import ChatOllama  # ✅ Working version with invoke()
from langchain_core.tools import Tool

from report_generator import generate_report
from access_simulation import find_admin_panels
from recon_modules import run_port_scan, run_subdomain_scan

# -------- Utility -------- #
def clean_domain(domain):
    return domain.strip().split()[0].replace('@10.', '')

# -------- Tools -------- #
def run_dns(domain):
    try:
        domain = clean_domain(domain)
        answers = dns.resolver.resolve(domain, 'A')
        return '\n'.join([str(rdata) for rdata in answers])
    except Exception as e:
        return f"DNS Error: {e}"

def run_whois(domain):
    try:
        domain = clean_domain(domain)
        info = whois.whois(domain)
        return str(info)
    except Exception as e:
        return f"WHOIS Error: {e}"

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
            expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            return f"🔐 SSL Certificate for {domain}\nIssued To: {issued_to}\nIssued By: {issued_by}\nExpiry: {cert['notAfter']} ({(expiry - datetime.utcnow()).days} days left)"
    except Exception as e:
        return f"SSL Error: {e}"

def port_scan(domain): return run_port_scan(domain)
def subdomain_enum(domain): return run_subdomain_scan(domain)
def find_admin(domain): return "\n".join(find_admin_panels(domain)) or "No admin panels found."

def geo_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        resp = requests.get(f"http://ip-api.com/json/{ip}").json()
        return f"{resp['query']} → {resp['country']}, {resp['regionName']}, {resp['city']}"
    except:
        return "GeoIP failed."

def reverse_dns(domain):
    try:
        ip = socket.gethostbyname(domain)
        return f"{ip} → {socket.gethostbyaddr(ip)[0]}"
    except:
        return "Reverse DNS failed."

def get_headers(domain):
    try:
        r = requests.head(f"https://{domain}", timeout=5)
        return "\n".join([f"{k}: {v}" for k, v in r.headers.items()])
    except:
        return "Header fetch failed."

def tech_stack(domain):
    return "Tech stack detection not implemented. Use Wappalyzer API."

def run_vulnerability_scan(domain):
    try:
        result = subprocess.run(
            ["nuclei", "-u", f"https://{domain}", "-silent", "-timeout", "10"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60
        )
        return result.stdout or result.stderr or "✅ No vulnerabilities found."
    except Exception as e:
        return f"Scan Error: {e}"

# -------- Tool List -------- #
tools = [
    Tool(name="DNS Lookup", func=run_dns, description="Get DNS A records"),
    Tool(name="WHOIS Lookup", func=run_whois, description="WHOIS info"),
    Tool(name="SSL Check", func=run_ssl_check, description="SSL cert info"),
    Tool(name="Port Scan", func=port_scan, description="Scan open ports"),
    Tool(name="Subdomain Finder", func=subdomain_enum, description="Find subdomains"),
    Tool(name="Admin Panel Finder", func=find_admin, description="Find admin panels"),
    Tool(name="IP Geolocation", func=geo_ip, description="Locate IP"),
    Tool(name="Reverse DNS", func=reverse_dns, description="Reverse DNS lookup"),
    Tool(name="HTTP Header Checker", func=get_headers, description="Get response headers"),
    Tool(name="Technology Stack Detector", func=tech_stack, description="Detect stack (placeholder)"),
    Tool(name="Vulnerability Scanner", func=run_vulnerability_scan, description="Nuclei CVE scan")
]

# -------- Manual Tool Runner -------- #
def manual_tool_runner(query, domain):
    for tool in tools:
        if any(k in query.lower() for k in tool.name.lower().split()):
            print(f"🔧 Using Tool: {tool.name}")
            return tool.func(domain)
    return f"❌ No matching tool found for: '{query}'"

# -------- Main CLI -------- #
parser = argparse.ArgumentParser()
parser.add_argument("--query", required=True)
parser.add_argument("--output", default="day29_report.html")
args = parser.parse_args()
query = args.query
output_file = args.output

# -------- Normalize Domain -------- #
domain_match = re.search(r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', query)
domain = domain_match.group(1) if domain_match else "example.com"

# -------- Run Tool -------- #
tool_output = manual_tool_runner(query, domain)

# -------- Use Ollama for Summary -------- #
llm = ChatOllama(model="llama3")
summary = llm.invoke(f"Summarize this recon result:\n\n{tool_output}")

# -------- Final Output -------- #
print("\n🧠 Final Output:\n", summary)

# -------- Save Report -------- #
generate_report("LangGraph Agent Report", {
    "User Query": query,
    "Tool Output": tool_output,
    "LLM Summary": str(summary)
}, output_file)
print(f"\n✅ Report saved: {output_file}")
