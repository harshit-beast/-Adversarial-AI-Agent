import argparse
import re
import subprocess
import dns.resolver
import whois as whois_module
import ssl
import socket
import requests
import time
import os
from datetime import datetime

from langchain_ollama import ChatOllama  # ✅ LLM
from langchain_core.tools import Tool

from report_generator import generate_report
from access_simulation import find_admin_panels
from recon_modules import run_port_scan, run_subdomain_scan

# -------- Utility -------- #
def clean_domain(domain):
    return domain.strip().split()[0].replace('@10.', '')

# -------- Tool Functions -------- #
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
        info = whois_module.whois(domain)
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

            subject_dict = dict(x[0] for x in cert.get('subject', []))
            issuer_dict = dict(x[0] for x in cert.get('issuer', []))
            issued_to = subject_dict.get('commonName', 'N/A')
            issued_by = issuer_dict.get('commonName', 'N/A')

            expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (expiry - datetime.utcnow()).days
            return f"🔐 SSL Certificate for {domain}\nIssued To: {issued_to}\nIssued By: {issued_by}\nExpiry: {cert['notAfter']} ({days_left} days left)"
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
        start = time.time()
        result = subprocess.run(
            [
                "nuclei",
                "-u", f"{domain}",
                "-severity", "critical,high",
                "-timeout", "5",
                "-retries", "1",
                "-silent",
                "-etags", "fuzz"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60
        )
        end = time.time()
        output = result.stdout or result.stderr or "✅ No vulnerabilities found."
        return f"⏱️ Scan duration: {round(end - start)}s\n{output}"
    except subprocess.TimeoutExpired:
        return f"❌ Scan Error: Nuclei scan timed out after 60s."
    except Exception as e:
        return f"❌ Scan Error: {e}"

def run_sqlmap_scan(url):
    try:
        sqlmap_path = os.path.expanduser("~/sqlmap/sqlmap.py")

        if not os.path.exists(sqlmap_path):
            return "❌ SQLMap path not found. Please ensure SQLMap is cloned to ~/sqlmap"

        if url.startswith("https://"):
            url = url.replace("https://", "http://")

        print(f"⏳ Running SQLMap on {url}")
        result = subprocess.run(
            [
                "python3", sqlmap_path,
                "-u", url,
                "--batch",
                "--level", "2",
                "--risk", "1",
                "--random-agent",
                "--silent"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=90
        )

        raw_output = result.stdout or result.stderr or "✅ No SQL injection vulnerabilities found."

        # LLM Summary
        llm = ChatOllama(model="llama3")
        summary_prompt = f"""You are a cybersecurity expert. The following output is from a SQLMap scan on a website.\nPlease summarize whether the site is vulnerable, what type of injection was found, the DBMS, and any important details in plain language:\n\n```\n{raw_output}\n```\nOnly include useful insights and remove unnecessary log lines."""
        summary = llm.invoke(summary_prompt)

        return f"🔍 SQLMap Raw Output:\n{raw_output}\n\n🧠 LLM Summary:\n{summary}"

    except subprocess.TimeoutExpired:
        return "❌ SQLMap timed out after 90s."
    except Exception as e:
        return f"❌ SQLMap failed: {e}"

# -------- Tools List -------- #
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
    Tool(name="Vulnerability Scanner", func=run_vulnerability_scan, description="Nuclei CVE scan"),
    Tool(name="SQLMap Injection Tester", func=run_sqlmap_scan, description="Use SQLMap to test for SQL injection")
]

# -------- Keyword Map for Matching -------- #
tool_keywords = {
    "DNS Lookup": ["dns", "a record"],
    "WHOIS Lookup": ["whois"],
    "SSL Check": ["ssl", "certificate"],
    "Port Scan": ["port", "nmap", "scan"],
    "Subdomain Finder": ["subdomain", "subdomains"],
    "Admin Panel Finder": ["admin", "panel", "admin panel"],
    "IP Geolocation": ["geo", "location", "ip location"],
    "Reverse DNS": ["reverse dns", "ptr"],
    "HTTP Header Checker": ["header", "http header"],
    "Technology Stack Detector": ["stack", "tech", "technology", "wappalyzer"],
    "Vulnerability Scanner": ["vuln", "vulnerability", "cve", "exploit", "nuclei"],
    "SQLMap Injection Tester": ["sqlmap", "sql injection", "inject", "database"]
}

# -------- Manual Tool Runner -------- #
def manual_tool_runner(query, domain):
    query_lower = query.lower()
    for tool in tools:
        keywords = tool_keywords.get(tool.name, [])
        if any(k in query_lower for k in keywords):
            print(f"🔧 Using Tool: {tool.name}")
            return tool.func(domain if tool.name != "SQLMap Injection Tester" else query)
    return f"❌ No matching tool found for: '{query}'"

# -------- Main CLI Logic (safe from import) -------- #
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", required=True)
    parser.add_argument("--output", default="day29_report.html")
    args = parser.parse_args()
    query = args.query
    output_file = args.output

    # Extract domain from query
    domain_match = re.search(r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', query)
    domain = domain_match.group(1) if domain_match else "example.com"

    # Run matched tool
    tool_output = manual_tool_runner(query, domain)

    # Use LLM to summarize
    llm = ChatOllama(model="llama3")
    summary = llm.invoke(f"Summarize this recon result:\n\n{tool_output}")

    # Display and save report
    print("\n🧠 Final Output:\n", summary)
    generate_report("LangGraph Agent Report", {
        "User Query": query,
        "Tool Output": tool_output,
        "LLM Summary": str(summary)
    }, output_file)

    print(f"\n✅ Report saved: {output_file}")

