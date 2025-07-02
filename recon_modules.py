import nmap
import requests
import socket
import dns.resolver
import subprocess
# Remove or comment this if it exists:
# import whois

# Add this instead:
import whois as pythonwhois 
def run_whois(target):
    try:
        result = pythonwhois.whois(target)
        return str(result)
    except Exception as e:
        return f"WHOIS Error: {e}"

def run_dns(target):
    try:
        result = dns.resolver.resolve(target, 'A')
        return '\n'.join([str(ip.address) for ip in result])
    except Exception as e:
        return f"DNS Error: {e}"

def run_port_scan(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments='-T4 -F')
        result = ""
        for host in nm.all_hosts():
            result += f"Host: {host} ({nm[host].hostname()})\n"
            for proto in nm[host].all_protocols():
                result += f"Protocol: {proto}\n"
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]['state']
                    result += f"Port: {port}\tState: {state}\n"
        return result or "No open ports found."
    except Exception as e:
        return f"Nmap Error: {e}"

def run_subdomain_scan(target):
    subdomains = ["www", "mail", "ftp", "test", "ns1", "blog"]
    results = []
    for sub in subdomains:
        url = f"{sub}.{target}"
        try:
            socket.gethostbyname(url)
            results.append(url)
        except:
            continue
    return '\n'.join(results) or "No subdomains found."

def generate_html_report(target, whois_data, dns_data, ports_data, subdomains_data, filename):
    with open(filename, "w") as f:
        f.write("<html><body>")
        f.write(f"<h2>Recon Report for {target}</h2><hr>")
        f.write(f"<h3>WHOIS Data</h3><pre>{whois_data}</pre><hr>")
        f.write(f"<h3>DNS Data</h3><pre>{dns_data}</pre><hr>")
        f.write(f"<h3>Port Scan</h3><pre>{ports_data}</pre><hr>")
        f.write(f"<h3>Subdomains</h3><pre>{subdomains_data}</pre>")
        f.write("</body></html>")

def run_vulnerability_scan(domain):
    try:
        result = subprocess.run(
            ["nuclei", "-u", f"https://{domain}", "-silent", "-timeout", "10"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60
        )
        if result.stdout:
            return result.stdout
        elif result.stderr:
            return f"Nuclei error:\n{result.stderr}"
        else:
            return "✅ No vulnerabilities found."
    except Exception as e:
        return f"Error running vulnerability scan: {e}"