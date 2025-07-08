from agents.user_query_agent import run_dns, run_ssl_check, run_whois, geo_ip, reverse_dns, get_headers, tech_stack, run_vulnerability_scan
from recon_tools.recon_modules import run_port_scan, run_subdomain_scan
from exploit_tools.access_simulation import find_admin_panels

def run_full_recon(domain):
    results = []
    results.append("🔧 DNS:\n" + run_dns(domain))
    results.append("🔧 WHOIS:\n" + run_whois(domain))
    results.append("🔧 SSL:\n" + run_ssl_check(domain))
    results.append("🔧 GeoIP:\n" + geo_ip(domain))
    results.append("🔧 Reverse DNS:\n" + reverse_dns(domain))
    results.append("🔧 HTTP Headers:\n" + get_headers(domain))
    results.append("🔧 Tech Stack:\n" + tech_stack(domain))
    results.append("🔧 Vuln Scan:\n" + run_vulnerability_scan(domain))
    results.append("🔧 Port Scan:\n" + run_port_scan(domain))
    results.append("🔧 Subdomain Finder:\n" + run_subdomain_scan(domain))
    results.append("🔧 Admin Panel Finder:\n" + "\n".join(find_admin_panels(domain)))
    return "\n\n".join(results)
