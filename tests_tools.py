from user_query_agent import (
    run_dns, run_ssl_check, run_whois, geo_ip, reverse_dns,
    get_headers, tech_stack, run_vulnerability_scan
)
from recon_modules import run_port_scan, run_subdomain_scan
from access_simulation import find_admin_panels

domain = "example.com"  # 🔁 Change as needed

print("\n🔧 Testing Tools...\n")

print("✅ DNS Lookup:", run_dns(domain))
print("✅ WHOIS:", run_whois(domain))
print("✅ SSL Check:", run_ssl_check(domain))
print("✅ Geo IP:", geo_ip(domain))
print("✅ Reverse DNS:", reverse_dns(domain))
print("✅ HTTP Headers:", get_headers(domain))
print("✅ Tech Stack:", tech_stack(domain))
print("✅ Vuln Scan:", run_vulnerability_scan(domain))
print("✅ Port Scan:", run_port_scan(domain))
print("✅ Subdomain Scan:", run_subdomain_scan(domain))
print("✅ Admin Panel Finder:", find_admin_panels(domain))
