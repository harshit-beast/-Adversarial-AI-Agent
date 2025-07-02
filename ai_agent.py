from recon_modules import get_whois_info, get_ip_address, get_dns_records, port_scan, find_subdomains
from generate_report import generate_html_report
from datetime import datetime

def log_output(data):
    with open("recon_log.txt", "a") as log_file:
        log_file.write(data + "\n")

def ask_user():
    print("🤖 What recon tasks would you like to run?")
    print("Options: whois, ip, dns, port, subdomains, all")
    return input("👉 Enter your choice (comma-separated): ").lower().split(',')

def main():
    domain = input("🌐 Enter target domain (e.g., example.com): ").strip()

    with open("recon_log.txt", "w") as clear_file:
        clear_file.write(f"=== Recon Started: {datetime.now()} ===\n")

    tasks = ask_user()

    if "whois" in tasks or "all" in tasks:
        log_output("\n🔍 WHOIS Info:")
        get_whois_info(domain)

    if "ip" in tasks or "all" in tasks:
        log_output("\n🌐 IP Address:")
        get_ip_address(domain)

    if "dns" in tasks or "all" in tasks:
        log_output("\n🧬 DNS Records:")
        get_dns_records(domain)

    if "port" in tasks or "all" in tasks:
        log_output("\n🛡️ Port Scan:")
        port_scan(domain)

    if "subdomains" in tasks or "all" in tasks:
        log_output("\n📡 Subdomains:")
        find_subdomains(domain)

    generate_html_report()
    print("\n✅ Recon complete. Report saved as 'report.html'.")

if __name__ == "__main__":
    main()
