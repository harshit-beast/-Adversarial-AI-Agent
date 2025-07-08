from recon_tools.recon_modules import get_whois_info, get_ip_address, get_dns_records, port_scan, find_subdomains
from report_generator.generate_report import generate_html_report
from datetime import datetime

def log_output(data):
    with open("recon_log.txt", "a") as log_file:
        log_file.write(data + "\n")

# Basic keyword-based NLP interpretation
def interpret_input(user_input):
    user_input = user_input.lower()
    tasks = []

    if "all" in user_input or "everything" in user_input:
        return ["whois", "ip", "dns", "port", "subdomains"]
    if "whois" in user_input:
        tasks.append("whois")
    if "ip" in user_input or "address" in user_input:
        tasks.append("ip")
    if "dns" in user_input:
        tasks.append("dns")
    if "port" in user_input or "scan" in user_input:
        tasks.append("port")
    if "subdomain" in user_input:
        tasks.append("subdomains")

    return tasks

def main():
    domain = input("🌐 Enter target domain (e.g., example.com): ").strip()

    with open("recon_log.txt", "w") as clear_file:
        clear_file.write(f"=== Recon Started: {datetime.now()} ===\n")

    print("🗣️ Type your recon instruction (e.g., 'Check whois and port scan')")
    user_input = input("👉 Command: ")
    tasks = interpret_input(user_input)

    if not tasks:
        print("❌ Could not understand your request.")
        return

    if "whois" in tasks:
        log_output("\n🔍 WHOIS Info:")
        get_whois_info(domain)

    if "ip" in tasks:
        log_output("\n🌐 IP Address:")
        get_ip_address(domain)

    if "dns" in tasks:
        log_output("\n🧬 DNS Records:")
        get_dns_records(domain)

    if "port" in tasks:
        log_output("\n🛡️ Port Scan:")
        port_scan(domain)

    if "subdomains" in tasks:
        log_output("\n📡 Subdomains:")
        find_subdomains(domain)

    generate_html_report()
    print("\n✅ Recon complete. Report saved as 'report.html'.")

if __name__ == "__main__":
    main()
