import whois
import dns.resolver
import socket

# Function to get WHOIS info
def get_domain_info(domain):
    print("\n🔍 WHOIS Info:")
    try:
        info = whois.whois(domain)
        print(info)
    except Exception as e:
        print("Error in WHOIS:", e)

# Function to get DNS records
def get_dns_records(domain):
    print("\n🌐 DNS Records:")
    try:
        for record in ['A', 'MX', 'NS']:
            answers = dns.resolver.resolve(domain, record)
            print(f"{record} Records:")
            for rdata in answers:
                print(rdata.to_text())
    except Exception as e:
        print("DNS Error:", e)

# Function to get IP
def get_ip(domain):
    print("\n💡 IP Address:")
    try:
        ip = socket.gethostbyname(domain)
        print("IP Address:", ip)
    except Exception as e:
        print("IP Error:", e)

# Main
if __name__ == "__main__":
    domain = input("Enter domain (e.g., google.com): ").strip()
    get_domain_info(domain)
    get_dns_records(domain)
    get_ip(domain)
