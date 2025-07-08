from datetime import datetime

def generate_summary(domain, ip, open_ports, subdomains, whois_data):
    summary = f"""
    🔍 Summary Report:
    - Target Domain: {domain}
    - IP Address: {ip}
    - Open Ports: {', '.join(str(p) for p in open_ports)}
    - Subdomains Found: {', '.join(subdomains)}
    - Domain Registrar: {whois_data.get('registrar')}
    - Expiration Date: {whois_data.get('expiration_date')}
    """
    return summary

def risk_analysis(open_ports, whois_data):
    risks = []
    risky_ports = {21, 23, 8080, 3306}
    exp_date = whois_data.get('expiration_date')

    if any(port in open_ports for port in risky_ports):
        risks.append("⚠️ High-risk ports open")
    else:
        risks.append("✅ Ports look safe")

    if exp_date and isinstance(exp_date, list):
        exp_date = exp_date[0]

    if exp_date and isinstance(exp_date, datetime):
        if exp_date < datetime.now().replace(year=datetime.now().year + 1):
            risks.append("🟡 WHOIS expiry within 1 year")
        else:
            risks.append("✅ WHOIS expiry is safe")
    else:
        risks.append("❓ Could not determine WHOIS expiry")

    return risks
