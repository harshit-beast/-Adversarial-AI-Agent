import requests
import random
import time


def simulate_weak_login_attempts(target):
    if not target.startswith("http"):
        target = "http://" + target

    login_paths = ["/admin", "/login", "/administrator"]
    weak_creds = [("admin", "admin"), ("admin", "123456"), ("root", "toor")]

    results = []

    for path in login_paths:
        login_url = target + path
        for username, password in weak_creds:
            # Note: We don't actually log in, we simulate as if we tried
            results.append(f"Tried {username}:{password} at {login_url} [SIMULATED]")
    
    return "\n".join(results)

def find_admin_panels(domain):
    common_paths = ["/admin", "/login", "/admin/login", "/cpanel", "/dashboard"]
    found = []

    for path in common_paths:
        url = f"http://{domain}{path}"
        try:
            res = requests.get(url, timeout=3)
            if res.status_code == 200:
                found.append(url)
        except:
            continue

    return found

def simulate_phishing_risk(emails):
    risk_keywords = ["admin", "support", "help", "info"]
    flagged = [email for email in emails if any(k in email.lower() for k in risk_keywords)]
    return flagged

def simulate_privilege_escalation(target):
    simulated_findings = []

    # Simulate if sensitive files are exposed
    sensitive_paths = ["/.env", "/config.php", "/backup.zip", "/db.sql"]

    if not target.startswith("http"):
        target = "http://" + target

    for path in sensitive_paths:
        try:
            url = target + path
            res = requests.get(url, timeout=3)
            if res.status_code == 200:
                simulated_findings.append(f"⚠️ Found possible sensitive file: {url}")
        except:
            continue

    if not simulated_findings:
        simulated_findings.append("No sensitive files or privilege escalation vectors found.")

    return "\n".join(simulated_findings)

def simulate_evasion():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "curl/7.68.0",
        "Wget/1.20.3 (linux-gnu)",
        "ReconAgent/1.0"
    ]

    fake_honeypots = ["/secret-admin", "/hidden-login", "/dont-click-here"]

    actions = []

    # Randomize user-agent
    chosen_agent = random.choice(user_agents)
    actions.append(f"User-Agent spoofed as: {chosen_agent}")

    # Simulated delay
    delay = random.randint(1, 3)
    time.sleep(delay)
    actions.append(f"Added delay of {delay} seconds to avoid detection.")

    # Honeypot skip logic
    actions.append(f"Skipped suspicious honeypot URLs: {', '.join(fake_honeypots)}")

    return "\n".join(actions)


def simulate_data_exfiltration(target):
    fake_files = ["credentials.txt", "employee_data.csv", "source_code.zip"]
    simulated_server = "http://attacker-server.com/upload"

    actions = []
    for file in fake_files:
        actions.append(f"Exfiltrated {file} → {simulated_server}/{file} [SIMULATED]")

    return "\n".join(actions)
def simulate_ransomware_activity(target):
    dummy_files = [
        "/home/user/documents/resume.docx",
        "/var/www/html/index.html",
        "/etc/passwd",
        "/project/database.db"
    ]

    actions = []

    for file in dummy_files:
        actions.append(f"Encrypted {file} with AES-256 [SIMULATED]")

    actions.append("\n🚨 RANSOM NOTE 🚨")
    actions.append("Your files have been encrypted.")
    actions.append("To recover them, send 1 BTC to wallet: 1FAKEransomWalletBTCaddress")
    actions.append("Contact: attacker@example.com")

    return "\n".join(actions)
