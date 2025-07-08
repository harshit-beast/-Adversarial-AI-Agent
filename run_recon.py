import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import argparse
import re

from recon_tools.recon_modules import run_whois, run_dns, run_port_scan, run_subdomain_scan
from report_generator import generate_report
from exploit_tools.access_simulation import find_admin_panels, simulate_phishing_risk
from exploit_tools.access_simulation import simulate_weak_login_attempts, simulate_data_exfiltration, simulate_ransomware_activity
from exploit_tools.privilege_evasion import simulate_privilege_escalation, simulate_evasion
from agent_brain import generate_response, is_ollama_running, react_to_llm_advice
from utils.attack_graph import generate_attack_graph


def main():
    parser = argparse.ArgumentParser(description="AI Recon Agent - Day 29")
    parser.add_argument('--target', required=True, help='Target domain or IP address')
    parser.add_argument('--output', required=False, help='Output HTML filename (default: report.html)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output (progress messages)')

    args = parser.parse_args()
    target = args.target
    verbose = args.verbose
    output_file = args.output if args.output else "report.html"

    report_data = {}

    if verbose:
        print(f"[+] Starting recon on: {target}")

    # DNS
    report_data['DNS Lookup'] = run_dns(target)
    if verbose:
        print("[+] DNS lookup complete")

    # WHOIS
    whois_result = run_whois(target)
    report_data['WHOIS Lookup'] = whois_result
    if verbose:
        print("[+] WHOIS lookup complete")

    # Port Scan
    report_data['Port Scan'] = run_port_scan(target)
    if verbose:
        print("[+] Port scanning complete")

    # Subdomain Enumeration
    report_data['Subdomain Enumeration'] = run_subdomain_scan(target)
    if verbose:
        print("[+] Subdomain enumeration complete")

    # Extract emails from WHOIS
    emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", whois_result)

    # Admin Panel Detection
    admin_panels = find_admin_panels(target)
    report_data['Admin Panel Detection'] = "\n".join(admin_panels) if admin_panels else "No admin panels found."

    # Phishing Email Simulation
    risky_emails = simulate_phishing_risk(emails)
    report_data['Phishing Risk Emails'] = "\n".join(risky_emails) if risky_emails else "No risky emails detected."

    # Weak login attempts
    weak_login_results = simulate_weak_login_attempts(target)
    report_data['Weak Login Attempts (Simulated)'] = weak_login_results
    if verbose:
        print("[+] Weak login simulation complete")

    # Privilege Escalation
    report_data['Privilege Escalation'] = simulate_privilege_escalation(target)
    if verbose:
        print("[+] Privilege Escalation simulation complete")

    # Evasion
    report_data['Evasion Techniques'] = simulate_evasion()
    if verbose:
        print("[+] Evasion simulation complete")

    # Data Exfiltration
    report_data['Data Exfiltration Simulation'] = simulate_data_exfiltration(target)
    if verbose:
        print("[+] Data exfiltration simulation complete")

    # Ransomware
    report_data['Ransomware Simulation'] = simulate_ransomware_activity(target)
    if verbose:
        print("[+] Ransomware simulation complete")

    # ---------- LLM Integration ---------
    if is_ollama_running():
        full_recon_text = ""
        for section, content in report_data.items():
            full_recon_text += f"[{section}]\n{content}\n\n"

        prompt = f"""
You are a cybersecurity analyst.

Here is the reconnaissance and simulated attack data collected on a target:

{full_recon_text}

Analyze this and provide:
- Potential vulnerabilities found
- Suggested next actions
- Any red flags or dangerous patterns observed
"""
        print("[+] Sending recon summary to LLM for analysis...")
        llm_response = generate_response(prompt)
        report_data["LLM Summary & Recommendations"] = llm_response
        print("[+] LLM analysis complete.")

        # 🌐 ATTACK GRAPH GENERATION
        attack_graph = generate_attack_graph(llm_response)
        report_data["🕸️ Simulated Attack Graph"] = "\n".join(attack_graph)

        react_to_llm_advice(llm_response, target, verbose)
    else:
        print("❌ Ollama is not running. Skipping LLM summary.")

    # ✅ Final Report Generation
    generate_report(target, report_data, output_file)

    if verbose:
        print(f"[+] Recon finished. Report saved as {output_file}")


if __name__ == "__main__":
    main()
