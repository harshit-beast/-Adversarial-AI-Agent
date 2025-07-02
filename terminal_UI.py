import subprocess
import os

print("🔐 AI Recon Agent - Terminal Interface")
print("----------------------------------------")

# Step 1: Enter Domain
domain = input("🌐 Enter a domain (e.g., openai.com): ").strip()

# Step 2: Choose Recon Type
print("\nChoose an action:")
print("1. Full Recon & LLM Summary")
print("2. LangGraph Query (e.g., 'check whois', 'check ssl')")
choice = input("Enter choice (1/2): ").strip()

# Base directory
base_dir = os.path.dirname(os.path.abspath(__file__))

if choice == "1":
    print("\n🕵️ Running full recon using run_recon.py...")
    cmd = f'python3 "{os.path.join(base_dir, "run_recon.py")}" --target "{domain}" --verbose'

    subprocess.run(cmd, shell=True)

elif choice == "2":
    action = input("🧠 Enter your query (e.g., check whois / check ssl): ").strip().lower()

    # ✅ Direct Vulnerability Scan
    if "vuln" in action or "cve" in action or "exploit" in action:
        print("\n⚠️ Launching direct vulnerability scan with Nuclei...")
        from user_query_agent import run_vulnerability_scan
        result = run_vulnerability_scan(domain)
        print(result)

        from report_generator import generate_report
        report_data = {
            "Tool": "Vulnerability Scanner",
            "Target": domain,
            "Result": result
        }
        report_name = f"vulnerability_scan_{domain.replace('.', '_')}.html"
        generate_report(report_name, report_data)
        print(f"\n✅ Vulnerability scan report saved: {report_name}")
        exit(0)

    # ✅ Smart Query Conversion
    if "whois" in action:
        query = f"Check WHOIS info of {domain}"
    elif "dns" in action:
        query = f"Check DNS records of {domain}"
    elif "ssl" in action:
        query = f"Check SSL certificate of {domain}"
    elif "port" in action:
        query = f"Scan ports on {domain}"
    elif "subdomain" in action:
        query = f"Find subdomains of {domain}"
    elif "admin" in action:
        query = f"Look for admin panels on {domain}"
    elif "geo" in action or "location" in action:
        query = f"Get IP geolocation of {domain}"
    elif "reverse" in action:
        query = f"Reverse DNS lookup of {domain}"
    elif "header" in action:
        query = f"Check HTTP headers of {domain}"
    elif "tech" in action or "stack" in action:
        query = f"Detect technology stack of {domain}"
    else:
        query = f"{action} for {domain}"

    output_file = os.path.join(base_dir, f"report_{domain.replace('.', '_')}.html")
    cmd = f"python3 {os.path.join(base_dir, 'day29_user_query_agent.py')} --query \"{query}\" --output \"{output_file}\""
    subprocess.run(cmd, shell=True)

    if os.path.exists(output_file):
        print(f"\n✅ Report generated: {output_file}")
        open_cmd = f"open \"{output_file}\"" if os.name != "nt" else f"start {output_file}"
        subprocess.run(open_cmd, shell=True)
    else:
        print("❌ Report generation failed or file not found.")

else:
    print("❌ Invalid choice.")


