from utils.ai_summary import generate_summary, risk_analysis  # Make sure this module exists and is correct

def generate_html_report():
    try:
        with open("recon_log.txt", "r") as log_file:
            data = log_file.read()

        # Extract relevant parts for summary/risk functions
        # This is mock parsing — you can refine it based on your log format
        domain = ""
        ip_address = ""
        open_ports = []
        subdomains = []
        whois_info = {}

        for line in data.splitlines():
            if line.startswith("[WHOIS] Domain:"):
                domain = line.split(":")[1].strip()
            elif line.startswith("[IP]"):
                ip_address = line.split()[-1]
            elif "[Port tcp]" in line and "is open" in line:
                port = int(line.split()[2])
                open_ports.append(port)
            elif "[Subdomain] Found:" in line:
                sub = line.split(":")[1].split("->")[0].strip()
                subdomains.append(sub)
            elif "Registrar:" in line:
                whois_info["registrar"] = line.split(":")[1].strip()
            elif "Expiration Date:" in line:
                # Simplified parsing — assumes format: list of datetime
                from datetime import datetime
                try:
                    date_str = line.split("datetime.datetime(")[1].split(")")[0]
                    parts = list(map(int, date_str.split(",")))
                    whois_info["expiration_date"] = [datetime(*parts)]
                except:
                    pass

        # Generate summaries
        summary = generate_summary(domain, ip_address, open_ports, subdomains, whois_info)
        risks = risk_analysis(open_ports, whois_info)

        # Build HTML
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Recon Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    margin: 40px;
                }}
                h1 {{
                    color: #333;
                }}
                pre {{
                    background: #fff;
                    border: 1px solid #ddd;
                    padding: 20px;
                    border-radius: 5px;
                    white-space: pre-wrap;
                }}
                ul {{
                    background: #fff;
                    border: 1px solid #ddd;
                    padding: 20px;
                    border-radius: 5px;
                }}
            </style>
        </head>
        <body>
            <h1>Reconnaissance Report</h1>
            <pre>{data}</pre>
            <h2>🔍 Summary</h2>
            <pre>{summary}</pre>
            <h2>🔒 Risk Analysis</h2>
            <ul>
                {''.join(f'<li>{risk}</li>' for risk in risks)}
            </ul>
        </body>
        </html>
        """

        with open("report.html", "w") as report_file:
            report_file.write(html_content)

        print("[✔] HTML report generated successfully as 'report.html'")

    except FileNotFoundError:
        print("[✖] recon_log.txt not found! Run your recon first.")

generate_html_report()
