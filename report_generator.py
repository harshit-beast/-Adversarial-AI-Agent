def generate_report(target, report_data, output_file):
    with open(output_file, "w") as f:
        f.write(f"""<html>
<head>
  <title>Recon Report for {target}</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      background: #f8f9fa;
      margin: 0;
      padding: 20px;
    }}
    h1 {{
      background: #343a40;
      color: white;
      padding: 15px;
      text-align: center;
    }}
    h2 {{
      background: #007bff;
      color: white;
      padding: 10px;
      border-radius: 5px;
    }}
    pre {{
      background: #ffffff;
      border: 1px solid #ced4da;
      padding: 10px;
      border-radius: 5px;
      overflow-x: auto;
    }}
    .risk-low {{ color: green; }}
    .risk-medium {{ color: orange; }}
    .risk-high {{ color: red; }}
    .risk-critical {{ color: darkred; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>Recon Report for {target}</h1>
""")

        for section, data in report_data.items():
            f.write(f"<h2>{section}</h2>\n<pre>{data}</pre>\n")

        # Risk analysis
        risk_score = 0
        if "Subdomain Enumeration" in report_data and report_data["Subdomain Enumeration"]:
            risk_score += 1
        if "Port Scan" in report_data and any(str(port) in report_data["Port Scan"] for port in ["22", "21", "23", "3389"]):
            risk_score += 1
        if "WHOIS" in report_data and "Registrar" not in report_data["WHOIS"]:
            risk_score += 1

        risk_level = {
            0: "Low",
            1: "Medium",
            2: "High",
            3: "Critical"
        }.get(risk_score, "Unknown")

        css_class = f"risk-{risk_level.lower()}" if risk_level else ""

        f.write(f"""
  <h2>Risk Analysis</h2>
  <p><strong>Risk Score:</strong> {risk_score}/3</p>
  <p class="{css_class}"><strong>Risk Level:</strong> {risk_level}</p>
</body>
</html>""")
