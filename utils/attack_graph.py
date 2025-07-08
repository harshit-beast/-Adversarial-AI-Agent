def generate_attack_graph(llm_advice):
    graph_steps = []

    if "SSH" in llm_advice:
        graph_steps.append("1. 🔍 Open SSH Port Identified")
        graph_steps.append("2. 🚪 Brute Force Attempt on SSH")

    if "admin panel" in llm_advice:
        graph_steps.append("3. 🧠 Admin Panel Detected")
        graph_steps.append("4. 🎯 Credential Spray Simulation")

    if "phishing" in llm_advice.lower():
        graph_steps.append("5. 🎣 Phishing Risk Identified")
        graph_steps.append("6. 📧 Simulated Phishing Campaign")

    if "data exfiltration" in llm_advice.lower():
        graph_steps.append("7. 📤 Data Exfiltration Vector Found")

    if "ransomware" in llm_advice.lower():
        graph_steps.append("8. 💣 Ransomware Payload Delivered")

    if not graph_steps:
        graph_steps.append("✅ No active attack paths detected.")

    return graph_steps
