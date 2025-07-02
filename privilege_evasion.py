import os

def simulate_privilege_escalation(target):
    # Simulated list of suspicious files
    simulated_files = [
        "config.php", "admin.env", "db_backup.sql", "root_access.txt"
    ]
    found = [f for f in simulated_files if any(x in f.lower() for x in ['admin', 'root', 'config', 'password'])]
    result = "Simulated sensitive files:\n" + "\n".join(found)
    return result

def simulate_evasion():
    techniques = [
        "Renamed nmap to notepad.exe",
        "Base64-encoded payload scripts",
        "Used comments and junk code to obfuscate",
        "Accessed files using hidden paths (e.g. /.hidden/config)"
    ]
    result = "Simulated evasion techniques:\n" + "\n".join(techniques)
    return result
