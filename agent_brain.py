# agent_brain.py

import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "llama3"  # or use 'mistral', 'codellama', etc.

def generate_response(prompt, model=DEFAULT_MODEL):
    """
    Sends a prompt to the local Ollama model and returns the generated response.
    """
    headers = {"Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()["message"]["content"]
    except requests.exceptions.RequestException as e:
        return f"Error contacting Ollama: {e}"
def react_to_llm_advice(llm_response, target, verbose=False):
    if "port 22" in llm_response.lower() or "ssh" in llm_response.lower():
        if verbose: print("[🤖] LLM detected SSH risk — simulating brute-force attack")
        print("⚠️ Simulated brute-force login on SSH (port 22)")

    if "admin panel" in llm_response.lower():
        if verbose: print("[🤖] LLM mentioned admin panel — attempting credential spray")
        print("⚠️ Simulated admin panel login attempt at /admin")

    if "phishing" in llm_response.lower() or "risky email" in llm_response.lower():
        if verbose: print("[🤖] Phishing vector identified — crafting social engineering email")
        print("⚠️ Simulated phishing email campaign on target addresses")

    if "exfiltration" in llm_response.lower():
        if verbose: print("[🤖] LLM advised data exfiltration — simulating")
        print("⚠️ Simulated data exfiltration attempt")

    if "ransomware" in llm_response.lower():
        if verbose: print("[🤖] LLM suggested ransomware stage — initiating simulation")
        print("⚠️ Simulated ransomware payload deployment")

    print("✅ LLM advice processed and corresponding actions simulated.")


def is_ollama_running():
    """
    Checks whether Ollama is running locally.
    """
    try:
        r = requests.get("http://localhost:11434")
        return r.status_code == 200
    except:
        return False

