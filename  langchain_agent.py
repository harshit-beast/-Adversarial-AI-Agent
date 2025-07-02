 # ------------------ WARNINGS CLEANUP ------------------ #
import warnings


# Suppress unwanted warnings
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=ImportWarning)

try:
    from urllib3.exceptions import NotOpenSSLWarning
    warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
except ImportError:
    pass

try:
    from langchain.utils import LangChainDeprecationWarning
    warnings.filterwarnings("ignore", category=LangChainDeprecationWarning)
except ImportError:
    pass

# ------------------ LANGCHAIN + TOOLS ------------------ #
from langchain.agents import initialize_agent, Tool
from langchain.agents.agent_types import AgentType
from langchain.llms import Ollama

import dns.resolver

# FIX: Proper import for WHOIS
try:
    import whois
    if not hasattr(whois, 'whois'):
        raise ImportError("⚠️ Wrong 'whois' module installed. Run: pip uninstall whois && pip install python-whois")
except ImportError as e:
    print(e)
    exit(1)

# ------------------ CLEAN DOMAIN ------------------ #
def clean_domain(domain):
    domain = domain.strip().split()[0]
    domain = domain.replace('@10.', '')
    return domain

# ------------------ DNS TOOL ------------------ #
def run_dns(domain):
    try:
        domain = clean_domain(domain)
        answers = dns.resolver.resolve(domain, 'A')
        return '\n'.join([str(rdata) for rdata in answers])
    except Exception as e:
        return f"DNS Error: {e}"

# ------------------ WHOIS TOOL ------------------ #
def run_whois(domain):
    try:
        domain = clean_domain(domain)
        info = whois.whois(domain)
        return str(info)
    except Exception as e:
        return f"WHOIS Error: {e}"

# ------------------ INIT OLLAMA ------------------ #
llm = Ollama(model="llama3")

tools = [
    Tool(name="DNS Lookup", func=run_dns, description="Resolve A records of a domain"),
    Tool(name="WHOIS Lookup", func=run_whois, description="Get WHOIS info of a domain")
]

# ------------------ AGENT ------------------ #
agent = initialize_agent(tools, llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION, verbose=True)

# ------------------ RUN ------------------ #
query = "Is the domain openai.com secure? Check DNS & WHOIS and tell vulnerabilities."
response = agent.invoke(query)
print("\n🧠 Final Output:\n", response)
