import os
import re
import requests
import ctypes

LOG_FILE = r"R:\querylog.json"
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

if not os.path.exists(LOG_FILE):
    exit()

domains = set()
with open(LOG_FILE, "r", encoding="utf-8") as file:
    for line in file.readlines()[-150:]:
        match = re.search(r'"QH":"([^"]+)"', line)
        if match:
            domains.add(match.group(1))

if not domains:
    exit()

prompt_text = (
    "You are a network privacy assistant. "
    "Review these requested DNS domains and flag any that look like advertising networks, "
    "telemetry trackers, or suspicious data collection sites. "
    "Reply ONLY with the flagged domains separated by commas. "
    "If all domains look like normal websites, reply EXACTLY with the word 'CLEAN'. "
    f"Domains: {', '.join(domains)}"
)

payload = {"model": "llama3.1", "prompt": prompt_text, "stream": False}

try:
    response = requests.post(OLLAMA_URL, json=payload, timeout=45).json()
    analysis = response.get("response", "").strip()

    if "CLEAN" not in analysis.upper() and analysis:
        # Native Windows Message Box (Bypasses Debloated Notification Center)
        # 0x40000 = Always on top | 0x30 = Warning Icon
        ctypes.windll.user32.MessageBoxW(0, analysis, "AI DNS Sentinel: Threat Detected", 0x40000 | 0x30)
except Exception as e:
    pass
