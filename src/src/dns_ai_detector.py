import os
import re
import json
import time
import requests
import ctypes
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.panel import Panel

LOG_FILE = r"R:\querylog.json"
WHITELIST_FILE = "whitelist.json"
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

console = Console()

if os.path.exists(WHITELIST_FILE):
    with open(WHITELIST_FILE, "r") as f:
        whitelist = set(json.load(f))
else:
    whitelist = set(["localhost", "127.0.0.1", "github.com"])
    with open(WHITELIST_FILE, "w") as f:
        json.dump(list(whitelist), f)

def generate_dashboard(scanned_count, flagged_domains, latency):
    table = Table(title="🛡️ Zero-Trust DNS Sentinel [Live]", style="cyan", expand=True)
    table.add_column("Timestamp", style="dim", width=12)
    table.add_column("Domains Scanned", justify="right", style="blue")
    table.add_column("Flagged Threats", style="red")
    table.add_column("Inference Latency", justify="right", style="green")
    
    threat_text = ", ".join(flagged_domains) if flagged_domains else "None (CLEAN)"
    
    table.add_row(
        time.strftime("%H:%M:%S"),
        str(scanned_count),
        threat_text,
        f"{latency:.2f}s"
    )
    return Panel(table, border_style="green")

def run_sentinel():
    if not os.path.exists(LOG_FILE):
        return 0, [], 0.0

    domains = set()
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file.readlines()[-150:]:
            match = re.search(r'"QH":"([^"]+)"', line)
            if match:
                domain = match.group(1)
                if domain not in whitelist:
                    domains.add(domain)

    if not domains:
        return 0, [], 0.0

    prompt_text = (
        "You are a network privacy assistant. "
        "Review these requested DNS domains and flag any that look like advertising networks, "
        "telemetry trackers, or suspicious data collection sites. "
        "Reply ONLY with the flagged domains separated by commas. "
        "If all domains look like normal websites, reply EXACTLY with the word 'CLEAN'. "
        f"Domains: {', '.join(domains)}"
    )

    payload = {"model": "llama3.1", "prompt": prompt_text, "stream": False}
    
    start_time = time.time()
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=45).json()
        analysis = response.get("response", "").strip()
        latency = time.time() - start_time

        flagged = []
        if "CLEAN" not in analysis.upper() and analysis:
            flagged = [d.strip() for d in analysis.split(",") if d.strip()]
            ctypes.windll.user32.MessageBoxW(0, f"Threats Detected:\n{analysis}", "AI DNS Sentinel", 0x40000 | 0x30)
            
        return len(domains), flagged, latency
    except Exception:
        return len(domains), ["Ollama Connection Error"], time.time() - start_time

with Live(generate_dashboard(0, [], 0.0), refresh_per_second=1) as live:
    while True:
        scanned, flags, lat = run_sentinel()
        live.update(generate_dashboard(scanned, flags, lat))
        time.sleep(10)
