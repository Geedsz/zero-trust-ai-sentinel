# Zero-Trust Local AI DNS Sentinel

![Status: Active](https://img.shields.io/badge/Status-Active-success)
![Platform: Windows 11](https://img.shields.io/badge/Platform-Windows_11-blue)
![AI Model: Llama 3.1 (8B)](https://img.shields.io/badge/AI-Llama_3.1-orange)
![Security: Air-Gapped](https://img.shields.io/badge/Security-Air--Gapped-red)
![License: MIT](https://img.shields.io/badge/License-MIT-blue)

**Author:** Rocky  
**Project Type:** Zero-Trust Network Architecture, AI Security Monitoring, OS Hardening  

##  Executive Summary
The **Zero-Trust Local AI DNS Sentinel** is an air-gapped, locally hosted cybersecurity toolchain designed to autonomously analyze network traffic for malicious activity, telemetry trackers, and Command & Control (C2) servers. 

Rather than relying on static blocklists or cloud-based threat intelligence—which compromise privacy via telemetry leaks—this architecture uses a locally hosted Large Language Model (Llama 3.1) to heuristically analyze DNS queries intercepted by a local AdGuard Home instance. All logs are written to a volatile RAM disk to ensure zero forensic persistence on physical storage.

##  System Architecture & Workflow

The system is compartmentalized into four distinct stages to ensure maximum isolation and zero-trust execution:

1. **DNS Interception (AdGuard Home):** Routes all local machine DNS queries through a loopback resolver.
2. **Volatile Storage (RAM Disk):** AdGuard query logs (`querylog.json`) are written exclusively to an `R:\` drive partitioned in system RAM. Upon system power loss or reboot, all logs are mathematically destroyed.
3. **AI Heuristics (Ollama + Llama 3.1):** A Python script runs as a hidden, highly privileged Windows scheduled task every 5 minutes. It extracts the domains and sends them to Llama 3.1 via the local loopback API (`127.0.0.1:11434`) for threat analysis.
4. **Native Alerting (`ctypes`):** To bypass stripped or "debloated" Windows Action Centers, the script leverages native Windows C-library bindings (`MessageBoxW`) to force an "Always On Top" warning onto the desktop if a threat is detected.

##  Hardware Prerequisites
This system relies on local AI inference and volatile memory allocation. It was engineered and tested on the following high-performance specification:
* **GPU:** NVIDIA GeForce RTX 4070 Super (Requires adequate VRAM for local 8B parameter model execution)
* **CPU:** AMD Ryzen 7 7800X3D (Ensures background inference does not interrupt foreground scheduling)
* **RAM:** 64GB DDR5 (Provides ample overhead to dedicate blocks to the `R:\` RAM disk)
* **OS:** Windows 11 (Hardened)

##  Military-Grade OS Hardening Implementations
To ensure the sentinel script operates in a secure environment, the host OS was subjected to rigorous endpoint hardening aligned with strict operational security (OPSEC) standards:

* **Execution Policy:** Locked via PowerShell (`Set-ExecutionPolicy AllSigned -Scope LocalMachine`) to block all unauthorized and unsigned script execution.
* **LSA Protection:** Local Security Authority configured via Registry (`RunAsPPL=1`) as a Protected Process Light to block memory injection and credential dumping.
* **SMBv1 Disabled:** Legacy protocols completely stripped via `Set-SmbServerConfiguration` to prevent lateral movement attacks.
* **Data Execution Prevention (DEP):** Forced on globally via system registry policies to prevent buffer overflow execution.
* **Encryption:** Active TPM 2.0 configuration with forced pre-boot BitLocker PIN authentication to thwart physical DMA (Direct Memory Access) attacks.

##  Core Components & Code

### 1. The Sentinel Script (`src/dns_ai_detector.py`)
This script operates completely invisibly, extracting the last 150 DNS queries from the volatile RAM disk and executing the Llama 3.1 safety prompt. 

```python
import os
import re
import requests
import ctypes

LOG_FILE = r"R:\querylog.json"
OLLAMA_URL = "[http://127.0.0.1:11434/api/generate](http://127.0.0.1:11434/api/generate)"

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
