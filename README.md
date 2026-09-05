# Zero-Trust Local AI DNS Sentinel

![Status: Active](https://img.shields.io/badge/Status-Active-success)
![Platform: Windows 11](https://img.shields.io/badge/Platform-Windows_11-blue)
![AI Model: Llama 3.1 (8B)](https://img.shields.io/badge/AI-Llama_3.1-orange)
![Security: Air-Gapped](https://img.shields.io/badge/Security-Air--Gapped-red)
![License: MIT](https://img.shields.io/badge/License-MIT-blue)

**Author:** Rocky  
**Project Type:** Zero-Trust Network Architecture, AI Security Monitoring, OS Hardening  

## Executive Summary
The Zero-Trust Local AI DNS Sentinel is an air-gapped, locally hosted cybersecurity toolchain designed to autonomously analyze network traffic for malicious activity, telemetry trackers, and C2 servers. 

Most modern security tools rely on static blocklists or cloud-based threat intelligence. The problem with this approach is that sending your DNS logs to a cloud server compromises your privacy through telemetry collection. To solve this, this architecture uses a locally hosted Large Language Model (Llama 3.1) to heuristically analyze DNS queries intercepted by a local AdGuard Home instance. All logs are written to a volatile RAM disk to ensure zero forensic persistence on physical storage.

## System Architecture and Workflow

The system is compartmentalized into distinct stages to ensure maximum isolation and zero-trust execution:

1. **DNS Interception:** AdGuard Home routes all local machine DNS queries through a loopback resolver.
2. **Volatile Storage:** AdGuard query logs (querylog.json) are written exclusively to an R:\ drive partitioned in system RAM. Upon system power loss or reboot, all logs are mathematically destroyed.
3. **AI Heuristics:** A Python script extracts the domains and sends them to Llama 3.1 via the local loopback API (127.0.0.1:11434) for threat analysis.
4. **Native Alerting:** To bypass stripped or debloated Windows Action Centers, the script leverages native Windows C-library bindings (MessageBoxW) to force an "Always On Top" warning onto the desktop if a threat is detected.

## Core Features

| Feature | Description |
| :--- | :--- |
| **Volatile Logging** | DNS logs exist strictly in RAM. Upon reboot, the data is completely destroyed. |
| **Local LLM Analysis** | Leverages Llama 3.1 (8B) for heuristic analysis of domain strings without signature databases. |
| **Air-Gapped Operation** | All components communicate exclusively over local loopback (127.0.0.1). |
| **Debloat-Proof Alerts** | Bypasses the native Windows Action Center using ctypes to ensure alerts trigger even on heavily optimized OS configurations. |
| **Real-Time CLI Dashboard** | Built with the rich library, providing a live terminal UI that tracks scanned domains, threat scores, and inference latency in real-time. |
| **Automated Whitelisting** | Utilizes a localized JSON database (whitelist.json) to silently approve trusted domains and prevent inference loops on known-safe local traffic. |
| **Docker Containerization** | Fully containerized execution environment via docker-compose. Mounts the Windows RAM disk via secure read-only volume bindings while maintaining air-gapped network logic. |
| **Hardware Toggle** | Includes an administrative Batch script kill-switch to pause the AI loop, instantly freeing VRAM for competitive gaming. |

## Hardware Prerequisites
This system relies on local AI inference and volatile memory allocation. I engineered and tested it on the following high-performance specification:

* **GPU:** NVIDIA GeForce RTX 4070 Super (Requires adequate VRAM for local 8B parameter model execution)
* **CPU:** AMD Ryzen 7 7800X3D (Ensures background inference does not interrupt foreground scheduling)
* **RAM:** 64GB DDR5 (Provides ample overhead to dedicate blocks to the R:\ RAM disk)
* **OS:** Windows 11 (Hardened)

## OS Hardening Implementations
To ensure the sentinel script operates in a secure environment, the host OS was subjected to rigorous endpoint hardening aligned with strict operational security (OPSEC) standards:

* **Execution Policy:** Locked via PowerShell (Set-ExecutionPolicy AllSigned) to block all unauthorized and unsigned script execution.
* **LSA Protection:** Local Security Authority configured via Registry (RunAsPPL=1) as a Protected Process Light to block memory injection and credential dumping.
* **SMBv1 Disabled:** Legacy protocols completely stripped via Set-SmbServerConfiguration to prevent lateral movement attacks.
* **Encryption:** Active TPM 2.0 configuration with forced pre-boot BitLocker PIN authentication to thwart physical DMA (Direct Memory Access) attacks.

## Core Components and Code

### 1. The Sentinel Script (src/dns_ai_detector.py)
This script runs a continuous loop, rendering a live tracking table in the command prompt while firing native C-library alerts if a genuine threat bypasses the whitelist.

```python
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
OLLAMA_URL = "[http://127.0.0.1:11434/api/generate](http://127.0.0.1:11434/api/generate)"

console = Console()

if os.path.exists(WHITELIST_FILE):
    with open(WHITELIST_FILE, "r") as f:
        whitelist = set(json.load(f))
else:
    whitelist = set(["localhost", "127.0.0.1", "github.com"])
    with open(WHITELIST_FILE, "w") as f:
        json.dump(list(whitelist), f)

def generate_dashboard(scanned_count, flagged_domains, latency):
    table = Table(title="Zero-Trust DNS Sentinel [Live]", style="cyan", expand=True)
    table.add_column("Timestamp", style="dim", width=12)
    table.add_column("Domains Scanned", justify="right", style="blue")
    table.add_column("Flagged Threats", style="red")
    table.add_column("Inference Latency", justify="right", style="green")
    
    threat_text = ", ".join(flagged_domains) if flagged
