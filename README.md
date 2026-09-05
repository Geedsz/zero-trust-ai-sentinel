# zero-trust-ai-sentinel
An air-gapped, local AI network sentinel that autonomously analyzes DNS query logs for malware, C2 servers, and trackers using Llama 3.1.
zero-trust-ai-sentinel/
├── .github/
│   └── workflows/          # (Optional) For GitHub Pages automated deployment
├── src/
│   └── dns_ai_detector.py  # The core Python ctypes/Ollama script
├── scripts/
│   └── Toggle_Sentinel.bat # The Task Scheduler gaming kill-switch
├── docs/
│   ├── architecture.md     # Deep dive into the RAM disk and local loopback
│   └── security-hardening.md # Details on registry tweaks and execution policies
└── README.md               # The master presentation document
