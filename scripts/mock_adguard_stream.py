import time
import random

# Generates a local mock log for testing without a RAM disk
LOG_FILE = "querylog.json"

DOMAINS = [
    "github.com",
    "google.com",
    "telemetry.microsoft.com",
    "malware-c2.hacker.net",
    "api.steampowered.com",
    "track.amazon-adsystem.com",
    "cloudflare.com",
    "xboxlive.com"
]

print(f"📡 Starting mock AdGuard DNS stream to {LOG_FILE}...")
print("Press Ctrl+C to stop.")

try:
    while True:
        domain = random.choice(DOMAINS)
        # Formatted to match AdGuard's JSON structure expected by the Sentinel
        mock_entry = f'{{"QH":"{domain}"}}\n'
        
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(mock_entry)
        
        print(f"[+] Mock query logged: {domain}")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n🛑 Stopped mock stream.")
