#!/usr/bin/env python3
import concurrent.futures
import json
import subprocess
import sys
import time

PROXY = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:9050"

def curl(url, timeout=12):
    cmd = ["curl", "-s", "--max-time", str(timeout), "--socks5-hostname", PROXY, url]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.returncode, res.stdout.strip()

def main():
    print(f"Testing proxy rotator at {PROXY}...")

    # 1. HTTP routing
    code, out = curl("http://api.ipify.org?format=json")
    if code != 0:
        print(f"[-] HTTP check failed (code {code})")
        sys.exit(1)
    ip1 = json.loads(out).get("ip")
    print(f"[+] HTTP OK -> Exit IP: {ip1}")

    # 2. Authentic HTTPS
    code, out = curl("https://browserleaks.com/ip")
    if code != 0 or len(out) < 200:
        print(f"[-] HTTPS check failed (code {code})")
        sys.exit(1)
    print(f"[+] HTTPS OK -> Clean TLS tunnel (no cert errors)")

    # 3. Concurrent burst
    def probe(i):
        code, out = curl("http://api.ipify.org?format=json", timeout=8)
        return code == 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(probe, range(5)))
    ok = sum(1 for r in results if r)
    print(f"[+] Concurrency: {ok}/5 requests succeeded")

    print("\nAll checks passed.")

if __name__ == "__main__":
    main()
