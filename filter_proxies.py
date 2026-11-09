#!/usr/bin/env python3
import argparse
import concurrent.futures
import os
import subprocess
import sys
import urllib.request

SOURCES = [
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
]

def check_proxy(proxy, timeout=4.0):
    proxy = proxy.strip()
    if not proxy or proxy.startswith("#"):
        return None
    if "://" not in proxy:
        proxy = "socks5://" + proxy

    # Strict SSL curl to verify authentic TLS without cert tampering / MITM
    cmd = ["curl", "-s", "--max-time", str(timeout), "--proxy", proxy, "https://browserleaks.com/ip"]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0 and len(res.stdout) > 200:
            return proxy
    except Exception:
        pass
    return None

def fetch_candidates():
    proxies = []
    for url in SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.88.1"})
            with urllib.request.urlopen(req, timeout=5) as r:
                for line in r.read().decode("utf-8", "ignore").splitlines()[:250]:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        proxies.append("socks5://" + line if "://" not in line else line)
        except Exception:
            continue
    return proxies

def main():
    parser = argparse.ArgumentParser(description="Find clean, working SOCKS5 proxies")
    parser.add_argument("-o", "--out", default="working-proxies.txt", help="output file")
    parser.add_argument("-n", "--limit", type=int, default=15, help="target number of proxies")
    parser.add_argument("-w", "--workers", type=int, default=50, help="threads")
    args = parser.parse_args()

    print(f"Fetching and testing candidate proxies...")
    candidates = fetch_candidates()
    if not candidates:
        print("No candidates found.")
        sys.exit(1)

    alive = []
    seen = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for res in pool.map(check_proxy, candidates):
            if res and res not in seen:
                seen.add(res)
                alive.append(res)
                print(f"  + {res}")
                if len(alive) >= args.limit:
                    break

    if alive:
        with open(args.out, "w") as f:
            f.write("\n".join(alive) + "\n")
        print(f"\nSaved {len(alive)} clean proxies to {args.out}")
    else:
        print("No working proxies found.")

if __name__ == "__main__":
    main()
