#!/usr/bin/env python3
import sys
import json
import socket
import argparse
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Configuration
# -----------------

WORDLIST = [
    "www", "api", "dev", "staging", "admin", "test", "app", "mail",
    "beta", "portal", "dashboard", "auth", "login", "docs", "cdn",
    "static", "media", "assets", "proxy", "vpn", "remote", "internal",
    "intranet", "corp", "secure", "ftp", "git", "jenkins", "jira",
    "confluence", "wiki", "status", "monitor", "grafana", "kibana",
    "elasticsearch", "redis", "db", "shop", "store", "pay", "billing",
    "support", "helpdesk", "crm", "erp", "mx", "ns1", "ns2", "smtp",
]

HTTP_TIMEOUT   = 3     # seconds per request
MAX_WORKERS    = 25    # concurrent threads
WILDCARD_PROBE = "nonexistent-xrecon-7z9q"  # random prefix for wildcard detection

INTERESTING_STATUSES = {200, 201, 301, 302, 403}



# Data model
# ----------------

@dataclass
class SubdomainResult:
    subdomain:      str
    url:            str
    status_code:    int
    content_length: int
    score:          int = 0  # 0=raw, 1=alive, 2=interesting



# Core functions
# -------------------

def generate_subdomains(domain: str) -> list[str]:
    """Return FQDN candidates from the internal wordlist."""
    return [f"{word}.{domain}" for word in WORDLIST]


def _resolve(hostname: str) -> Optional[str]:
    """DNS A-record lookup. Returns IP string or None."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def _http_probe(url: str) -> Optional[requests.Response]:
    """GET request with short timeout, ignoring TLS errors."""
    try:
        return requests.get(
            url,
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "SentryTools-Recon(/1.0)"},
        )
    except requests.RequestException:
        return None


def detect_wildcard(domain: str) -> Optional[tuple[str, int]]:
    """
    Detect wildcard DNS by probing a guaranteed-nonexistent subdomain.
    Returns (wildcard_ip, baseline_content_length) if wildcard is live, else None.
    The baseline content length is used downstream to filter false positives.
    """
    probe_host = f"{WILDCARD_PROBE}.{domain}"
    ip = _resolve(probe_host)
    if not ip:
        return None

    # Wildcard DNS resolves — capture baseline body length for filtering
    for scheme in ("https", "http"):
        resp = _http_probe(f"{scheme}://{probe_host}")
        if resp is not None:
            return (ip, len(resp.content))
    return (ip, 0)


def _probe_subdomain(subdomain: str) -> Optional[SubdomainResult]:
    """
    Resolve + HTTP probe a single subdomain.
    Tries HTTPS first, falls back to HTTP.
    Returns SubdomainResult on success, None if unreachable.
    """
    if not _resolve(subdomain):
        return None

    for scheme in ("https", "http"):
        resp = _http_probe(f"{scheme}://{subdomain}")
        if resp is not None:
            return SubdomainResult(
                subdomain=subdomain,
                url=f"{scheme}://{subdomain}",
                status_code=resp.status_code,
                content_length=len(resp.content),
            )
    return None


def check_alive(subdomains: list[str]) -> list[SubdomainResult]:
    """Concurrently probe all candidates. Returns alive results only."""
    alive = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_probe_subdomain, s): s for s in subdomains}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                alive.append(result)
    return alive


def filter_results(
    results: list[SubdomainResult],
    wildcard: Optional[tuple[str, int]],
) -> list[SubdomainResult]:
    """
    Multi-signal noise reduction:

    1. Wildcard filter   — drop responses whose content_length matches the
                           wildcard baseline (catches catch-all DNS records).
    2. Status filter     — keep only responses with actionable status codes.
    3. Scoring           — status 200 with non-baseline content_length → score 2
                           (interesting); other keepers → score 1 (alive).

    Returns filtered list sorted by score desc, then subdomain asc.
    """
    wildcard_len = wildcard[1] if wildcard else None
    SCORE_THRESHOLD = 50  # min byte delta from wildcard baseline to be "interesting"

    filtered = []
    for r in results:
        # 1. Wildcard suppression
        if wildcard_len is not None and r.content_length == wildcard_len:
            continue

        # 2. Status-code gating
        if r.status_code not in INTERESTING_STATUSES:
            continue

        # 3. Scoring
        is_unique_size = (
            wildcard_len is None
            or abs(r.content_length - wildcard_len) > SCORE_THRESHOLD
        )
        r.score = 2 if (r.status_code == 200 and is_unique_size) else 1
        filtered.append(r)

    filtered.sort(key=lambda x: (-x.score, x.subdomain))
    return filtered


def format_output(
    domain: str,
    alive: list[SubdomainResult],
    filtered: list[SubdomainResult],
    wildcard: Optional[tuple[str, int]],
) -> dict:
    """Assemble the final structured report."""
    return {
        "target": domain,
        "wildcard_detected": wildcard is not None,
        "wildcard_baseline_length": wildcard[1] if wildcard else None,
        "alive_subdomains": [
            {
                "subdomain": r.subdomain,
                "url": r.url,
                "status_code": r.status_code,
                "content_length": r.content_length,
            }
            for r in alive
        ],
        "filtered_results": [
            {
                "subdomain": r.subdomain,
                "url": r.url,
                "status_code": r.status_code,
                "content_length": r.content_length,
                "score": r.score,
                "interesting": r.score == 2,
            }
            for r in filtered
        ],
    }


# Entry point
# --------------

def main():
    parser = argparse.ArgumentParser(
        description="recon_pipeline — subdomain enumeration & HTTP recon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python recon_pipeline.py example.com",
    )
    parser.add_argument("domain", help="Target root domain (e.g. example.com)")
    args = parser.parse_args()
    domain = args.domain.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")
    domain = domain.split("/")[0]

    log = lambda msg: print(msg, file=sys.stderr)
    log("[*] SentryTools Recon Pipeline v1")
  
    log(f"[*] Target          : {domain}")

    log("[*] Wildcard check  : probing...")
    wildcard = detect_wildcard(domain)
    if wildcard:
        log(f"[!] Wildcard active : IP={wildcard[0]}, baseline_len={wildcard[1]}")
    else:
        log("[*] Wildcard check  : none detected")

    subdomains = generate_subdomains(domain)
    log(f"[*] Candidates      : {len(subdomains)}")

    log(f"[*] Probing         : {MAX_WORKERS} threads, timeout={HTTP_TIMEOUT}s")
    alive = check_alive(subdomains)
    log(f"[*] Alive           : {len(alive)}")

    filtered = filter_results(alive, wildcard)
    log(f"[*] Post-filter     : {len(filtered)}")

    output = format_output(domain, alive, filtered, wildcard)
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
