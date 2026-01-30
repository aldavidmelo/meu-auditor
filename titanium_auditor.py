import os
import time
import csv
import concurrent.futures
import dns.resolver # pip install dnspython
from curl_cffi import requests as browser_requests

# ==============================================================================
# [SYSTEM CONFIGURATION]
# ==============================================================================

# AJUSTE DE CAMINHO: Use r"" para evitar erros de barra no Windows
FILE = os.path.join(os.path.dirname(__file__), "proxies.txt")
OUTPUT_FILE = os.path.join(os.path.dirname(FILE), "titanium_audit_report.csv")

THREADS = 30            
TIMEOUT_VAL = 20        
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"

# [THREAT INTELLIGENCE DATABASES]
DNSBL_PROVIDERS = [
    "zen.spamhaus.org",       
    "b.barracudacentral.org", 
    "bl.spamcop.net",         
    "dnsbl.sorbs.net"         
]

# Keywords for Semantic ISP Analysis (Source: Risk Assessment Framework)
RISK_KEYWORDS = {
    "CRITICAL": [
        "hosting", "datacenter", "cloud", "vps", "server", "m247", "digitalocean", 
        "hetzner", "ovh", "amazon", "aws", "google", "microsoft", "azure", "alibaba"
    ],
    "HIGH": [
        "student", "university", "education", "school", "library", "dorm", 
        "residence hall", "academic", "campus", "solution", "network", "telecom"
    ],
    "MODERATE": [
        "business", "corporate", "systems", "services", "limited", "communication"
    ]
}

# ==============================================================================
# [MODULE] UTILITIES
# ==============================================================================

def print_log(level, message):
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] [{level:<8}] {message}")

def parse_proxy_struct(line):
    line = line.strip()
    if not line: return None
    parts = line.split(":")
    data = {"original": line, "ip": "", "port": "", "user": None, "pass": None, "valid": False}
    
    if len(parts) == 2:
        data.update({"ip": parts[0], "port": parts[1], "valid": True})
    elif len(parts) == 4:
        data.update({"ip": parts[0], "port": parts[1], "user": parts[2], "pass": parts[3], "valid": True})
    return data

def build_conn_str(data, protocol="http"):
    if data["user"] and data["pass"]:
        return f"{protocol}://{data['user']}:{data['pass']}@{data['ip']}:{data['port']}"
    return f"{protocol}://{data['ip']}:{data['port']}"

def reverse_ip(ip):
    try:
        return ".".join(reversed(ip.split('.')))
    except:
        return None

# ==============================================================================
# [MODULE] INTELLIGENCE GATHERING
# ==============================================================================

def check_dnsbl(ip):
    rev_ip = reverse_ip(ip)
    if not rev_ip: return 0, []
    
    flags = []
    penalty = 0
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.5 
    resolver.lifetime = 1.5

    for bl in DNSBL_PROVIDERS:
        try:
            resolver.resolve(f"{rev_ip}.{bl}", "A")
            flags.append(bl)
            penalty += 25 
        except:
            continue
    return penalty, flags

def analyze_isp_risk(isp_name):
    isp_lower = str(isp_name).lower()
    score = 0
    tags = []

    for kw in RISK_KEYWORDS["CRITICAL"]:
        if kw in isp_lower:
            score += 90
            tags.append("DATACENTER_INFRA")
            break 

    for kw in RISK_KEYWORDS["HIGH"]:
        if kw in isp_lower:
            score += 50
            tags.append(f"HIGH_RISK_KEYWORD({kw.upper()})")

    if score == 0: 
        for kw in RISK_KEYWORDS["MODERATE"]:
            if kw in isp_lower:
                score += 20
                tags.append("BUSINESS_LINE")

    return score, tags

def get_deep_intel(ip):
    try:
        # Using public API for audit (Local IP -> API, no proxy needed)
        fields = "status,message,countryCode,regionName,isp,org,as,mobile,proxy,hosting"
        url = f"http://ip-api.com/json/{ip}?fields={fields}"
        r = browser_requests.get(url, timeout=10, impersonate="chrome110")
        return r.json()
    except:
        return {"status": "fail"}

# ==============================================================================
# [MODULE] CORE LOGIC
# ==============================================================================

def audit_endpoint(raw_line):
    proxy = parse_proxy_struct(raw_line)
    
    report = {
        "ip": "N/A",
        "status": "DEAD",
        "risk_score": 0,
        "risk_level": "UNKNOWN",
        "infra_type": "UNKNOWN",
        "isp": "N/A",
        "country": "N/A",
        "latency": 0,
        "protocol": "N/A",
        "tiktok_status": "UNTESTED",
        "blacklists": "",
        "notes": "",
        "proxy_str": raw_line
    }

    if not proxy or not proxy["valid"]:
        report["notes"] = "INVALID_FORMAT"
        return report

    report["ip"] = proxy["ip"]

    # --- STEP 1: CONNECTIVITY TEST ---
    active_proto = None
    
    for proto in ["http", "socks5"]:
        try:
            p_url = build_conn_str(proxy, proto)
            st = time.time()
            # Using impersonate to check actual proxy viability
            r = browser_requests.get("http://httpbin.org/ip", proxies={"http": p_url, "https": p_url}, timeout=15, impersonate="chrome110")
            if r.status_code == 200:
                active_proto = proto
                report["latency"] = round((time.time() - st) * 1000)
                break
        except:
            continue

    if active_proto:
        report["status"] = "ALIVE"
        report["protocol"] = active_proto
    else:
        report["status"] = "DEAD"
        report["notes"] = "CONNECTION_FAIL_BUT_AUDITING"
        # CRITICAL CHANGE: We do NOT return here. We proceed to gather intel.

    # --- STEP 2: INTELLIGENCE GATHERING (FORENSIC) ---
    intel = get_deep_intel(proxy["ip"])
    
    if intel.get("status") != "success":
        report["notes"] += "|API_ERROR"
    else:
        report["country"] = intel.get("countryCode", "XX")
        report["isp"] = intel.get("isp", "Unknown ISP")
        
        risk_accumulator = 0
        audit_log = []

        # A. Infrastructure Analysis
        if intel.get("mobile"):
            report["infra_type"] = "MOBILE (4G/5G)"
            risk_accumulator = 0 
            audit_log.append("TRUSTED_CARRIER")
        elif intel.get("hosting") or intel.get("proxy"):
            report["infra_type"] = "DATACENTER/VPN"
            risk_accumulator += 90 
            audit_log.append("HOSTING_DETECTED")
        else:
            report["infra_type"] = "RESIDENTIAL/ISP"

        # B. Semantic ISP Analysis
        isp_score, isp_tags = analyze_isp_risk(report["isp"])
        risk_accumulator += isp_score
        audit_log.extend(isp_tags)

        # C. Blacklist Check (DNSBL)
        bl_score, bl_list = check_dnsbl(proxy["ip"])
        risk_accumulator += bl_score
        if bl_list:
            report["blacklists"] = "|".join(bl_list)
            audit_log.append(f"BLACKLISTED_ON_{len(bl_list)}_LISTS")

        # Final Scoring
        report["risk_score"] = min(risk_accumulator, 100)
        
        # Append new logs to existing notes
        if audit_log:
            current_note = report["notes"] + "|" if report["notes"] else ""
            report["notes"] = current_note + "|".join(audit_log)

        # Risk Categorization
        if report["risk_score"] >= 75: report["risk_level"] = "CRITICAL"
        elif report["risk_score"] >= 40: report["risk_level"] = "HIGH"
        elif report["risk_score"] >= 15: report["risk_level"] = "MODERATE"
        else: report["risk_level"] = "SAFE"

    # --- STEP 3: TIKTOK VERIFICATION (Only if alive) ---
    if active_proto:
        try:
            p_url = build_conn_str(proxy, active_proto)
            tt_r = browser_requests.get("https://www.tiktok.com", proxies={"http": p_url, "https": p_url}, timeout=10, impersonate="chrome110")
            
            if tt_r.status_code == 200:
                report["tiktok_status"] = "ACCESS_OK (200)"
            elif tt_r.status_code == 403:
                report["tiktok_status"] = "BANNED (403)"
                if report["risk_score"] < 50:
                    report["risk_score"] = 80 
                    report["risk_level"] = "SHADOW_BAN"
            else:
                report["tiktok_status"] = f"HTTP_{tt_r.status_code}"
        except:
            report["tiktok_status"] = "TIMEOUT/RESET"

    return report

# ==============================================================================
# [MAIN]
# ==============================================================================

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("-" * 80)
    print(" TITANIUM PROXY AUDITOR V5 | FORENSIC MODE")
    print("-" * 80)

    if not os.path.exists(FILE):
        print_log("FATAL", f"File not found: {FILE}")
        return

    with open(FILE, "r", encoding="utf-8") as f:
        proxies = [l.strip() for l in f if l.strip()]

    print_log("INFO", f"Loaded {len(proxies)} targets.")
    print_log("CONFIG", f"Threads: {THREADS} | Force Audit: ENABLED")
    print("-" * 80)
    print(f"{'IP ADDRESS':<16} | {'STATUS':<9} | {'ISP':<30} | {'RISK':<10}")
    print("-" * 80)

    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(audit_endpoint, p): p for p in proxies}

        for future in concurrent.futures.as_completed(futures):
            data = future.result()
            results.append(data)

            # Print all results, even DEAD ones, but format nicely
            isp_clean = (data["isp"][:28] + '..') if len(data["isp"]) > 28 else data["isp"]
            status_display = data["status"]
            
            print(f"{data['ip']:<16} | {status_display:<9} | {isp_clean:<30} | {data['risk_level']:<10}")

    # Save Report
    headers = [
        "ip", "status", "infra_type", "risk_level", "risk_score", 
        "tiktok_status", "latency", "protocol", "country", "isp", 
        "blacklists", "notes", "proxy_str"
    ]
    
    results.sort(key=lambda x: (x["risk_score"], x["status"]))

    try:
        with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(results)
        print("-" * 80)
        print_log("SUCCESS", f"Report saved: {OUTPUT_FILE}")
    except Exception as e:
        print_log("ERROR", f"Save failed: {e}")

if __name__ == "__main__":
    main()