"""
DNS Guardian - core analysis engine.

Pipeline:
  1. normalize()        -> clean the user's input into a bare domain
  2. get_dns_records()  -> look up A, AAAA, MX, NS, TXT records
  3. domain_features()  -> look at the name itself (length, entropy, TLD ...)
  4. get_reputation()   -> domain age (RDAP) + Spamhaus DBL blocklist check
  5. score_domain()     -> turn all findings into a 0-100 risk score
  6. analyze()          -> runs everything and returns one result dictionary
"""

import ipaddress
import math
import re
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import requests

# ---------------------------------------------------------------- constants
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work",
    "zip", "country", "support", "icu", "buzz", "rest", "cam", "monster",
}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "banking",
    "wallet", "paypal", "amazon", "apple", "microsoft", "google", "support",
    "password", "confirm", "billing", "free", "bonus", "gift", "prize",
]

# Public suffixes made of two labels (common ones, so "bbc.co.uk" works).
TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "co.in", "org.in", "net.in", "ac.in", "gov.in",
    "com.au", "com.br", "co.jp", "co.za",
}


# ------------------------------------------------------------------ helpers
def normalize(text):
    """'https://WWW.Example.com/path?x=1' -> 'www.example.com'"""
    d = text.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    return d.strip(".")


def is_valid_domain(d):
    pattern = r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"
    return bool(re.match(pattern, d))


def registered_domain(d):
    """Return the registrable part, e.g. mail.google.co.in -> google.co.in"""
    parts = d.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def shannon_entropy(s):
    """Higher entropy = more random-looking text (typical of generated domains)."""
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def _resolver():
    r = dns.resolver.Resolver()
    r.lifetime = 5
    r.timeout = 3
    return r


# ----------------------------------------------------------- 1. DNS records
def get_dns_records(domain):
    """Query common record types. Returns records, TTL and any status notes."""
    resolver = _resolver()
    result = {"records": {}, "ttl": None, "status": "ok"}

    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answer = resolver.resolve(domain, rtype)
            result["records"][rtype] = [r.to_text() for r in answer]
            if rtype == "A":
                result["ttl"] = answer.rrset.ttl
        except dns.resolver.NXDOMAIN:
            result["status"] = "nxdomain"      # domain does not exist
            result["records"][rtype] = []
            break
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            result["records"][rtype] = []
        except dns.exception.DNSException:
            result["records"][rtype] = []
            result["status"] = "lookup_error"
    return result


# ------------------------------------------------- 2. characteristics of name
def domain_features(domain):
    labels = domain.split(".")
    tld = labels[-1]
    main = labels[-2] if len(labels) >= 2 else domain
    return {
        "length": len(domain),
        "tld": tld,
        "subdomain_depth": max(len(labels) - 2, 0),
        "digit_ratio": round(sum(c.isdigit() for c in main) / max(len(main), 1), 2),
        "hyphens": main.count("-"),
        "entropy": round(shannon_entropy(main), 2),
        "is_punycode": "xn--" in domain,
        "keywords": [k for k in PHISHING_KEYWORDS if k in domain],
        "bad_tld": tld in SUSPICIOUS_TLDS,
    }


# ----------------------------------------------------------- 3. reputation
def get_domain_age_days(domain):
    """Ask the public RDAP service for the registration date."""
    try:
        resp = requests.get(f"https://rdap.org/domain/{registered_domain(domain)}",
                            timeout=8, headers={"Accept": "application/json"})
        if resp.status_code != 200:
            return None
        for ev in resp.json().get("events", []):
            if ev.get("eventAction") == "registration":
                created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - created).days
    except Exception:
        pass
    return None


def check_blocklist(domain):
    """Spamhaus Domain Block List. Returns True / False / None (unknown)."""
    try:
        answer = _resolver().resolve(f"{registered_domain(domain)}.dbl.spamhaus.org", "A")
        code = answer[0].to_text()
        if code.startswith("127.255.255"):     # resolver not allowed to query DBL
            return None
        return True
    except dns.resolver.NXDOMAIN:
        return False                            # not listed
    except Exception:
        return None


def get_reputation(domain):
    return {"age_days": get_domain_age_days(domain),
            "blocklisted": check_blocklist(domain)}


# ---------------------------------------------------------- 4. risk scoring
def score_domain(dns_info, feat, rep):
    """Return (score 0-100, list of (points, reason))."""
    findings = []

    def add(points, reason):
        findings.append((points, reason))

    recs = dns_info["records"]

    # --- DNS based checks
    if dns_info["status"] == "nxdomain":
        add(15, "Domain does not exist in DNS (NXDOMAIN) - often seen with throwaway or generated domains.")
    else:
        a_records = recs.get("A", [])
        if not a_records and not recs.get("AAAA"):
            add(10, "Domain has no A/AAAA record, so it does not point to any server.")
        if dns_info["ttl"] is not None and dns_info["ttl"] < 300:
            add(10, f"Very low TTL ({dns_info['ttl']}s). Attackers use it to change servers quickly.")
        if len(a_records) > 5:
            add(10, f"{len(a_records)} IP addresses returned - possible fast-flux hosting.")
        for ip in a_records:
            try:
                if ipaddress.ip_address(ip).is_private:
                    add(10, f"Resolves to a private IP ({ip}), which is abnormal for a public site.")
                    break
            except ValueError:
                pass
        if not recs.get("NS"):
            add(5, "No NS records found for this name.")
        has_spf = any("v=spf1" in t for t in recs.get("TXT", []))
        if not recs.get("MX") and not has_spf:
            add(5, "No mail (MX) or SPF records - looks like a minimal, unmaintained setup.")

    # --- name based checks
    if feat["bad_tld"]:
        add(10, f"TLD '.{feat['tld']}' is frequently abused for cheap throwaway domains.")
    if feat["keywords"]:
        add(min(5 * len(feat["keywords"]), 15),
            "Contains phishing-style words: " + ", ".join(feat["keywords"]) + ".")
    if feat["entropy"] > 3.5 and feat["length"] > 12:
        add(10, f"Name looks random (entropy {feat['entropy']}), typical of auto-generated domains.")
    if feat["digit_ratio"] > 0.3:
        add(5, "High proportion of digits in the domain name.")
    if feat["hyphens"] >= 2:
        add(5, f"Contains {feat['hyphens']} hyphens - common in look-alike domains.")
    if feat["subdomain_depth"] >= 3:
        add(5, "Many nested subdomains, used to hide the real domain.")
    if feat["length"] > 30:
        add(5, "Unusually long domain name.")
    if feat["is_punycode"]:
        add(10, "Uses punycode (xn--), which can hide look-alike characters.")

    # --- reputation checks
    age = rep["age_days"]
    if age is not None:
        if age < 30:
            add(20, f"Domain was registered only {age} days ago.")
        elif age < 180:
            add(10, f"Domain is fairly new ({age} days old).")
    if rep["blocklisted"] is True:
        add(40, "Listed on the Spamhaus Domain Block List.")

    return min(sum(p for p, _ in findings), 100), findings


def risk_level(score):
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


# --------------------------------------------------------------- entry point
def analyze(user_input):
    domain = normalize(user_input)
    if not is_valid_domain(domain):
        return {"error": "Please enter a valid domain, e.g. example.com"}

    dns_info = get_dns_records(domain)
    feat = domain_features(domain)
    rep = get_reputation(domain)
    score, findings = score_domain(dns_info, feat, rep)

    return {
        "domain": domain,
        "dns": dns_info,
        "features": feat,
        "reputation": rep,
        "score": score,
        "level": risk_level(score),
        "reasons": [{"points": p, "reason": r} for p, r in findings],
    }
