# DNS Guardian – Suspicious Domain Detection

A small tool that takes a domain name, looks at its DNS records, name characteristics and
reputation data, then produces a **risk score (0–100)** and **explains why** the domain looks suspicious.

---

## 1. Problem Statement
Phishing, malware and scam websites use domains that are newly registered, randomly named,
or hosted with unstable DNS settings. Checking these signs by hand is slow. DNS Guardian
automates the checks and gives a simple, explainable verdict.

## 2. Objectives
- Accept a domain name from the user.
- Analyze its DNS records (A, AAAA, MX, NS, TXT, TTL).
- Check domain characteristics and reputation data.
- Generate a risk score.
- Explain every reason that contributed to the score.

## 3. Project Files
| File | Purpose |
|---|---|
| `analyzer.py` | Core engine: DNS lookup, feature checks, reputation, scoring |
| `app.py` | Simple web page (Flask) |
| `main.py` | Command-line version |
| `requirements.txt` | Python dependencies |

## 4. How It Works (Workflow)

```
User enters domain
      |
      v
 Normalize input  (remove https://, paths, uppercase)
      |
      v
 [1] DNS records   -> A, AAAA, MX, NS, TXT, TTL
 [2] Characteristics -> length, TLD, entropy, digits, hyphens, keywords
 [3] Reputation    -> domain age (RDAP) + Spamhaus blocklist
      |
      v
 Scoring engine adds points for each suspicious sign
      |
      v
 Output: Risk score + level (LOW / MEDIUM / HIGH) + reasons
```

## 5. Scoring Rules
Each suspicious sign adds points. Total is capped at 100.

| Category | Check | Points |
|---|---|---|
| DNS | Domain does not exist (NXDOMAIN) | +15 |
| DNS | No A/AAAA record | +10 |
| DNS | TTL below 300 seconds | +10 |
| DNS | More than 5 IPs (fast-flux) | +10 |
| DNS | Resolves to a private IP | +10 |
| DNS | No NS record | +5 |
| DNS | No MX and no SPF | +5 |
| Name | Suspicious TLD (.xyz, .top, .tk ...) | +10 |
| Name | Phishing keywords (login, verify, paypal ...) | +5 each, max 15 |
| Name | High entropy (random-looking) | +10 |
| Name | Many digits | +5 |
| Name | 2 or more hyphens | +5 |
| Name | 3 or more subdomains | +5 |
| Name | Very long name (30+ chars) | +5 |
| Name | Punycode (`xn--`) | +10 |
| Reputation | Registered less than 30 days ago | +20 |
| Reputation | Registered less than 180 days ago | +10 |
| Reputation | Listed on Spamhaus DBL | +40 |

**Risk levels:** 0–29 = LOW, 30–59 = MEDIUM, 60–100 = HIGH.

## 6. Technologies
- Python 3
- `dnspython` – DNS queries
- `requests` – RDAP (domain age) lookup
- `Flask` – simple web interface

## 7. Installation & Running
```bash
pip install -r requirements.txt

# Web version
python app.py            # open http://127.0.0.1:5000

# Command-line version
python main.py example.com
```
An internet connection is required (DNS and RDAP lookups).

## 8. Sample Test Inputs
| Input | Expected result |
|---|---|
| `google.com` | LOW risk |
| `wikipedia.org` | LOW risk |
| `secure-login-paypal-verify123.xyz` | HIGH risk (keywords, hyphens, digits, bad TLD, NXDOMAIN) |
| `xk3j9q2zpl8vm1.top` | MEDIUM/HIGH (random name, bad TLD) |

Only test with domains you are allowed to look up. The tool only reads public DNS data.

## 9. Limitations
- Rule-based scoring, not machine learning, so it can give false positives/negatives.
- A new but legitimate domain may score higher than it should.
- Blocklist check depends on the DNS resolver being allowed to query Spamhaus (shows "unknown" otherwise).
- Registered-domain detection uses a small list of two-part suffixes.

## 10. Future Scope
- Add more reputation sources (VirusTotal, PhishTank) via API keys.
- Train a machine-learning model on labelled domain data.
- Detect look-alike (typosquatting) domains of popular brands.
- Batch scan from a file and export reports.

## 11. Conclusion
DNS Guardian shows how simple, explainable checks on DNS data can help identify suspicious
domains early, and it is easy to extend.
