# Incident Report: Web Threat Analysis
**Site:** labcommand.com  
**Log Coverage:** March 7 – March 11, 2026  
**Report Generated:** March 11, 2026  
**Author:** Dauun-LC (Lab Command)

---

## 1. Executive Summary

10,000 web log entries from labcommand.com were analyzed covering March 7–11, 2026. The analysis identified **12 distinct threat actors** across four attack categories, with multiple persistent campaigns active across the entire log window.

The most significant finding is a **coordinated webshell C2 probing campaign** across 6+ IPs on Hetzner and Vultr infrastructure, generating over 400 combined HTTP 200 responses to `wp-load.php` — indicating either planted webshell access attempts or systematic exploitation testing.

| Metric | Value |
|---|---|
| Total Log Entries | 10,000 |
| Threat Actors | 12 distinct IPs/clusters |
| Attack Categories | 4 (Webshell, XMLrpc, Recon, Scan) |
| Log Window | Mar 7–11, 2026 (4 days) |

| Severity | Count |
|---|---|
| 🔴 CRITICAL | 2 threats |
| 🟠 HIGH | 5 threats |
| 🟡 MEDIUM | 3 threats |
| 🟢 LOW | 1 threat |

---

## 2. Immediate Action Items

| # | IP / Target | Action | Status |
|---|---|---|---|
| 1 | 66.42.61.105 | Block in WAF — 83 wp-load.php hits all returning 200 | ⚠ PENDING |
| 2 | 5.161.0.0/16 (Hetzner) | Block subnet in WAF — 5+ IPs in coordinated wp-load campaign | ⚠ PENDING |
| 3 | 178.156.x.x (Frantech) | Block 178.156.128.204 and 178.156.136.36 in WAF | ⚠ PENDING |
| 4 | 61.5.200.197 (Afghan Wireless) | Submit AbuseIPDB report — reporting privilege now approved | ⚠ PENDING |
| 5 | 212.200.181.149 (Serbia) | Submit AbuseIPDB report for xmlrpc.php attacks (37 hits) | ⚠ PENDING |
| 6 | 178.132.108.223 (New) | Block in WAF + AbuseIPDB report (12 xmlrpc hits) | ⚠ PENDING |
| 7 | Webshell scan verification | Run full WAF scan — 400+ wp-load.php 200 responses warrant verification | ⚠ RECOMMENDED |

---

## 3. Threat Actor Details

### T-01 🔴 CRITICAL — wp-load.php Webshell C2 Probe

| Field | Detail |
|---|---|
| IP Address | 66.42.61.105 |
| Origin / ASN | Vultr VPS (US) |
| Total Hits | 83 |
| HTTP Status | 200 (83/83) |
| Active Window | Mar 7 – Mar 11 |
| User-Agent | Chrome/104.0.5112.97 (Win10 x64) |

**Analysis:** Persistent campaign POSTing randomized query strings to `wp-load.php` (e.g. `/wp-load.php?88b063=38632`). All 83 requests returned HTTP 200. This is a known webshell dropper/C2 callback pattern — the attacker is probing whether a previously implanted webshell responds. 83 hits across 4 days indicates automated tooling on a schedule.

**IOC Pattern:** `/wp-load.php?[hex6]=[int5]`

**Recommended Action:** Block in WAF immediately. Report to AbuseIPDB (category 21 - Web App Attack). Verify no webshell was planted — run WAF scan.

---

### T-02 🔴 CRITICAL — wp-load.php Webshell C2 Probe Cluster

| Field | Detail |
|---|---|
| IP Addresses | 5.161.250.15 / 5.161.201.188 / 5.161.44.164 / 5.161.106.94 / 5.161.52.234 |
| Origin / ASN | Hetzner (DE) — same /16 as prior actor 5.161.177.123 |
| Total Hits | 339 |
| HTTP Status | 200 (~98%) |
| Active Window | Mar 7 – Mar 11 |
| User-Agent | Chrome/104.0.5112.97 (Win10 x64) — identical to T-01 |

**Analysis:** Five distinct Hetzner IPs, all using identical User-Agent strings as T-01 and 5.161.177.123 (prior known threat). Combined 339 hits on `wp-load.php` with randomized query strings. Identical UA and URL pattern across 6+ IPs strongly indicates a **single automated campaign rotating IPs** within Hetzner infrastructure. 5.161.177.123 was already flagged in the prior incident — this is the same actor, expanded.

**IOC Pattern:** `5.161.x.x` + `/wp-load.php?[hex]=[int]` + `Chrome/104`

**Recommended Action:** Block entire `5.161.0.0/16` subnet in WAF. Report all IPs to AbuseIPDB. Submit OTX pulse linking to prior 5.161.177.123 entry.

---

### T-03 🟠 HIGH — wp-load.php Webshell C2 Probe (Frantech)

| Field | Detail |
|---|---|
| IP Addresses | 178.156.136.36 / 178.156.128.204 |
| Origin / ASN | Frantech Solutions (CA) — bulletproof hosting |
| Total Hits | 113 |
| HTTP Status | 200 (113/113) |
| Active Window | Mar 7 – Mar 11 |
| User-Agent | Chrome/104.0.5112.97 (Win10 x64) — same campaign fingerprint |

**Analysis:** Two Frantech/BuyVM IPs following the exact same `wp-load.php` pattern as the Hetzner cluster. 113 combined hits, 100% HTTP 200. Frantech is a known bulletproof hosting provider frequently associated with malicious infrastructure.

**IOC Pattern:** `178.156.x.x` + `wp-load.php`

**Recommended Action:** Block in WAF. Report to AbuseIPDB. Note: Frantech does not respond to abuse reports — consider blocking `178.156.0.0/16`.

---

### T-04 🟠 HIGH — XML-RPC Brute Force (Serbia)

| Field | Detail |
|---|---|
| IP Address | 212.200.181.149 |
| Origin / ASN | Serbia (Orion Telekom) — CARRY-OVER from prior incident |
| Total Hits | 37 |
| HTTP Status | 200 (37/37) |
| Active Window | Mar 8, 10:04–11:42 UTC |
| User-Agent | Firefox spoof (Windows NT 6.3 x86 — outdated) |

**Analysis:** Continued XML-RPC attack from prior incident. All 37 requests to `/xmlrpc.php` returned 200, meaning WAF is passing the request but WordPress is handling auth. The spoofed outdated UA (Windows 6.3/x86) is a classic attacker fingerprint. AbuseIPDB report still pending.

**IOC Pattern:** `/xmlrpc.php`, 37 hits, `NT 6.3 x86` UA

**Recommended Action:** Submit pending AbuseIPDB report. Consider adding IP block in WAF. Verify xmlrpc.php is not returning auth tokens.

---

### T-05 🟠 HIGH — XML-RPC Brute Force (New Actor)

| Field | Detail |
|---|---|
| IP Address | 178.132.108.223 |
| Origin / ASN | Unknown — new actor |
| Total Hits | 12 |
| HTTP Status | 200 (12/12) |
| Active Window | Mar 8, 16:34–17:16 UTC |
| User-Agent | Firefox/Windows NT 10.0 x64 spoof |

**Analysis:** New IP not seen in prior incidents. 12 `xmlrpc.php` requests over 42 minutes, all returning 200. Possible credential stuffing or multicall attack. Pattern mirrors 212.200.181.149 behavior.

**IOC Pattern:** `/xmlrpc.php`, 12 hits

**Recommended Action:** Block in WAF. Report to AbuseIPDB (categories 18 + 21). Lookup on VirusTotal and OTX.

---

### T-06 🟠 HIGH — XML-RPC Brute Force (Afghan Wireless)

| Field | Detail |
|---|---|
| IP Address | 61.5.200.197 |
| Origin / ASN | Afghan Wireless — CARRY-OVER from prior incident |
| Total Hits | 10 |
| HTTP Status | 200 (10/10) |
| Active Window | Mar 9, 02:01–02:21 UTC |
| User-Agent | Chrome/Ubuntu x64 spoof |

**Analysis:** Persistent actor from prior incident. OTX and ThreatFox submissions were completed — AbuseIPDB report was pending approval. Still active with `xmlrpc.php` attacks. 10 hits in a 20-minute burst.

**IOC Pattern:** `/xmlrpc.php`, 10 hits

**Recommended Action:** Submit AbuseIPDB report now that reporting privilege is approved.

---

### T-07 🟠 HIGH — WordPress Path Traversal / Webshell Scan

| Field | Detail |
|---|---|
| IP Address | 20.196.201.163 |
| Origin / ASN | Microsoft Azure (JP region) |
| Total Hits | 63 |
| HTTP Status | 403 (60/63) |
| Active Window | Mar 10, 11:03 UTC (burst) |
| User-Agent | Chrome/Win10 x64 |

**Analysis:** Burst scan within 13 seconds probing multiple unusual paths: `/xmlrpc.php`, `/wp-themes.php` (non-existent), `/wp-includes/style-engine/`, `/wp-includes/js/dist/script-modules/block-library/search/about.php` (webshell path injection), `/wp-includes/images/wp-login.php`. The attempted path injection into wp-includes subdirectories is a webshell access attempt. All 60 requests returned 403 — WAF blocked correctly.

**IOC Pattern:** `/wp-includes/[...]/about.php`, `/wp-includes/images/wp-login.php`

**Recommended Action:** Already blocked by WAF. Report to AbuseIPDB (category 21). Flag to Azure abuse: abuse@microsoft.com.

---

### T-08 🟠 HIGH — WordPress Author Enumeration

| Field | Detail |
|---|---|
| IP Address | 43.139.137.13 |
| Origin / ASN | Tencent Cloud (CN) — CARRY-OVER |
| Total Hits | 20 |
| HTTP Status | 429 (20/20) — rate limited |
| Active Window | Mar 8, 18:39 UTC (6-second burst) |
| User-Agent | Apache-HttpClient/4.5.2 (Java/1.8.0_151) — automated tool |

**Analysis:** Systematic enumeration of `/?author=1` through `/?author=20` using Java HTTP client. This is username harvesting — attackers use author IDs to map real WordPress usernames for credential attacks. Rate limiter all 20 requests (429). However, the attacker received enough responses to confirm the site is WordPress.

**IOC Pattern:** `/?author=[1-20]`, `Apache-HttpClient` UA

**Recommended Action:** Block in WAF. Ensure user enumeration is blocked at plugin level. Report to AbuseIPDB.

---

### T-09 🟡 MEDIUM — PHP Info / Configuration Probe

| Field | Detail |
|---|---|
| IP Address | 34.142.251.255 |
| Origin / ASN | Google Cloud (EU) |
| Total Hits | 7 |
| HTTP Status | 403 (7/7) |
| Active Window | Single session |
| User-Agent | Chrome/Win10 x64 |

**Analysis:** Sequential probe of common PHP diagnostic paths: `/phpinfo`, `/info.php`, `/index.php`, `/_profiler/phpinfo`, `/test.php`, `/phpinfo.php`. All blocked with 403. Classic recon to identify PHP version, configuration, and installed extensions.

**IOC Pattern:** `/phpinfo`, `/info.php`, `/_profiler/phpinfo`

**Recommended Action:** Already blocked. Report to AbuseIPDB (category 21).

---

### T-10 🟡 MEDIUM — Webshell Access Attempt (fix/up.php)

| Field | Detail |
|---|---|
| IP Address | 5.175.189.34 |
| Origin / ASN | Unknown |
| Total Hits | 1 |
| HTTP Status | 403 |
| Active Window | Single request |
| User-Agent | Chrome/85.0 (Win10) |

**Analysis:** Single GET request for `//wp-content/plugins/fix/up.php` — a known webshell path associated with a fake 'fix' plugin dropper. Double-slash prefix is used to confuse path normalization. Blocked 403 by WAF. The specific path `/plugins/fix/up.php` indicates the attacker has a list of webshell implant locations and is checking if a previous compromise is accessible.

**IOC Pattern:** `//wp-content/plugins/fix/up.php`

**Recommended Action:** Already blocked. Report to AbuseIPDB.

---

### T-11 🟡 MEDIUM — Windows Live Writer Manifest Probe

| Field | Detail |
|---|---|
| IP Address | 154.16.49.63 |
| Origin / ASN | Unknown |
| Total Hits | 13 |
| HTTP Status | 429 (13/13) |
| Active Window | Rate limited |
| User-Agent | Various |

**Analysis:** Repeated requests for `//test/wp-includes/wlwmanifest.xml` — a file used by Windows Live Writer that reveals WordPress installation details. The double-slash and `/test/` prefix are obfuscation attempts. Rate limited all requests.

**IOC Pattern:** `//test/wp-includes/wlwmanifest.xml`

**Recommended Action:** Already rate-limited. Consider explicitly blocking `wlwmanifest.xml` in WAF.

---

### T-12 🟢 LOW — Crypto/Finance Platform Fingerprinting

| Field | Detail |
|---|---|
| IP Addresses | 123.245.84.115, 182.138.158.55, 182.138.158.196, 123.144.26.115, 220.197.78.96, 42.48.38.36 |
| Origin / ASN | China (Multiple ASNs) |
| Total Hits | 36 each (216 total) |
| HTTP Status | 404 (all) |
| Active Window | Distributed |
| User-Agent | Chrome/120 Win10 x64 (identical across all IPs) |

**Analysis:** Six IPs from Chinese networks, all with identical UA strings, requesting the exact same 36 URLs in identical order referencing `/assets/index/kuailian/` — a known Chinese crypto exchange path. This appears to be a botnet performing platform fingerprinting, scanning for a specific web application across millions of hosts. Not WordPress-targeted.

**IOC Pattern:** `/assets/index/kuailian/`, identical 36-URL pattern across 6 IPs

**Recommended Action:** Low priority — all returned 404. No action required. Note in incident log as botnet fingerprinting campaign.

---

## 4. Infrastructure & Legitimate Traffic Notes

The following high-volume sources were confirmed as legitimate:

| IP | Hits | Source | Notes |
|---|---|---|---|
| 99.175.87.246 | 4,009 | Whitelisted admin IP | Normal browsing and admin activity |
| 103.115.9.76 | 1,342 | WordPress.com cron | Legitimate POST to /wp-cron.php |
| 192.0.102.146 | 581 | uptime monitor | Expected ~10 min intervals |
| 192.0.x.x ranges | Various | WordPress REST API | Backup and sync, correct auth tokens |
| 85.208.98.197 | 157 | JetBrains IDE HTTP client | Developer browsing — not a threat |
| 40.77.x.x / 207.46.x.x | Various | Microsoft Bing crawler | Legitimate |
| 52.x.x.x (various) | Various | OpenAI GPTBot | Legitimate AI indexing |
| 206.189.45.73 | Various | WellKnownBot | Checking /security.txt — legitimate |

> **Note:** 66.225.208.76 (109 requests, HeadlessChrome UA) appears to be a content aggregator scraping article pages. Activity is benign but worth monitoring.

---

## 5. AbuseIPDB Reporting Queue

| IP Address | Hits | Category | Priority | Notes |
|---|---|---|---|---|
| 61.5.200.197 | 10 | 18, 21 | HIGH | Template ready from prior incident |
| 212.200.181.149 | 37 | 18, 21 | HIGH | 37 xmlrpc hits, Mar 8 burst |
| 5.161.177.123 | 58 | 21 | HIGH | Hetzner wp-load.php cluster leader |
| 66.42.61.105 | 83 | 21 | HIGH | Vultr wp-load.php, 83 hits 200 |
| 178.132.108.223 | 12 | 18, 21 | MEDIUM | New xmlrpc attacker Mar 8 |
| 20.196.201.163 | 63 | 21 | MEDIUM | Azure path traversal, all 403'd |
| 43.139.137.13 | 20 | 21 | MEDIUM | Author enum /?author=1-20, all 429 |
| 34.142.251.255 | 7 | 21 | LOW | GCP phpinfo probe, all 403 |

> ⚠ Reports must be submitted before **May 5, 2026** (60-day window from earliest attack Mar 7).

---

## 6. Defense Performance

The current security stack performed well during this log window:

✅ **WAF** successfully blocked (403) all path traversal, phpinfo, and webshell access attempts from 20.196.201.163, 34.142.251.255, and 5.175.189.34.

✅ **rate limiting** (429) caught the author enumeration sweep from 43.139.137.13 and the wlwmanifest probe from 154.16.49.63.

✅ **REST API lockdown** (401) correctly blocked unauthenticated oembed and wp-json requests from external IPs.

⚠ **CONCERN:** 400+ HTTP 200 responses to `wp-load.php` from the Hetzner/Vultr cluster require investigation. HTTP 200 does not confirm webshell execution, but WAF should be configured to block randomized parameter POST requests to `wp-load.php`.

⚠ **CONCERN:** `xmlrpc.php` is returning 200 to known malicious IPs (212.200.181.149, 61.5.200.197, 178.132.108.223). Verify brute force protection or WAF is blocking actual authentication attempts, not just the connection.

---

## 7. Incident Documentation Status

| Item | Status |
|---|---|
| GitHub incident report (this document) | ✅ Complete |
| OTX pulse for 212.200.181.149 | ⚠ Pending |
| DMARC DNS TXT record | ✅ Complete |
| AbuseIPDB reports (queue in Section 5) | ⚠ Pending — process before May 5, 2026 |
| WAF blocks (66.42.61.105, 5.161.0.0/16, 178.156.x.x) | ⚠ Pending |

---

*Report prepared by Lab Command (Dauun-LC) — labcommand.com*
