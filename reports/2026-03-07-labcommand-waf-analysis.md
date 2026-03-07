# Threat Intelligence Report: LabCommand.com Log Analysis
**Period:** February 21 – February 28, 2026  
**Analyst:** LabCommand Security Research  
**Status:** Final  
**Repository:** LabCommand-Threat-Intel

---

## Executive Summary

During the period of February 21–28, 2026, LabCommand.com experienced sustained 
automated attack activity across four distinct threat categories: surface 
reconnaissance, content scraping, web shell hunting, and credential brute forcing. 
All activity was blocked by the site's WAF and ██████** layers. Analysis of 8,660 log entries 
identified 28 unique attacker IPs, enriched against AbuseIPDB and VirusTotal. 

Notable findings include a confirmed Remcos RAT command-and-control server, two 
coordinated Azure-hosted web shell hunting campaigns running identical toolkits 
across multiple nodes, a Lithuanian hosting provider serving as infrastructure 
for both WordPress credential attacks and broader phishing and fraud operations, 
and a Serbian-registered IP with Iranian threat actor list associations conducting 
persistent brute force campaigns since September 2025.

---

## Methodology

WAF, ██████**, ██████**, and web server logs were exported and triaged in Google Sheets. Own 
infrastructure IPs, legitimate platform IPs (██████**, ██████**, ██████)**, 
and verified crawlers were filtered out, reducing 8,660 rows to 28 unique blocked 
attacker IPs. Each IP was categorized by behavioral pattern and enriched using 
AbuseIPDB (confidence score, report count, source count, categories) and 
VirusTotal (vendor detections, passive DNS, referring files, community notes). 
IOCs were recorded in structured CSV format by category. 

---

## Findings by Category

### 1. Scanners (7 IPs)

Automated surface reconnaissance activity targeting robots.txt, /.well-known/, 
/security.txt, and root paths. User agents included self-identified scanner 
strings, Go HTTP clients, and Python requests libraries alongside spoofed 
browser agents. 

Most significant finding: 45.154.98.13 (AS 1337 Services GmbH, NL) identified 
as a confirmed Remcos RAT command-and-control server hosted on disposable 
anonymous RDP infrastructure — flagged by 10/94 VirusTotal vendors. Two Oracle 
Cloud IPs (129.213.23.155, 150.136.37.19) demonstrated rotating user agent 
evasion, cycling between fake Googlebot and browser impersonation across 
multiple visits. Community reporting confirmed WordPress attacks, DDoS activity, 
SQL injection, and xmlrpc.php probing from these nodes beyond the recon 
observed at LabCommand.

### 2. Scrapers (1 IP)

A single high-volume scraper was identified: 117.132.188.205 (AS9808 China 
Mobile, CN) conducted systematic content harvesting across blog posts, tags, 
and categories — 97 requests in a single session. AbuseIPDB confidence 100%, 
1,059 reports from 212 distinct sources. VirusTotal flagged 6/94 vendors 
malicious. Behavior is consistent with large-scale content aggregation or 
AI training data collection operations associated with Chinese mobile 
infrastructure.

### 3. Shell Hunters (3 IPs)

Two coordinated campaigns were identified.

**Campaign 1 — Azure Japan (20.78.129.228, 20.89.58.13):** Two Microsoft Azure 
nodes operating from Osaka and Tokyo executed identical web shell dictionary 
scans one day apart (Feb 26 and Feb 27), probing 19–26 distinct PHP backdoor 
paths per session. Shared path lists include bless.php, bolt.php, rip.php, 
adminfuns.php, class-t.api.php, and ioxi-o.php — consistent with an automated 
shell hunting toolkit running across multiple compromised Azure nodes. Community 
reporting also identified cryptominer installation path probing (/cgi-bin/xmrlpc.php) 
from these IPs. AbuseIPDB confidence 100% on both, with 1,086 and 1,094 reports 
respectively — both actively reported on the day of analysis. 

**Campaign 2 — OVH Germany (51.75.151.149):** A distinctly more targeted 
attacker operating from OVH Frankfurt conducted a persistent 6-day campaign 
(Feb 21–27). Unlike the Azure toolkit approach, this IP probed specific WordPress 
plugin vulnerability paths (/wp-content/plugins/one_images_user/), REST API 
endpoints (/wp-json/teknocore/v1/), and attempted web shell placement within 
image subdirectories (/assets/images/, /images/images/). This behavioral profile 
indicates an attacker with specific WordPress internals knowledge rather than 
generic automated scanning. Community reports confirm concurrent xmlrpc.php 
brute forcing and SQL injection activity. (██████** omitted for privacy ██████**)

### 4. Brute Forcers (5 IPs)

Five IPs targeted Wordpress & ██████** authentication endpoints (wp-login.php, wp-admin/, ██████**, ██████**, ██████**).

**Lithuanian infrastructure (141.98.11.169, 141.98.11.209, AS209605 UAB Host 
Baltic):** Two IPs from the same ASN conducted credential attacks using spoofed 
Mac/Firefox user agents. 141.98.11.169 carries 21,125 AbuseIPDB reports from 
1,053 sources — one of the highest-volume IPs in this dataset — and was actively 
reporting during analysis. VirusTotal passive DNS for 141.98.11.209 reveals 
75 associated domain resolutions including domains consistent with phishing and 
financial fraud operations, indicating this infrastructure extends well beyond 
WordPress targeting.

**DigitalOcean Singapore (129.212.238.91):** Three hits in a single session 
cycling through Mac Firefox and Windows Chrome user agents — consistent with 
automated credential stuffing. Community AutoBlock triggers confirmed 20–30x 
login attempts against other targets.

**Private Layer Switzerland (179.43.159.170):** Single wp-admin probe. 684 
AbuseIPDB reports, 100% confidence, actively reported on day of analysis. 
Community reports document 31 xmlrpc.php and wp-login.php hits per minute 
against other targets — LabCommand received a single blocked probe.

**Cipher Operations Serbia (62.60.130.228, AS215930):** Single wp-admin probe 
with spoofed Mac Safari user agent. Despite the Serbian ASN registration, 
VirusTotal geolocates this IP to Iran and it appears in Iranian IP threat actor 
activity lists. Persistent WordPress brute force campaign documented since 
September 2025. 5,699 AbuseIPDB reports from 426 sources.

---

## Threat Actor Infrastructure Observations

Several patterns emerged across categories that suggest shared infrastructure 
or coordinated campaigns:

- The Azure Japan shell hunting campaign (20.78.129.228, 20.89.58.13) used 
  identical path wordlists one day apart, suggesting a single operator or 
  shared toolkit running across compromised Microsoft cloud nodes.
- 51.75.151.149 and 62.60.130.228 share referring files in VirusTotal 
  (including an Australian university access log), suggesting possible 
  infrastructure overlap or shared tooling between the OVH shell hunter 
  and the Serbian/Iranian brute forcer.
- The Lithuanian ASN (AS209605) served dual purpose — WordPress credential 
  attacks and broader phishing/fraud domain hosting — consistent with 
  bulletproof hosting or criminal infrastructure-as-a-service.
- Oracle Cloud IPs (AS31898) appeared in both the scanner and multi-behavior 
  categories, suggesting Oracle Cloud infrastructure is being routinely 
  abused for attack staging.
- (Omitted for privacy ██████**)
- (Omitted for privacy ██████**) 

---

## Defensive Posture Assessment

All 28 IPs were blocked at the WAF and ██████** layers. No successful intrusions were 
detected. The following observations apply:

- (Omitted for privacy ██████**)
- (Omitted for privacy ██████**)
- (Omitted for privacy ██████**)

---

## IOC Summary

| Category | IPs | Total Requests | All Blocked |
|---|---|---|---|
| Scanners | 7 | ~20 | Yes |
| Scrapers | 1 | 97 | Yes |
| Shell Hunters | 3 | 58 | Yes |
| Brute Forcers | 5 | 11 | Yes |
| **Total** | **16** | **~186** | **Yes** |

Full IOC data available in /iocs/ directory.

---

## Recommendations

1. Continue monitoring for recurrence from documented IPs, particularly 
   the Lithuanian ASN (AS209605) and Azure Japan nodes given their active 
   status at time of analysis.
2. Consider blocking AS209605 (UAB Host Baltic) at network level given 
   confirmed criminal infrastructure designation.
3. Monitor Oracle Cloud (AS31898) traffic for continued multi-behavior 
   patterns.
4. (Omitted for privacy ██████**)

---

*Report prepared as part of ongoing LabCommand security research and 
threat intelligence documentation.*
**REDACTED/OMITTED FOR PRIVACY 
