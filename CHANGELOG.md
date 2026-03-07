# Changelog

All updates to this repository are logged here in reverse chronological order.

## [2026-03-07] (continued)
- Added 3 IOC entries to shell-hunters.csv covering systematic PHP backdoor 
  hunting and targeted WordPress exploitation from JP and DE origins. Two 
  Azure Japan IPs (20.78.129.228, 20.89.58.13) running identical web shell 
  dictionary toolkits across compromised Microsoft infrastructure, probing 
  25+ backdoor paths per session including cryptominer installation targets. 
  OVH Germany IP (51.75.151.149) shows distinct profile — persistent 6-day 
  campaign with WordPress plugin-specific CVE probing, REST API enumeration, 
  and image directory shell placement attempts. All entries enriched via 
  AbuseIPDB and VirusTotal.
- Response code corrected, Line 2 scrapers  

## [2026-03-07]
- Added 5 IOC entries to brute-forcers.csv covering WordPress credential 
  attacks against wp-login.php and wp-admin from LT, SG, CH, RS origins. 
  Notable entries include two IPs from Lithuanian criminal infrastructure 
  with phishing domain associations, a DigitalOcean Singapore node using 
  rotating user agents, and a Serbian-registered IP with Iranian threat 
  actor list associations. All entries enriched via AbuseIPDB and VirusTotal.

## [2026-03-07]
- Added 7 IOC entries to scanners.csv covering automated recon, surface mapping, 
  Googlebot user agent spoofing, and multi-behavior scanning activity originating 
  from DE, NL, and US data center infrastructure. Notable entries include a confirmed 
  Remcos RAT C2 server, Oracle Cloud IPs with rotating user agent evasion, and a 
  self-identified scanner/1.0 agent. All entries enriched via AbuseIPDB and VirusTotal.

## [2026-03-06]
- Added first IOC entry to scrapers.csv: 117.132.188.205 (CN) — content scraper, 97 requests, AbuseIPDB 100% confidence
- Added IOC entry to shell-hunters.csv: 20.53.240.38 (AU) — web shell hunter, 33 requests, Azure cloud IP, AbuseIPDB 100% confidence

## [2026-03-05]
- Initialized repository structure
- Added IOC category files: scanners, scrapers, shell-hunters, brute-forcers
- Added reports folder
