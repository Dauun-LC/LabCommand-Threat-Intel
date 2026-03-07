# Changelog

All updates to this repository are logged here in reverse chronological order.

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
