# Security Policy

## About This Repository

**LabCommand-Threat-Intel** is a personal cybersecurity homelab project used for
hands-on learning, threat intelligence research, and SOC analyst skill development.
This is not a production application. No live customer data is stored here.

## Supported Versions

This is a single-branch lab environment. Only the current `main` branch is actively
maintained.

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| others  | :x:                |

## Reporting a Vulnerability

If you discover a security issue in this repository (e.g., accidentally exposed
credentials, misconfigurations, or malicious content), please report it responsibly.

**Do not open a public Issue for security concerns.**

Instead, use one of the following:

- **GitHub Private Vulnerability Reporting** (preferred):
  Use the "Report a vulnerability" button under the Security tab of this repository.
- **GitHub Profile**: [github.com/Dauun-LC](https://github.com/Dauun-LC)

### What to Include

- A clear description of the issue
- Steps to reproduce or proof of concept (if applicable)
- Potential impact assessment

### Response Expectations

Since this is a solo lab project, I will aim to:

- Acknowledge the report within **72 hours**
- Remediate valid findings within **7 days**
- Credit reporters in the relevant commit message (if desired)

## Scope

The following are considered **in scope**:

- Hardcoded secrets or credentials in any file
- Malicious or unintended code in scripts
- Dependency vulnerabilities flagged by Dependabot

The following are **out of scope**:

- Theoretical attacks with no practical impact
- Issues in third-party tools referenced but not maintained here

---

*This security policy follows responsible disclosure best practices as part of
ongoing cybersecurity training and portfolio development.*
