# Security Policy

## Supported Versions

ThreatSynth 79 is currently maintained on the `main` branch only.

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in ThreatSynth 79, please **do not open a public issue**.

Instead, report it privately:

1. Go to the repository's **Security** tab on GitHub.
2. Click **"Report a vulnerability"** to open a private security advisory.
   (Enable this under **Settings → Code security → Private vulnerability reporting**.)
3. Alternatively, email the maintainer directly (add your contact email here).

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept if possible)
- Any suggested remediation

## Response Process

- We will acknowledge receipt of your report within **72 hours**.
- We will investigate and provide an initial assessment within **7 days**.
- Once confirmed, a fix will be prioritized based on severity and released as soon as practical.
- Credit will be given to the reporter in the release notes, unless anonymity is requested.

## Scope

This project uses **synthetic data only** and is built for demo/incident-response-drill purposes.
It is not currently intended for production deployment against real SIEM or PII/PHI data without
further hardening (secrets management, production-grade IdP integration, TLS termination, etc.).

## Disclosure Policy

We follow a **coordinated disclosure** approach — please give us a reasonable window to address
the issue before any public disclosure.
