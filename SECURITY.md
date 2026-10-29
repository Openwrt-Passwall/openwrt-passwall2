# Security Policy — OpenWrt-PassWall2

The OpenWrt-PassWall2 project takes the security of our software, network routing infrastructure, and users' privacy seriously. As a gateway application running with elevated system privileges on OpenWrt routers, PassWall2 manages low-level firewall rules (`nftables`/`iptables`), DNS interception, and proxy core services (`sing-box`, `xray-core`, `shadowsocks-rust`).

This document outlines our vulnerability disclosure process, threat model, response timelines, and security guidelines for researchers and operators.

---

## 1. Supported Versions

Security updates and patches are actively provided for the following versions:

| Branch / Release | Status | OpenWrt Compatibility | Security Support |
| :--- | :--- | :--- | :--- |
| **PassWall 2.x (`main`)** | **Active** | 24.10, 23.05, 22.03 | :white_check_mark: Full Support & Active Backports |
| PassWall 2.x (Legacy tags) | Maintenance | 21.02 | :warning: Critical CVEs Only |
| PassWall 1.x / Forks | End-of-Life | All | :x: Unsupported (Upgrade to PassWall 2.x) |

---

## 2. Reporting a Vulnerability

We follow the principle of **Coordinated Vulnerability Disclosure (CVD)**. Please do **NOT** report security vulnerabilities via public GitHub issues, discussions, or pull requests.

### Preferred Method: GitHub Private Vulnerability Reporting
1. Navigate to the repository's [Security Advisories](https://github.com/Openwrt-Passwall/openwrt-passwall2/security/advisories) tab.
2. Click **"Report a vulnerability"** to open a confidential draft advisory.
3. Collaborate directly with maintainers in the secure advisory workspace.

### Alternative / Fallback Method: Encrypted Email
If you are unable to use GitHub Security Advisories or need to submit sensitive zero-day research:
- **Email:** `security@passwall.org` *(or contact repository maintainers directly via their signed PGP keys listed on GitHub)*
- **Subject:** `[SECURITY] OpenWrt-PassWall2 Vulnerability Report - <Brief Summary>`
- Please encrypt your submission using GPG/PGP when sending sensitive proofs of concept.

### What to Include in Your Report
To accelerate validation and triage, please provide:
- **Component affected:** (e.g., LuCI CBI model, LuCI controller, shell script in `/usr/share/passwall2/`, firewall script).
- **Environment details:** OpenWrt version, target architecture (e.g., `x86_64`, `aarch64`, `mips_24kc`), PassWall2 package version.
- **Vulnerability classification:** (e.g., Command Injection, Authenticated/Unauthenticated RCE, Cross-Site Scripting, DNS Leak, Insecure Deserialization).
- **Step-by-step reproduction / PoC:** Clear instructions, minimal sample configs, or script payloads demonstrating the issue.
- **Impact assessment:** What access, data, or network control an attacker gains upon exploitation.

---

## 3. SLA & Response Timelines

We commit to meeting 2026 industry standards for vulnerability response:

```
[Day 0] Report Received
   │
   ├─► [≤ 48 Hours] Initial Acknowledgment & Ticket Assignment
   │
   ├─► [≤ 5 Business Days] Severity Triage (CVSS v3.1 / v4.0) & Reproduction
   │
   ├─► [Development Phase] Private Patch Development & Verification in CI/Staging
   │
   └─► [Release Phase] Coordinated Release & Public Advisory (GHSA/CVE)
```

| Milestone | Target SLA |
| :--- | :--- |
| **Initial Acknowledgment** | **Within 48 hours** |
| **Triage & Reproducibility Assessment** | **Within 5 business days** |
| **Patch & Release (Critical Severity — CVSS 9.0–10.0)** | **Target ≤ 14 calendar days** |
| **Patch & Release (High Severity — CVSS 7.0–8.9)** | **Target ≤ 30 calendar days** |
| **Patch & Release (Medium / Low Severity)** | **Target ≤ 60–90 calendar days** |
| **Public Disclosure Window** | **Coordinated at release date** |

---

## 4. Threat Model & Scope Boundaries

PassWall2 operates at the network gateway level. Understanding the boundaries between application logic, upstream dependencies, and host OS helps focus security investigations:

### In-Scope Vulnerabilities
- **LuCI Web Interface Vulnerabilities:**
  - Authenticated or unauthenticated Remote Code Execution (RCE) via web endpoints.
  - Cross-Site Scripting (XSS) or Cross-Site Request Forgery (CSRF) in LuCI controllers (`luasrc/controller/`) or view templates (`luasrc/view/`).
  - Path traversal or arbitrary file read/write through LuCI file upload mechanisms (e.g., rule list imports, backup restore).
- **Shell & UCI Injections:**
  - Command injection in POSIX `/bin/sh` scripts (`root/usr/share/passwall2/*`, init scripts) caused by improper parameter escaping.
  - Insecure handling of user-controlled UCI parameters resulting in arbitrary system modification.
- **Routing & Firewall Bypass / Traffic Leakage:**
  - Flaws in `nftables` or `iptables` rule generation causing complete proxy bypass when "Global Proxy" or "TCP/UDP Proxy" is enabled.
  - Unintended direct DNS leaks bypassing configured DoH/DoT/DoQ or upstream encrypted DNS resolvers.
- **Subscription & Node Ingestion:**
  - Code execution, SSRF, or system denial of service triggered by parsing malicious remote subscription links or configuration payloads.
- **Local Credential & State Exposure:**
  - Insecure file permissions exposing plaintext credentials in `/etc/config/passwall2` to unprivileged local accounts on the router.

### Out-of-Scope Vulnerabilities
- **Upstream Core Zero-Days:** Vulnerabilities residing purely inside third-party core binaries (`sing-box`, `xray-core`, `chinadns-ng`, `shadowsocks-rust`, `trojan-go`) without PassWall2 integration fault. Please report these directly to the respective upstream maintainers.
- **Physical Hardware Exploits:** Attacks requiring direct hardware access, UART debug pins, JTAG adapters, or SPI flash desoldering.
- **Host Compromise Prerequisites:** Attacks that require the attacker to already possess root shell access to the OpenWrt router (e.g., via compromised SSH keys or pre-existing system backdoors).
- **Generic DoS / Network Saturation:** Bandwidth exhaustion or ISP uplink saturation targeting router network interfaces.
- **Missing Non-Critical Headers:** Security scanner reports flagging missing HTTP response headers on local embedded LuCI HTTP daemons (uHTTPd/Nginx) unless a concrete, exploitable vector is demonstrated.

---

## 5. Supply Chain & Build Integrity

OpenWrt-PassWall2 enforces continuous security automation and artifact transparency:

- **Static Security Auditing:** Automated linting via `shellcheck` for all POSIX shell scripts, and strict syntax verification for Lua 5.1 modules.
- **Secret Scanning:** Repository commits are scanned for accidentally embedded private keys, tokens, or personal server credentials.
- **Package Integrity Verification:**
  - Release packages (`.ipk` and `.apk`) include corresponding SHA256 checksums published alongside every release.
  - **Security Warning on `--allow-untrusted`:** When installing `.apk` packages on modern OpenWrt releases using `apk add --allow-untrusted`, package signature checks are bypassed. Operators should verify package SHA256 checksums against official GitHub release notes prior to installation.
- **Cryptographic Signing:** Maintainers sign git release tags and security advisories using verified GPG keys.

---

## 6. Safe Harbor Policy

We consider ethical security research conducted under this policy to be **authorized** and **welcome**.

When conducting security research in good faith:
1. **No Legal Action:** We will not pursue civil or criminal action against you for unintentional or good-faith violations of this policy.
2. **Support & Communication:** We will work collaboratively with you to validate, triage, and resolve confirmed vulnerabilities.
3. **Public Credit:** We will publicly acknowledge your responsible disclosure in release notes and the published GitHub Security Advisory, unless you request anonymity.

### Ground Rules for Researchers
- Make every effort to avoid privacy violations, data destruction, degradation of user experience, or disruption of production router systems.
- Give maintainers reasonable time to remediate the vulnerability before publicly discussing or disclosing any details.
- Only interact with router testbeds and accounts you own or have explicit written permission from the owner to test.

---

## 7. Operator & Deployment Hardening Guidelines

To maintain highest security when deploying PassWall2 on your network gateway:

> [!IMPORTANT]
> **1. Never Expose LuCI to Public WAN**
> Keep your OpenWrt management interface restricted to LAN or accessible solely through encrypted management tunnels (WireGuard, OpenVPN, or SSH port forwarding).

> [!WARNING]
> **2. Sanitize Logs Before Public Sharing**
> When sharing debug logs or filing GitHub issues, always redact sensitive information:
> - Server domain names and public IP addresses
> - Subscription tokens and URLs
> - UUIDs, passwords, and custom encryption keys

> [!TIP]
> **3. Enable DNS Leak Protection & Strict Routing**
> When privacy is critical, ensure TCP/UDP routing and local DNS forwarders are routed through secure, encrypted DNS (DoH/DoT) to prevent ISP-level DNS spoofing.
