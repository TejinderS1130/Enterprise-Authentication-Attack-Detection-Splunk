# Enterprise Authentication Attack Detection with Splunk

Enterprise SOC detection lab demonstrating authentication attack detection across Linux, Windows, and VPN infrastructure using Splunk SIEM.

---

# Project Overview

This lab simulates real-world authentication attacks across multiple systems and demonstrates how a Security Operations Center (SOC) detects and investigates them using centralized logging and SIEM analytics.

### Attacks Simulated

• SSH brute force (Linux)  
• Password spray (Linux accounts)  
• Windows RDP brute force  
• OpenVPN authentication attack  

All attack activity is ingested and analyzed in Splunk SIEM.

---

# Lab Architecture

This lab replicates a **real-world enterprise SOC environment** with:

- Network segmentation  
- Centralized logging  
- Multi-source telemetry  
- SIEM-based detection  

---

## Network Zones

- **WAN (Internet)** → External attacker entry point  
- **Firewall Layer (pfSense)** → Traffic control + VPN gateway  
- **DMZ Zone** → Public-facing service (OpenVPN)  
- **Internal LAN** → Endpoints (Windows, Linux)  
- **SOC Zone** → Security monitoring (Splunk SIEM)

---

## Architecture Diagram
```text
                          Internet (WAN)
                                │
                                │
                     ┌────────────────────┐
                     │   pfSense Firewall │
                     │   192.168.1.1      │
                     │  (VPN Gateway)     │
                     └─────────┬──────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
      DMZ Zone           Internal LAN             SOC Zone
         │                     │                     │
  ┌──────────────┐     ┌──────────────┐      ┌──────────────┐
  │ OpenVPN      │     │ Windows 10   │      │ Splunk SIEM  │
  │ Service      │     │ 192.168.1.20 │      │ 192.168.1.50 │
  │ (External)   │     │ (RDP Target) │      │ Log Analysis │
  └──────────────┘     └──────────────┘      └──────┬───────┘
                                                    │
                                              Log Ingestion
                                                    │
         ┌─────────────────────────────┼─────────────────────────────┐
         │                             │                             │
   Linux Logs                   Windows Logs               Firewall / VPN Logs
 (/var/log/auth.log)          (Event ID 4625/4624)        (pfSense / OpenVPN)

                                                    │
                                                    │
                                      ┌─────────────▼─────────────┐
                                      │   Kali Linux Attacker     │
                                      │   192.168.1.60            │
                                      │  (Simulated Threat Actor) │
                                      └───────────────────────────┘
```
##  Data Flow (Detection Pipeline)

1️⃣ Attacker (Kali Linux) launches attacks:

* SSH brute force
* RDP brute force
* VPN authentication attempts
* Password spraying

2️⃣ Target systems generate logs:

* Linux → `/var/log/auth.log`
* Windows → Event ID 4625 / 4624
* pfSense/OpenVPN → Authentication logs

3️⃣ Logs are forwarded to Splunk SIEM:

* Centralized ingestion
* Field extraction & normalization

4️⃣ Splunk performs detection:

* SPL detection queries
* Cross-source correlation
* Alert generation

5️⃣ SOC investigation:

* Identify attacker IP
* Analyze targeted accounts
* Correlate events across systems
* Validate attack behavior

---

## Security Controls Implemented

* Network segmentation (pfSense firewall)
* VPN authentication monitoring
* Endpoint log collection
* Centralized SIEM visibility

---

## SOC Perspective

This lab demonstrates key SOC capabilities:

* Multi-source log correlation
* Authentication attack detection
* Realistic attacker simulation
* End-to-end detection workflow
* SIEM-driven investigation

---

                              
<img width="468" height="650" alt="image" src="https://github.com/user-attachments/assets/5b069cd9-5a3a-47e3-8a15-749457a07819" />
