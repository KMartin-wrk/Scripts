# Windows Server Administration & Security Scripts

This repository contains a collection of **PowerShell scripts** designed to assist with **Windows Server administration, licensing, and security hardening**.  
All scripts are written with real-world enterprise environments in mind and align with **industry best practices**.

> ⚠️ **Important:** These scripts can make significant system changes.  
> Always test in a **lab or non-production environment first** and ensure appropriate approvals are in place before use.

---

## 📁 Scripts Included

### 1️⃣ Windows Server Evaluation → Full Conversion Script

**Purpose:**  
Converts Windows Server installations from **Evaluation** editions to **Full (Licensed)** editions using **Microsoft Generic Volume License Keys (GVLKs)**.

**Key Features:**
- Supports Windows Server **2016, 2019, 2022, and 2025**
- Automates:
  - Edition detection
  - GVLK application
  - License conversion
- Reduces manual error during post-build server preparation

**Important Notes:**
- This script **does not activate Windows**.
- A valid **KMS or MAK** activation method must still be in place.
- **Do not run on customer systems** without explicit approval from management or the customer.

---

### 2️⃣ Windows Server Security Hardening Script

**Purpose:**  
Applies **baseline security hardening** to Windows Server systems in line with:
- CIS Benchmarks
- Microsoft Security Baselines
- General industry best practices

**Key Features:**
- Interactive OS selection menu
- Registry backup prior to changes
- Configures:
  - Account & password policies
  - Audit policies
  - Defender Exploit Guard / ASR rules
  - PowerShell v2 removal
  - Optional TLS/SSL protocol hardening
- Generates **evidence-friendly logs** suitable for audits and reports

---
