# 🔍 Network Recon Toolkit

> Fast TCP port scanner with concurrent scanning, banner grabbing, service detection, OS fingerprinting, and HTML/JSON reporting. Zero external dependencies.

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Dependencies](https://img.shields.io/badge/Dependencies-None%20(stdlib%20only)-brightgreen?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()
[![Security](https://img.shields.io/badge/Domain-Network%20Security-red?style=flat-square)]()

---

## 📋 Overview

**Network Recon Toolkit** is a lightweight but capable TCP port scanner written in pure Python (no external libraries). It uses concurrent threading for speed, attempts banner grabbing on open ports, performs basic OS TTL fingerprinting, and outputs color-coded terminal results alongside professional HTML or JSON reports.

This tool was built to understand how network reconnaissance tools like Nmap work under the hood — and to practice building clean, production-quality security tooling.

---

## ✨ Features

- ⚡ **Concurrent scanning** — up to 500 threads for fast coverage
- 🏷️ **Banner grabbing** — extracts service version info from open ports
- 🖥️ **OS TTL fingerprinting** — guesses OS from ICMP TTL values
- 🎨 **Color-coded terminal output** — HIGH / MEDIUM / INFO risk per port
- 📊 **HTML & JSON reports** — shareable, professional output
- 📦 **Zero dependencies** — stdlib only, works on any Python 3.8+ install
- 🔧 **Flexible port selection** — common ports, full range, or custom ranges

---

## 🏗️ Architecture

```
network-recon-toolkit/
│
├── scanner.py        ← Main script (all logic in one file)
├── requirements.txt  ← No dependencies
├── .gitignore
└── README.md
```

---

## 🚀 Getting Started

```bash
git clone https://github.com/Charan-kommi/network-recon-toolkit.git
cd network-recon-toolkit
python scanner.py --help
```

No installation required — pure Python stdlib.

---

## 💻 Usage

```bash
# Scan common ports (default)
python scanner.py 192.168.1.1

# Scan specific ports
python scanner.py 192.168.1.1 -p 22,80,443,8080-8090

# Full port scan (1-65535) with 200 threads
python scanner.py 192.168.1.1 -p all --threads 200

# Fast scan without banner grabbing
python scanner.py 192.168.1.1 --no-banner

# Output both HTML and JSON reports
python scanner.py 192.168.1.1 --output both
```

### Sample Terminal Output

```
=======================================================
   Network Recon Toolkit — by Sai Charan Kommi
   ⚠️  Authorized use only
=======================================================

[*] Target  : 192.168.1.1
[*] IP      : 192.168.1.1
[*] Host    : router.local
[*] TTL     : 64  →  OS Guess: Linux / Unix
[*] Ports   : 35 to scan
[*] Threads : 100

  [OPEN]     22/tcp  SSH             [SSH-2.0-OpenSSH_8.9]
  [OPEN]     80/tcp  HTTP            [HTTP/1.1 200 OK]
  [OPEN]    443/tcp  HTTPS
  [OPEN]   3306/tcp  MySQL

[=] Scan complete — 4 open port(s) found
[+] HTML report → scan_report.html
```

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.8+ (stdlib only) |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` |
| Networking | `socket` module |
| OS Detection | ICMP TTL via `subprocess` + `ping` |
| Output | HTML, JSON, Terminal (ANSI colors) |

---

## 📊 Risk Classification

| Risk Level | Example Ports | Why It Matters |
|---|---|---|
| 🔴 HIGH | 21 (FTP), 23 (Telnet), 3389 (RDP), 445 (SMB) | Commonly exploited, plaintext protocols |
| 🟡 MEDIUM | 22 (SSH), 3306 (MySQL), 6379 (Redis) | Often misconfigured or exposed unintentionally |
| 🔵 INFO | 80 (HTTP), 443 (HTTPS), 53 (DNS) | Normal services, review for exposure |

---

## 🔒 Legal Disclaimer

> ⚠️ **This tool is intended for authorized security testing and educational purposes only.** Always obtain explicit written permission before scanning any network or host you do not own. Unauthorized port scanning may be illegal in your jurisdiction.

---

## 🗺️ Roadmap

- [x] TCP connect scan with threading
- [x] Banner grabbing
- [x] OS TTL fingerprinting
- [x] HTML + JSON reporting
- [ ] UDP scanning
- [ ] Service version detection (deeper probes)
- [ ] CIDR range scanning (e.g., `192.168.1.0/24`)
- [ ] CVE lookup for detected service versions

---

## 👤 Author

**Sai Charan Kommi**
[![LinkedIn](https://img.shields.io/badge/LinkedIn-charankommi-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/charankommi)
[![GitHub](https://img.shields.io/badge/GitHub-Charan--kommi-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/Charan-kommi)

> MS Cybersecurity @ GWU | CompTIA Security+ | AWS Cloud Security Builder
