# 🧾 Digital Forensics Evidence Collector

A cross-platform Python-based tool for collecting volatile and non-volatile evidence during incident response, forensic investigations, or audit automation. Now includes a **Tkinter-based GUI** for easier use.

---

## 📌 Features

- 🖥️ System Info — OS, CPU, memory, uptime
- ⚙️ Running Processes — Full list with PID, command-line
- 🌐 Network Connections — Active IPs, ports, domain resolution
- 🔌 USB Device History — Devices connected (Windows only)
- 📁 Recent Files — Recently accessed or modified files
- 🔍 Track Specific Process:
  - Metadata (name, PID, children)
  - CPU & Memory monitoring
  - Open files and logs
  - Live usage charts
- 📊 Chart Generation — Memory & CPU graphs, Top Visited Domains
- 📂 Output:
  - Auto timestamped folders
  - Structured JSON exports
  - Optional ZIP + SHA-256 hash
- 🖼️ **Live GUI** with Tkinter — Visual interface to run modules without CLI

---

## 🛠️ Installation

### Requirements

- Python 3.7+
- OS: ✅ Windows, ✅ Linux, ⚠️ WSL (partial support)

### Install Dependencies

```bash
pip install -r requirements.txt
psutil
matplotlib
pywin32 ; platform_system == "Windows"
```

### 🧠 Use Cases
🛡️ Security breach or malware investigation
🔍 Insider threat forensics
📊 Process behavior profiling
🎓 Digital forensics education & labs
📦 Evidence collection for compliance audits


### ✍️ Author
Harsh Lad
Cybersecurity & Forensics Enthusiast
📧 harshlad07@gmail.com
🔗 GitHub: [github.com/yourusername](https://github.com/harshlad07/)
🔗 LinkedIn: linkedin.com/in/harsh-lad-5907661b5