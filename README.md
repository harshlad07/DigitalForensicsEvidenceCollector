# 🧾 Digital Forensics Evidence Collector

A cross-platform Python-based tool to collect volatile and non-volatile digital evidence from a system. Designed for use in incident response, digital forensics investigations, system auditing, and cybersecurity labs.

---

## 📌 Features

- 🖥️ **System Info** — OS, CPU, memory, hostname, and uptime
- ⚙️ **Running Processes** — Full process list with PID, name, cmdline
- 🌐 **Network Connections** — Open ports, IPs, and active sessions
- 🔌 **USB History** — Devices connected (Windows only)
- 📁 **Recent Files** — Recently accessed or modified files
- 🔍 **Track Specific Process**:
  - Static metadata (name, PID, cmdline, children)
  - Live monitoring of CPU/Memory usage
  - Open files and sockets
  - Logs and activity footprint
- 📊 **Chart Generation** — CPU and Memory usage charts (`.png`)
- 📂 **Structured Output**:
  - Organized folders by module
  - Auto-timestamped to avoid overwrite
- 🧾 **Report Archiving** — Hash + ZIP archive

---

## 🛠️ Installation

### Requirements

- Python 3.7+
- OS Support:
  - ✅ Windows (full support)
  - ✅ Linux (partial for USB/logs)
  - ⚠️ WSL (limited log access)

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