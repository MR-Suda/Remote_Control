# REMOTE CONTROL - Network Research Tool

### 🚀 Description -
**REMOTE CONTROL** is a Bash-based network reconnaissance and scanning tool developed as part of a cybersecurity course (NX201).
It allows users to perform remote scans via SSH on a chosen server using anonymized traffic through the Nipe tool (Tor routing).
The script validates input, performs port scanning, WHOIS lookups, generates a TL;DR summary, and can produce ZIP and PDF reports.

---

### 📁 Project Info -
- **Student**: MR-Suda
- **Class**: 7736/32
- **Program**: NX201 - Cybersecurity & Network Defense
- **Password**: mrsuda

---

### 🛠 Features -
- 🔒 Root privilege enforcement with password check (although the script is not encrypted and the password can be viewed easily).
- 📦 Auto install dependencies (whois, git, nmap, geoip-bin, curl, sshpass, zip, nipe, perl, enscript and ghostscript).
- 🕵️ Activates Nipe for anonymity and verifies the spoofed IP. If the IP is from Israel, the script safely exits.
- 🔗 SSH connection to remote server with credential verification.
- 📍 Supports multiple scan types: Quick, Full, Service Detection and OS Detection.
- 🌐 WHOIS lookup on target IPs.
- 📄 Generates logs, a human-readable summary and an optional PDF report.
- 📦 Optional ZIP backup of scan results.

---

### 📂 Folder Structure (on provided path) -
```
Project Folder
├── <DirName>/
│   ├── whoisscan.txt
│   ├── nmapscan.txt
│   ├── nipe/
│   └── Remote_Control_Log.log
├── scan_report_DATE_TIME.zip (optional)
├── scan_report_DATE_TIME.pdf (optional)
└── Remote_Control.sh (can be stored outside this folder)
```

---

### ⚙️ Requirements -
- Linux (tested on Kali)
- Root access
- `bash`, `nmap`, `whois`, `sshpass`, `geoip-bin`, `curl`, `git`, `perl`, `enscript`, `ghostscript`, `zip`
- Internet access (for installing and WHOIS queries)

---

### 🔧 How to Use -
1. Run the script as root or with root privileges -
   ```bash
   sudo ./Remote_Control.sh
   ```
2. Follow on-screen prompts:
   - Set output directory
   - Connect to remote server
   - Choose scan type
   - View or export results

---

### 🧾 Example Output -
```
====================================
           REMOTE CONTROL
====================================

Spoofed country ~ Sweden

1) Run Scan
2) Exit

Enter your choice - 1
...
View WHOIS scan results? [y/n] - y
...
Zip the scan folder? [y/n] - y
...
Generate a PDF report? [y/n] - y
```

---

### 📌 Notes -
- Nipe must spoof your location successfully (non-Israel IP) to proceed.
- WHOIS might fail if the remote machine cannot resolve whois.arin.net.
- Enscript and ghostscript are required to generate PDFs.

---

### 🧑‍💻 Author -
- **MR-Suda**
- GitHub - [MR-Suda] - https://github.com/MR-Suda

---

### 📜 License -
This project is for educational purposes only under fair use. Unauthorized use is discouraged !!!

---

Feel free to fork, improve, and share!

---

✨ Happy Scanning!

