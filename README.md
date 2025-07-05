# Locky Ransomware Analysis

This repository contains a comprehensive static and dynamic analysis of the Locky ransomware sample, conducted as part of a malware reverse engineering project.

---

## 🧪 Project Overview

- **Malware Family:** Locky Ransomware
- **Sample Hash:** afec2b2af3ace2c478382f9366f6cbc9b9579f2c9a4273150fc33a2ccd59284c
- **Techniques Used:**
  - Static Analysis (PEiD, PEStudio, FLOSS, Ghidra, IDA)
  - Dynamic Analysis (ProcMon, Wireshark, Fakenet)
  - Behavioral Analysis (ANY.RUN, FLARE VM)

---

## 📂 Folder Structure

\`\`\`
├── analysis/
│   ├── static/
│   └── dynamic/
├── report/
├── provided_material/
└── sample/ (excluded from GitHub)
\`\`\`

---

## 🧠 Key Findings

- Locky uses junk code and encrypted strings to hinder reverse engineering.
- C2 communication was observed via HTTP POST.
- The main payload is decrypted and executed in memory.

---

## 🛠 Tools Used

| Tool        | Purpose                      |
|-------------|------------------------------|
| PEiD        | Packing detection            |
| PEStudio    | Static PE analysis           |
| FLOSS       | Obfuscated string recovery   |
| Ghidra/IDA  | Disassembly and decompilation|
| ProcMon     | File/Registry monitoring     |
| Wireshark   | Network traffic inspection   |
| Fakenet     | Simulated network sinkhole   |
| ANY.RUN     | Online sandbox behavior      |

---

## 👤 Authors

- **Karim Elmasry**
- **Abdelrahman Abdelmoaty**
- **Haidy Ahmed**
- **University:** AASTMT — Cybersecurity Program
- **Semester:** Spring 2025
