<div align="center">

# 🛡️ Anzen Security Watcher

**See the Unseen. Stop the Silent Threat. Empower Everyone with AI-Driven Endpoint Visibility.**

*An ultra-lightweight, real-time Windows 11 security radar & AI SOC diagnostic companion built with native C# / .NET 8 WPF.*

[![Language: English](https://img.shields.io/badge/Language-English-0078D4?style=for-the-badge)](./README.md)
[![Language: 日本語](https://img.shields.io/badge/言語-日本語-DC143C?style=for-the-badge)](./README.ja.md)
[![Language: 简体中文](https://img.shields.io/badge/语言-简体中文-DE2910?style=for-the-badge)](./README.zh-CN.md)
[![Language: Español](https://img.shields.io/badge/Idioma-Español-FFC400?style=for-the-badge)](./README.es.md)

[![Platform](https://img.shields.io/badge/Platform-Windows%2011-0078D6?style=flat-square&logo=windows11)](https://www.microsoft.com/windows)
[![Runtime](https://img.shields.io/badge/.NET-8.0%20WPF-512BD4?style=flat-square&logo=dotnet)](https://dotnet.microsoft.com/)
[![Architecture](https://img.shields.io/badge/Engine-Win32%20%26%20NT%20Native%20API-00A4EF?style=flat-square)](#key-features)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](./LICENSE)

</div>

---

## 🌍 Choose Your Language / 言語選択 / 选择语言 / Seleccionar idioma

- 🇺🇸 **[English (Default)](./README.md)** — You are here
- 🇯🇵 **[日本語 (Japanese)](./README.ja.md)** — 日本語ドキュメントはこちら
- 🇨🇳 **[简体中文 (Simplified Chinese)](./README.zh-CN.md)** — 中文文档请点击这里
- 🇪🇸 **[Español (Spanish)](./README.es.md)** — Documentación en español aquí

---

## 💡 Overview: Why "Anzen Security Watcher"?

Have you ever noticed a black terminal window flash on your screen for just **0.2 seconds** and wondered, *"Was that a normal Windows update, or did malware just execute?"*  
Have you ever worried whether a background remote-access tool is silently streaming your screen, or which country your PC is secretly communicating with right now?

Traditional antivirus software operates as a black box—until an alert fires, you have zero visibility into what your computer is actually doing. Meanwhile, enterprise EDR solutions are too expensive, complex, and heavy for everyday users or agile teams.

**Anzen Security Watcher** (*"Anzen" means Safety/Security in Japanese*) bridges that gap. Crafted as a personal open-source project by a **20-year veteran systems architect**, it transforms complex low-level Windows kernel/Win32 telemetry into an intuitive, real-time visual dashboard—and translates suspicious technical logs into **ready-to-paste AI prompts** so anyone can get instant, SOC-analyst-grade advice from ChatGPT, Claude, or Gemini.

---

## 🎯 Who Is This For?

| Audience | How Anzen Security Watcher Helps You |
| :--- | :--- |
| 🧑‍💻 **Everyday PC Users & Remote Workers** | Instantly see if your screen, camera, or mic is being shared without your knowledge. Get a simple **100-point Safety Score (Grade A–E)** and ask AI in plain language if something looks strange. |
| 🛡️ **IT Admins, SysAdmins & Blue Teams** | Catch **50ms flash terminals**, decode obfuscated PowerShell (`-enc`), spot periodic C2 beacons, audit persistence registries, and detect unsigned DLL sideloading without installing heavy kernel drivers. |
| 🏢 **Team Leads & Organization Admins** | Gain instant visibility into unexpected screen sharing, unauthorized remote desktop sessions, and suspicious background telemetry on work PCs to safeguard sensitive data. |
| ⚙️ **Developers & Security Researchers** | Explore a clean, native C# / .NET 8 WPF codebase demonstrating Win32 IP Helper APIs, `NtQueryInformationProcess`, WTS session inspection, and statistical beacon math. |

---

## ✨ Key Features

### 1. 🌐 Real-Time TCP/UDP Country-by-Country Traffic Monitor
- **Process-Level Socket Attribution**: Uses Win32 IP Helper APIs (`GetExtendedTcpTable` / `GetExtendedUdpTable`) to map every active TCP connection and UDP endpoint directly to its owning PID, process name, and executable path.
- **Hybrid GeoIP Engine**: Combines instant offline CIDR resolution for local/LAN and major cloud regions with asynchronous, API-key-free GeoIP lookups (`ipwho.is` / `ip-api.com`), persisted in a fast local cache (`Data/geoip_cache.json`).
- **One-Click Country Filtering**: Click any country summary card at the top of the screen to isolate traffic to/from specific nations.
- **Automated Threat Highlighting**: Immediately flags external connections initiated by LOLBins (`powershell`, `cmd`, `rundll32`, `mshta`), high-risk ports (`3389`, `5900`, `4444`), and watchlisted jurisdictions.

### 2. 🖥️ Live Screen-Sharing & Remote Control Detector (Topmost Visual Alert)
- **Windows RDP Detection**: Cross-checks WTS APIs (`WTSEnumerateSessions` / `WTSQuerySessionInformation`), `GetSystemMetrics(SM_REMOTESESSION)`, `rdpclip.exe` activity, and port `3389` states.
- **Remote Support Tool State Distinction**: Monitors AnyDesk, TeamViewer, UltraVNC/TightVNC/RealVNC, RustDesk, Chrome Remote Desktop, Windows Quick Assist, Parsec, Splashtop, ScreenConnect, and LogMeIn—smartly distinguishing between **"Idle Background Service"** and **"ACTIVE External Session Streaming Your Screen"**.
- **Meeting Screen-Share Catcher**: Uses Win32 `EnumWindows` to detect Zoom screen-capture processes (`CptHost.exe`, green border classes `ZPFTEWndClass`), Microsoft Teams, Discord, Slack, and browser sharing indicators.
- **Unmissable Warning System**: Flashes a red warning banner, triggers a **Topmost bottom-right alert popup**, and sends a Windows system tray notification the moment your screen starts leaving your PC.

### 3. ⚡ 50ms "Flash Terminal" Sniper & Process Command-Line Analyzer
- **0.05-Second (50ms) Sniper Engine**: Powered by high-speed Win32 `CreateToolhelp32Snapshot` polling, Anzen catches ultra-short-lived processes that flash on screen for just 0.1–0.3 seconds and vanish—recording their **full command-line arguments**, **parent process** (e.g., `svchost/Schedule`, `WmiPrvSE`), **exact lifespan in milliseconds**, and **matching Scheduled Task**.
- **⏰ 60-Minute Scheduled Task Correlator**: One click scans all Windows Task Scheduler folders (including `\Microsoft\Windows`) to pinpoint which background task spawned a mysterious flash window.
- **Periodic Beacon Detection**: Tracks launch timestamp histories and computes mean interval ($\mu$), standard deviation ($\sigma$), and coefficient of variation ($CV = \sigma / \mu$) to uncover automated C2 beacons or hidden cron-like jobs.
- **Rare / First-Seen / Unsigned Process Hunter**: Compares running processes against your baseline (`Data/process_baseline.json`) and highlights unsigned binaries executing from `Temp`, `Downloads`, or `AppData`.
- **Deep Command-Line De-obfuscation**: Queries `NtQueryInformationProcess` to extract full arguments, automatically decodes Base64 PowerShell (`-enc`), and detects `IEX`, `DownloadString`, shadow-copy deletion (`vssadmin delete shadows`), and Office-spawned shells.

### 4. 🛡️ 100-Point System Defense Score & 10-Layer Host Audit
- **📊 Automated Security Grading (0–100 Score / Grade A–E)**: Audits Microsoft Defender real-time protection, Windows Firewall, UAC, SmartScreen, RDP/NLA, UEFI Secure Boot, SMBv1 status, AutoRun blocking, `hosts` file tampering, and proxy hijacking—with one-click shortcuts to fix weak settings.
- **🚀 Persistence & Autorun Monitor**: Diffs `Run`/`RunOnce` keys, Startup folders, `Winlogon` (`Shell`/`Userinit`), `IFEO` (`Debugger`), services, and scheduled tasks against your clean baseline.
- **🧩 DLL Sideloading Detector**: Spots unsigned DLLs planted alongside digitally signed legitimate executables.
- **📷 Camera & Microphone Live Privacy Monitor**: Reads `CapabilityAccessManager\ConsentStore` to show which app is actively using your webcam or mic right now (`LastUsedTimeStop == 0`).
- **🎹 Keylogger & 📋 Clipboard Sniffer Detection**: Flags suspicious background processes importing global keyboard hooks (`SetWindowsHookEx`) or silently holding clipboard handles (`GetClipboardOwner`).
- **🔌 BadUSB & 📜 Root Certificate & 🔐 Account Tampering**: Alerts on newly plugged composite USB-HID devices, unauthorized Root CA injections (MITM detection), Event IDs `4625` (brute-force logon failures) / `4720` (new accounts), and `Administrators` group modifications.

### 5. 🤖 One-Click AI SOC Analyst Prompt Generator (Privacy-First)
- **Structured Diagnostic Prompts**: Turns complex security telemetry or full-PC health snapshots into an expert-engineered prompt ready for ChatGPT, Claude, or Gemini.
- **Automatic Privacy Sanitization**: Masks your hostname (`[MY_PC]`), Windows username (`[USER_NAME]`), and private LAN IPs (`192.168.x.x`) before copying to the clipboard—so you never leak sensitive PII to external LLMs.

### 6. 🔋 Battery & Power-Saving Consideration (Configurable Scan Intervals)
- **Flexible Scan Frequency**: Choose between "Fast: 3s", "Standard: 5s", and "Power Saving: 15s" from the Settings dialog to optimize laptop battery life.
- **Automatic Heavy Scan Scaling**: Resource-intensive deep scans (Task Scheduler COM enumeration, service inspection, registry search) scale proportionally (18s / 30s / 90s), and sniper polling intervals adapt automatically to minimize CPU wakeups without sacrificing short-lived process detection.

---

## 🚀 Installation & Quick Start

### System Requirements
- **OS**: Windows 11 (x64 recommended; also compatible with Windows 10)
- **Runtime**: [.NET 8.0 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0) (required for running binaries / MSI installer; .NET 8 SDK required for building from source)
- **Privileges**: Standard user works for basic monitoring; **Run as Administrator** is recommended for full Security Event Log (`4625`/`4720`) and system-wide process command-line inspection.

---

### 📦 For End Users: Install via MSI Installer (Recommended & Easiest)
For users without development tools (.NET SDK or Git), using the pre-built installer is the simplest approach.

1. Download the latest **`AnzenSecurityWatcher-Setup-*-x64.msi`** from the **[Releases](../../releases)** page.
2. Run the downloaded MSI file and follow the setup wizard.
   - Shortcuts are automatically created on the Desktop and Start Menu.
   - After installation, right-click the shortcut and select **"Run as administrator"**.

---

### 🛠️ For Developers: Build and Run from Source
For developers and security analysts who want to inspect the source code, customize rules, or contribute. (*[.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) is required.*)

#### Step 1: Clone the repository
```powershell
git clone https://github.com/sdozono/Anzen-Security-Watcher.git
cd anzen-security-watcher
```

#### Step 2: Launch the application (Two options)
- **Option A: One-click Launch via Batch Script**  
  Double-click **`run-watcher.bat`** in the project root.  
  *(On first run, it automatically compiles and runs via `dotnet run --configuration Release`. Subsequent runs instantly launch the compiled binary `bin\Release\net8.0-windows\AnzenSecurityWatcher.exe`.)*

- **Option B: Manual Build & Run via .NET CLI**  
  ```powershell
  dotnet build --configuration Release
  dotnet run --configuration Release
  ```

#### (Optional) Building the MSI Installer Locally
To build the MSI installer package locally using WiX Toolset v5:
```powershell
powershell -ExecutionPolicy Bypass -File .\build-installer.ps1
```
*(Outputs `installer\output\AnzenSecurityWatcher-Setup-*-x64.msi`)*

---

## 🎙️ A Message from the Creator

> *"Over two decades of engineering mission-critical systems, I have seen firsthand how opaque modern operating systems can feel to everyday users and engineers. Traditional security tools often operate as black boxes, making it difficult to understand what is truly happening behind the scenes.*  
> *While I built **Anzen Security Watcher** as an open-source tool for individual peace of mind, **if you are interested in applying these ideas—such as enterprise-wide deployment, centralized fleet management across thousands of PCs, or closed-network private AI integrations—please feel free to reach out and connect.**"*

---

## 🤝 Contributing & Inquiries

Anzen Security Watcher is an open-source project licensed under the MIT License. Individual feedback, code contributions, and enterprise inquiries are all warmly welcomed!

- 💬 **Enterprise & Large-Scale Inquiries**: Interested in adapting these concepts for enterprise fleet management or custom deployments? Feel free to start a conversation via [GitHub Discussions](../../discussions) or [GitHub Issues](../../issues).
- 🐛 **Issue Tracker**: Submit bug reports or feature requests via [GitHub Issues](../../issues).
- 🛠️ **Pull Requests**: Code contributions and improvements are always appreciated.

---

## 📄 License

This project is licensed under the **[MIT License](./LICENSE)**.

---

<div align="center">
  <sub>Built with ❤️ and 20 years of engineering craftsmanship as an open-source personal project.</sub>
</div>
