<div align="center">

# 🛡️ Anzen Security Watcher（安全终端卫士）

**洞悉隐秘连接，捕捉 0.05 秒瞬时终端，阻断静默屏幕泄露——让每个人都能拥有 AI 驱动的终端安全可视性。**

*基于原生 C# / .NET 8 WPF 打造的超轻量级 Windows 11 实时安全雷达与 AI SOC 诊断助手*

[![Language: English](https://img.shields.io/badge/Language-English-0078D4?style=for-the-badge)](./README.md)
[![Language: 日本語](https://img.shields.io/badge/言語-日本語-DC143C?style=for-the-badge)](./README.ja.md)
[![Language: 简体中文](https://img.shields.io/badge/语言-简体中文-DE2910?style=for-the-badge)](./README.zh-CN.md)
[![Language: Español](https://img.shields.io/badge/Idioma-Español-FFC400?style=for-the-badge)](./README.es.md)

[![Platform](https://img.shields.io/badge/Platform-Windows%2011-0078D6?style=flat-square&logo=windows11)](https://www.microsoft.com/windows)
[![Runtime](https://img.shields.io/badge/.NET-8.0%20WPF-512BD4?style=flat-square&logo=dotnet)](https://dotnet.microsoft.com/)
[![Architecture](https://img.shields.io/badge/Engine-Win32%20%26%20NT%20Native%20API-00A4EF?style=flat-square)](#核心功能五大监控引擎)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](./LICENSE)

</div>

---

## 🌍 选择语言 / Choose Your Language

- 🇺🇸 **[English (Default)](./README.md)**
- 🇯🇵 **[日本語 (Japanese)](./README.ja.md)**
- 🇨🇳 **[简体中文 (Simplified Chinese)](./README.zh-CN.md)** — 当前语言
- 🇪🇸 **[Español (Spanish)](./README.es.md)**

---

## 💡 项目概述：为什么选择 Anzen Security Watcher？

在使用电脑时，您是否遇到过**黑色命令窗口（CMD 或 PowerShell）仅仅闪烁了 0.2 秒就瞬间消失**，让您怀疑“到底是系统正常更新，还是恶意木马刚刚执行了命令”？  
您是否担心过自己的屏幕正在被后台远控软件悄悄直播，或者想知道电脑此时此刻正在与哪个国家的服务器通信？

传统的杀毒软件就像一个“黑盒”，在报警之前您对系统内部发生的一切一无所知；而企业级 EDR 方案又过于昂贵、臃肿，普通用户和中小型技术团队难以部署。

**Anzen Security Watcher**（“Anzen”在日语中意为“安全”）是由一名拥有 **20 年关键系统开发经验的资深系统架构师**作为个人开源项目倾力打造的免费工具。它通过底层 Win32 / NT 原生 API 将复杂的系统遥测数据转化为直观的实时仪表盘，并能将可疑日志一键转化为经过隐私脱敏的 **AI 诊断提示词（Prompt）**，让您随时调用 ChatGPT、Claude 或 Gemini 获得专家级的安全分析。

---

## 🎯 适用人群与核心价值

| 目标读者 | Anzen Security Watcher 为您带来的价值 |
| :--- | :--- |
| 🧑‍💻 **普通电脑用户与远程办公人员** | 实时检测摄像头、麦克风及屏幕共享状态，一旦发生未知远程控制立即置顶弹窗告警；通过 **100 分制安全评分（A–E 级）**直观了解电脑健康度，遇到可疑现象一键复制提问 AI。 |
| 🛡️ **IT 管理员、运维与蓝队安全人员** | 无需安装高风险内核驱动，即可实现 **50 毫秒（0.05 秒）瞬时终端抓拍**、PowerShell Base64（`-enc`）自动解码、C2 周期性信标（Beacon）统计检测以及未签名 DLL 侧加载排查。 |
| 🏢 **团队管理员与远程办公团队** | 实时掌控远程办公与业务电脑中意外发生的屏幕共享、非法远程控制及隐秘外联，及时排查潜在的数据泄露与安全隐患。 |
| ⚙️ **开发者与安全研究人员** | 干净、高效的原生 C# / .NET 8 WPF 源码，完整展示 Win32 IP Helper API、`NtQueryInformationProcess`、WTS 会话监控及变异系数（$CV = \sigma / \mu$）信标检测算法。 |

---

## ✨ 核心功能（五大监控引擎）

### 1. 🌐 TCP / UDP 国家/地区级实时通信监控
- **进程级套接字精准映射**：调用 Win32 IP Helper API (`GetExtendedTcpTable` / `GetExtendedUdpTable`)，实时获取所有活动的 TCP 连接与 UDP 端点，并精确绑定到对应的 PID、进程名称及可执行文件路径。
- **混合式 GeoIP 引擎**：结合本地局域网/主流云厂商 CIDR 离线毫秒级识别与免 API Key 的异步 GeoIP 查询（`ipwho.is` / `ip-api.com`），并持久化缓存至本地（`Data/geoip_cache.json`）。
- **一键国家/地区过滤**：点击界面顶部的**国家汇总卡片**，即可一键筛选与特定国家/地区的全部网络通信。
- **高危通信自动高亮**：自动标红由命令行工具（`powershell`, `cmd`, `rundll32`, `mshta` 等 LOLBins）发起的外部连接、高危端口（`3389`, `5900`, `4444` 等）以及敏感地区的通信。

### 2. 🖥️ 远程屏幕共享与 RDP 实时检测（置顶弹窗强提醒）
- **Windows RDP 多维检测**：综合监控 WTS API (`WTSEnumerateSessions` / `WTSQuerySessionInformation`)、`GetSystemMetrics(SM_REMOTESESSION)`、`rdpclip.exe` 进程及 `3389` 端口状态。
- **精准区分远控软件“后台待机”与“正在传输屏幕 (ACTIVE)”**：支持监控 AnyDesk, TeamViewer, UltraVNC / TightVNC / RealVNC, RustDesk, Chrome Remote Desktop, Windows 快速助手, Parsec, Splashtop, ScreenConnect, LogMeIn 等，智能识别软件是仅在后台静默运行，还是**已建立外部会话并正在实时外传您的屏幕画面**。
- **视频会议屏幕共享检测**：利用 Win32 `EnumWindows` 实时捕捉 Zoom 屏幕采集进程（`CptHost.exe` 及绿框窗口类 `ZPFTEWndClass`）、Microsoft Teams、Discord、Slack 及浏览器的屏幕共享指示器。
- **防忽略置顶告警**：一旦检测到屏幕外传，主界面顶部横幅立即变为红色警告，同时在**屏幕右下角弹出最前端（Topmost）警示窗**并发送 Windows 系统托盘通知。

### 3. ⚡ 进程与命令行监控（50ms 瞬时终端抓拍 & 周期性信标 & 混淆还原）
- **⚡ 50ms 瞬时终端狙击手监控**：基于 Win32 `CreateToolhelp32Snapshot` 的 **0.05 秒（50 毫秒）**超高速轮询，精准捕获在屏幕上仅闪现 0.1–0.3 秒就消失的短命进程，完整记录其**命令行参数**、**父进程（如 `svchost/Schedule` 或 `WmiPrvSE`）**、**存活时间（毫秒）**及**同时间触发的计划任务名称**。
- **⏰ 最近 60 分钟计划任务一键溯源**：点击“⏰ 调查最近任务”按钮，即可扫描 Windows 任务计划程序的所有目录（含 `\Microsoft\Windows`），快速揪出触发瞬时弹窗的幕后任务。
- **周期性进程检测（C2 信标排查）**：追踪进程启动时间戳历史，计算平均间隔 ($\mu$)、标准差 ($\sigma$) 与变异系数 ($CV = \sigma / \mu$)，自动揪出按固定周期唤醒的隐藏任务或木马信标。
- **罕见/首次出现/未签名进程识别**：与初始基线（`Data/process_baseline.json`）对比，提取在 `Temp`、`Downloads`、`AppData` 等目录中无数字签名运行的可疑程序。
- **深度命令行解析与自动解码**：通过 NT API (`NtQueryInformationProcess`) 提取完整参数，自动解码 PowerShell Base64 混淆指令（`-enc`），实时检测 `IEX`、`DownloadString`、卷影副本删除（`vssadmin delete shadows`）及 Office 文档拉起的异常 Shell。

### 4. 🛡️ 100 分制系统防御评分与 10 维主机安全审计
- **📊 安全配置自动评分（满分 100 分 / A–E 评级）**：自动审计 Microsoft Defender 实时保护、Windows 防火墙、UAC、SmartScreen、RDP/NLA、UEFI 安全启动、SMBv1 禁用状态、自动播放拦截、`hosts` 文件篡改及代理服务器劫持等 10 项指标，并支持一键跳转系统设置进行加固。
- **🚀 自启动（持久化）监控**：全面扫描 `Run`/`RunOnce` 注册表、启动文件夹、`Winlogon` (`Shell`/`Userinit`)、`IFEO` (`Debugger`)、系统服务与计划任务，对比基线发现恶意驻留。
- **🧩 DLL 侧加载（Sideloading）检测**：发现与具有合法数字签名的 EXE 放置在同一目录下的未签名可疑 DLL。
- **📷 摄像头与麦克风实时占用监控**：读取 `CapabilityAccessManager\ConsentStore` 注册表，精准定位当前正在使用摄像头或麦克风的应用（`LastUsedTimeStop == 0`）。
- **🎹 键盘记录器迹象 & 📋 剪贴板监听检测**：检测导入全局键盘钩子（`SetWindowsHookEx`）的非标准进程，以及在后台频繁读取或占用剪贴板的可疑程序。
- **🔌 BadUSB、📜 根证书篡改与 🔐 账户安全监控**：监控新接入的复合型 USB/HID 键盘设备、受信任根证书颁发机构存储中的异常新增证书（防范 HTTPS 中间人劫持）、安全事件日志 ID `4625`（登录失败暴力破解）/`4720`（新建账户）以及本地 `Administrators` 管理员组变更。

### 5. 🤖 一键生成 AI 安全诊断提示词（内置隐私脱敏）
- **结构化 SOC 专家提示词**：将捕获到的可疑安全事件或全机健康快照自动排版为结构化 Prompt，可直接粘贴至 ChatGPT、Claude 或 Gemini 获取深度分析。
- **自动隐私脱敏掩码**：在复制前自动将您的计算机名（`[MY_PC]`）、Windows 用户名（`[USER_NAME]`）及内网私有 IP（`192.168.x.x`）替换为脱敏标签，确保企业与个人隐私绝不外泄。

### 6. 🔋 针对笔记本电池与省电环境的优化（可调扫描间隔）
- **灵活的扫描频率选择**：在设置窗口中提供「高速: 3秒」、「标准: 5秒」与「省电: 15秒」三种档位，满足不同硬件与使用场景下的续航需求。
- **重型扫描联动扩展**：计划任务 COM 遍历、全系统服务枚举、注册表检索等高耗能详细扫描周期自动按比例联动（18秒 / 30秒 / 90秒），瞬时终端阻击循环的等待间隔也会自动调整，在保证瞬时异常捕捉力的同时大幅降低 CPU 唤醒频率与电量消耗。

---

## 🚀 安装与快速启动

### 运行环境要求
- **操作系统**：Windows 11（推荐 64 位，同样兼容 Windows 10）
- **运行库**：[.NET 8.0 桌面运行时 (Desktop Runtime)](https://dotnet.microsoft.com/zh-cn/download/dotnet/8.0)（运行 MSI 安装版或二进制文件所需；从源码编译则需要 [.NET 8 SDK](https://dotnet.microsoft.com/zh-cn/download/dotnet/8.0)）
- **权限建议**：普通用户权限即可运行基础监控；建议**“以管理员身份运行”**以启用完整的安全事件日志（`4625`/`4720`）读取与全局进程命令行分析。

---

### 📦 面向普通用户：通过 MSI 安装包安装（推荐・最便捷）
对于未配置开发环境（.NET SDK 或 Git）的用户，推荐直接下载安装包：

1. 前往 **[Releases](../../releases)** 页面下载最新的 **`AnzenSecurityWatcher-Setup-*-x64.msi`** 安装包。
2. 双击运行 MSI 文件，根据向导完成安装。
   - 程序将自动在桌面与开始菜单创建快捷方式。
   - 安装完成后，请右键单击快捷方式并选择**“以管理员身份运行”**启动。

---

### 🛠️ 面向开发者：从源码构建与运行
适用于需要审查代码、自定义规则或参与贡献的开发者与安全研究员。（需安装 [.NET 8 SDK](https://dotnet.microsoft.com/zh-cn/download/dotnet/8.0)）

#### 1. 克隆代码仓库
```powershell
git clone https://github.com/sdozono/Anzen-Security-Watcher.git
cd anzen-security-watcher
```

#### 2. 启动应用程序（两种方式）
- **方式 A：通过批处理脚本一键启动**  
  双击项目根目录下的 **`run-watcher.bat`**。  
  *(首次运行时会自动调用 `dotnet run --configuration Release` 编译并启动；编译完成后，后续运行将直接快速启动二进制文件 `bin\Release\net8.0-windows\AnzenSecurityWatcher.exe`)*

- **方式 B：使用 .NET CLI 手动构建与运行**  
  ```powershell
  dotnet build --configuration Release
  dotnet run --configuration Release
  ```

#### （参考）本地构建 MSI 安装包
若需要使用 WiX Toolset v5 在本地打包生成 MSI 安装程序，可执行附带的脚本：
```powershell
powershell -ExecutionPolicy Bypass -File .\build-installer.ps1
```
*(将生成 `installer\output\AnzenSecurityWatcher-Setup-*-x64.msi`)*

---

## 🎙️ 来自开发者的一封信（Developer's Message）

> *“在从事关键任务系统开发的 20 年间，我深刻体会到现代操作系统对于普通用户和一线工程师来说往往像一个‘黑盒’，很难看清后台到底在运行什么。*  
> *尽管我将 **Anzen Security Watcher** 作为个人开源项目发布，以帮助大家获得透明的安全可视性，但**如果您希望将这里的思路与技术架构应用到企业级场景、数千台员工电脑的集中管控、或内网私有化 AI 联动中，非常欢迎随时联系与交流！**”*

---

## 🤝 参与贡献与咨询交流（Contributing & Inquiries）

本项目为基于 MIT 协议的个人开源项目。欢迎个人日常使用，也十分欢迎企业应用探讨与代码贡献！

- 💬 **企业级应用与方案咨询**：如果您有意将本项目的理念或架构应用于企业多终端管理、私有化部署等场景，欢迎通过 [GitHub Discussions](../../discussions) 或 [GitHub Issues](../../issues) 随时联系交流。
- 🐛 **问题反馈与需求建议**：欢迎在 [GitHub Issues](../../issues) 提交反馈。
- 🛠️ **Pull Request**：欢迎提交代码改进与功能扩展。

---

## 📄 开源许可证（License）

本项目基于 **[MIT License](./LICENSE)** 开源发布。

---

<div align="center">
  <sub>由资深架构师凝聚 20 年工程匠心倾力打造的个人开源项目 ❤️</sub>
</div>
