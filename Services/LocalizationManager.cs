using System.Windows;

namespace AnzenSecurityWatcher.Services;

public enum AppLanguage
{
    English = 0,  // Default
    Chinese = 1,  // 简体中文
    Spanish = 2,  // Español
    Japanese = 3  // 日本語
}

/// <summary>
/// Shorthand helper for 4-language inline localization: English (Default), Chinese, Spanish, Japanese.
/// </summary>
public static class Loc
{
    public static AppLanguage Current => LocalizationManager.CurrentLanguage;

    public static string T(string en, string zh, string es, string ja) => LocalizationManager.CurrentLanguage switch
    {
        AppLanguage.Chinese => zh,
        AppLanguage.Spanish => es,
        AppLanguage.Japanese => ja,
        _ => en
    };
}

public static class LocalizationManager
{
    public static AppLanguage CurrentLanguage { get; private set; } = AppLanguage.English;

    public static event Action<AppLanguage>? OnLanguageChanged;

    public static string GetString(string key, string fallback = "")
    {
        if (System.Windows.Application.Current?.Resources.Contains(key) == true)
        {
            return System.Windows.Application.Current.Resources[key]?.ToString() ?? fallback;
        }
        return fallback;
    }

    public static void ApplyLanguage(AppLanguage language)
    {
        CurrentLanguage = language;

        var res = System.Windows.Application.Current?.Resources;
        if (res != null)
        {
            // Settings Window
            res["Loc_Settings_WindowTitle"] = Loc.T(
                "⚙️ Settings & Diagnostics — Anzen Security Watcher",
                "⚙️ 设置与诊断测试 — Anzen Security Watcher",
                "⚙️ Configuración y Pruebas — Anzen Security Watcher",
                "⚙️ 設定・動作テスト — Anzen Security Watcher");
            res["Loc_Settings_LangTitle"] = Loc.T(
                "🌐 Language / Idioma / 语言 / 言語",
                "🌐 界面语言 (Language)",
                "🌐 Idioma de la interfaz (Language)",
                "🌐 表示言語 (Language)");
            res["Loc_Settings_LangDesc"] = Loc.T(
                "Select the display language for the entire application (Default: English).",
                "切换整个应用程序的显示语言（默认：英语）。",
                "Seleccione el idioma de visualización de toda la aplicación (Predeterminado: Inglés).",
                "アプリ全体の表示言語を切り替えます（デフォルトは英語です）。");
            res["Loc_Settings_LangEn"] = Loc.T(
                "🇺🇸 English (Default)",
                "🇺🇸 English (英语 - 默认)",
                "🇺🇸 English (Inglés - Predet.)",
                "🇺🇸 English (英語 - デフォルト)");
            res["Loc_Settings_LangZh"] = Loc.T(
                "🇨🇳 中文 (Chinese)",
                "🇨🇳 中文 (简体中文)",
                "🇨🇳 中文 (Chino)",
                "🇨🇳 中文 (中国語)");
            res["Loc_Settings_LangEs"] = Loc.T(
                "🇪🇸 Español (Spanish)",
                "🇪🇸 Español (西班牙语)",
                "🇪🇸 Español (Español)",
                "🇪🇸 Español (スペイン語)");
            res["Loc_Settings_LangJa"] = Loc.T(
                "🇯🇵 日本語 (Japanese)",
                "🇯🇵 日本語 (日语)",
                "🇯🇵 日本語 (Japonés)",
                "🇯🇵 日本語");

            res["Loc_Settings_ThemeTitle"] = Loc.T(
                "🎨 Appearance & Theme",
                "🎨 外观与主题设置",
                "🎨 Apariencia y Tema",
                "🎨 外観・テーマ設定");
            res["Loc_Settings_ThemeDesc"] = Loc.T(
                "Switch the color theme for the application (follows Windows system setting by default).",
                "切换应用程序的整体配色方案（默认跟随 Windows 系统设置）。",
                "Cambie el esquema de colores de la aplicación (sigue la configuración de Windows por defecto).",
                "アプリ全体の配色を切り替えます（デフォルトはWindowsのシステム設定に追従します）。");
            res["Loc_Settings_ThemeSystem"] = Loc.T(
                "🔄 Follow System Setting (Default)",
                "🔄 跟随系统设置 (默认)",
                "🔄 Seguir configuración del sistema (Predeterminado)",
                "🔄 システム設定に追従 (デフォルト)");
            res["Loc_Settings_ThemeLight"] = Loc.T(
                "☀️ Light Mode (Bright color scheme)",
                "☀️ 浅色模式 (明亮配色)",
                "☀️ Modo Claro (Esquema claro)",
                "☀️ ライトモード (明るい配色)");
            res["Loc_Settings_ThemeDark"] = Loc.T(
                "🌙 Dark Mode (Dark color scheme)",
                "🌙 深色模式 (暗色配色)",
                "🌙 Modo Oscuro (Esquema oscuro)",
                "🌙 ダークモード (暗い配色)");

            res["Loc_Settings_ScanIntervalTitle"] = Loc.T(
                "🔋 Scan Interval & Power Saving",
                "🔋 扫描间隔与省电设置",
                "🔋 Intervalo de escaneo y ahorro de energía",
                "🔋 スキャン間隔 / 省電力設定");
            res["Loc_Settings_ScanIntervalDesc"] = Loc.T(
                "Adjust scan intervals to optimize battery life on laptops. Detailed scans (Task Scheduler COM, service enumeration, registry) scale automatically.",
                "调整扫描频率以节省笔记本电池电量。详细扫描（计划任务 COM、服务枚举、注册表检索）将自动按比例联动调整。",
                "Ajuste la frecuencia de escaneo para ahorrar batería en portátiles. Los escaneos detallados (COM de tareas, servicios, registro) se adaptan automáticamente.",
                "ノートPC等のバッテリー消費を抑えるため、監視間隔を設定します。詳細スキャン（タスクスケジューラCOM探索、全サービス列挙、レジストリ探索）も自動的に連動して調整されます。");
            res["Loc_Settings_ScanIntervalFast"] = Loc.T(
                "⚡ Fast: 3s (Detailed: 18s) — Default, high responsiveness",
                "⚡ 高速: 3秒 (详细扫描: 18秒) — 默认，高实时性",
                "⚡ Rápido: 3s (Detallado: 18s) — Predeterminado, alta respuesta",
                "⚡ 高速: 3秒 (詳細スキャン: 18秒) — デフォルト、高感度");
            res["Loc_Settings_ScanIntervalStandard"] = Loc.T(
                "⏱️ Standard: 5s (Detailed: 30s) — Balanced performance & CPU usage",
                "⏱️ 标准: 5秒 (详细扫描: 30秒) — 兼顾性能与 CPU 占用",
                "⏱️ Estándar: 5s (Detallado: 30s) — Rendimiento y consumo equilibrados",
                "⏱️ 標準: 5秒 (詳細スキャン: 30秒) — 性能と負荷のバランス型");
            res["Loc_Settings_ScanIntervalPowerSaving"] = Loc.T(
                "🔋 Power Saving: 15s (Detailed: 90s) — Recommended for battery operation",
                "🔋 省电: 15秒 (详细扫描: 90秒) — 推荐笔记本电池供电",
                "🔋 Ahorro de energía: 15s (Detallado: 90s) — Recomendado para batería",
                "🔋 省電力: 15秒 (詳細スキャン: 90秒) — ノートPC・バッテリー駆動に推奨");

            res["Loc_Settings_OptionsTitle"] = Loc.T(
                "📡 Network Monitoring & AI Output Options",
                "📡 网络监控与 AI 输出选项",
                "📡 Opciones de Monitoreo de Red y Salida de IA",
                "📡 ネットワーク監視・AI出力オプション");
            res["Loc_Settings_OptLoopback"] = Loc.T(
                "🏠 Show localhost (127.0.0.1) internal traffic",
                "🏠 显示本地主机 (127.0.0.1) 内部通信",
                "🏠 Mostrar tráfico interno de localhost (127.0.0.1)",
                "🏠 ローカルホスト (127.0.0.1) の内部通信も表示する");
            res["Loc_Settings_OptListen"] = Loc.T(
                "📡 Show ports in LISTEN state",
                "📡 显示处于 LISTEN 监听状态的端口",
                "📡 Mostrar puertos en estado LISTEN",
                "📡 LISTEN 待機状態のポートも表示する");
            res["Loc_Settings_OptUdp"] = Loc.T(
                "📡 Monitor and list UDP endpoints",
                "📡 监控并列出 UDP 端点",
                "📡 Monitorear y listar puntos finales UDP",
                "📡 UDP エンドポイントも監視・一覧表示する");
            res["Loc_Settings_OptDllSideload"] = Loc.T(
                "🧩 Check DLL sideloading (signed EXE + unsigned DLL) (Default: Off)",
                "🧩 检查 DLL 侧加载（已签名 EXE + 未签名 DLL）（默认：关闭）",
                "🧩 Comprobar carga lateral de DLL (EXE firmado + DLL sin firmar) (Predet.: Off)",
                "🧩 DLLサイドロード（署名EXE＋未署名DLL）をチェックする (デフォルト: オフ)");
            res["Loc_Settings_OptMaskPii"] = Loc.T(
                "🔒 Automatically mask PC name, username & local IP in AI prompts (Recommended)",
                "🔒 在 AI 咨询提示词中自动隐藏电脑名、用户名和本地 IP（推荐）",
                "🔒 Ocultar automáticamente nombre de PC, usuario e IP local en prompts de IA (Recomendado)",
                "🔒 AI相談プロンプトでPC名・ユーザー名・ローカルIPを自動マスクする (推奨)");
            res["Loc_Settings_OptDisableOnlineGeoIp"] = Loc.T(
                "🛡️ Disable online GeoIP lookups (Offline / air-gapped mode - Prevents sending IPs externally)",
                "🛡️ 完全禁用在线 GeoIP 查询（离线/隔离网络模式 - 彻底禁止向外部发送 IP 地址）",
                "🛡️ Deshabilitar consulta GeoIP en línea (Modo sin conexión / aislado - Evita enviar IPs al exterior)",
                "🛡️ オンラインGeoIP照会を完全に無効化する (オフライン専用/エアギャップ環境向け - 外部へのIP送信を遮断)");

            res["Loc_Settings_SimTitle"] = Loc.T(
                "🧪 Alert & Anomaly Detection Simulation Tests",
                "🧪 警报与异常检测模拟测试",
                "🧪 Pruebas de Simulación de Alertas y Detección de Anomalías",
                "🧪 警報・異常検知の動作テスト (模擬発報)");
            res["Loc_Settings_SimDesc"] = Loc.T(
                "Test alert popups, top banner warnings, and periodic process detection without running real remote tools (*simulated data is excluded from AI consultation logs).",
                "无需启动真实的远程工具或可疑进程，即可测试警告弹窗、顶部横幅和周期性进程检测（※模拟数据不会混入 AI 咨询日志）。",
                "Pruebe ventanas emergentes de alerta, banners superiores y detección de procesos periódicos sin ejecutar herramientas remotas reales (*los datos simulados no se incluyen en los registros de IA).",
                "実際にリモート操作ツールや不審プロセスを起動せずに、警告ポップアップ・上部バナー・周期プロセス検知の動作をテストできます（※AI相談ログには混入しません）。");
            res["Loc_Settings_SimAllBtn"] = Loc.T(
                "🚨 Trigger All Simulations (Screen Share Alert + Periodic/Unknown Processes)",
                "🚨 一键触发全部模拟警报（屏幕共享警报 + 周期/未知进程注入）",
                "🚨 Activar Todas las Simulaciones (Alerta de Pantalla + Procesos Periódicos/Desconocidos)",
                "🚨 一括テスト発報 (画面共有アラート ＋ 周期/未知プロセス注入)");
            res["Loc_Settings_SimIndividualLabel"] = Loc.T(
                "Individual Simulation Tests:",
                "单项模拟测试:",
                "Pruebas de Simulación Individuales:",
                "個別テスト発報:");
            res["Loc_Settings_SimAnyDeskBtn"] = Loc.T(
                "🖥️ AnyDesk Leak Test",
                "🖥️ AnyDesk 外泄测试",
                "🖥️ Prueba de AnyDesk",
                "🖥️ AnyDesk 流出テスト");
            res["Loc_Settings_SimZoomBtn"] = Loc.T(
                "📹 Zoom Screen Share Test",
                "📹 Zoom 屏幕共享测试",
                "📹 Prueba de Zoom",
                "📹 Zoom 画面共有テスト");
            res["Loc_Settings_SimRdpBtn"] = Loc.T(
                "🔑 Windows RDP Test",
                "🔑 Windows RDP 连接测试",
                "🔑 Prueba de Windows RDP",
                "🔑 Windows RDP 接続テスト");
            res["Loc_Settings_SimProcessBtn"] = Loc.T(
                "⚡ Flash Terminal & Periodic Test",
                "⚡ 瞬时终端与周期进程测试",
                "⚡ Terminal Fugaz y Periódico",
                "⚡ 瞬間ターミナル・周期テスト");
            res["Loc_Settings_SimDefenseBtn"] = Loc.T(
                "🛡️ System Defense Test (Obfuscated Cmd, Autostart, Webcam, BadUSB, Cert, Admin)",
                "🛡️ 系统防御测试（混淆命令、自启动、摄像头、BadUSB、证书、管理员添加）",
                "🛡️ Prueba de Defensa del Sistema (Cmd Ofuscado, Autoinicio, Cámara, BadUSB, Cert, Admin)",
                "🛡️ システム防御テスト (難読化コマンド・自動起動・カメラ・BadUSB・証明書・管理者追加)");
            res["Loc_Settings_ClearSimBtn"] = Loc.T(
                "🧹 Clear All Simulated Alerts & Test Data",
                "🧹 清除所有模拟警报与测试数据",
                "🧹 Limpiar Todas las Alertas y Datos de Simulación",
                "🧹 すべてのテスト警報・テストデータを解除");
            res["Loc_Settings_RealtimeNote"] = Loc.T(
                "Changes are applied in real time",
                "更改内容将实时生效",
                "Los cambios se aplican en tiempo real",
                "変更内容はリアルタイムに反映されます");
            res["Loc_Settings_CloseBtn"] = Loc.T(
                "Close",
                "关闭",
                "Cerrar",
                "閉じる");

            // AlertPopupWindow
            res["Loc_Alert_WindowTitle"] = Loc.T(
                "🚨 Screen Share & Remote Access Warning",
                "🚨 屏幕共享与远程连接警告",
                "🚨 Alerta de Pantalla Compartida y Conexión Remota",
                "🚨 画面共有・リモート接続 警告");
            res["Loc_Alert_Badge"] = Loc.T(
                "🚨 Screen Leak / Share Detected",
                "🚨 检测到屏幕外泄/共享",
                "🚨 Pantalla Compartida Detectada",
                "🚨 画面流出・共有検知");
            res["Loc_Alert_InspectBtn"] = Loc.T(
                "🔍 Inspect in Monitor",
                "🔍 在监控界面查看详情",
                "🔍 Ver detalles en el monitor",
                "🔍 監視画面で詳細を見る");
            res["Loc_Alert_AckCloseBtn"] = Loc.T(
                "Acknowledge (Close)",
                "已知晓 (关闭)",
                "Entendido (Cerrar)",
                "確認済み (閉じる)");

            // MainWindow Menu Bar
            res["Loc_Menu_File"] = Loc.T("File(_F)", "文件(_F)", "Archivo(_F)", "ファイル(_F)");
            res["Loc_Menu_File_Snapshot"] = Loc.T(
                "📸 Add Full PC Snapshot to AI Consultation(_S)",
                "📸 将当前电脑完整快照添加到 AI 咨询(_S)",
                "📸 Añadir instantánea completa del PC a consulta IA(_S)",
                "📸 現在のPC全体スナップショットをAI相談へ追加(_S)");
            res["Loc_Menu_File_CopyPrompt"] = Loc.T(
                "📋 Copy AI Consultation Prompt to Clipboard(_C)",
                "📋 复制 AI 咨询提示词到剪贴板(_C)",
                "📋 Copiar prompt de consulta IA al portapapeles(_C)",
                "📋 AI相談用プロンプトをクリップボードにコピー(_C)");
            res["Loc_Menu_File_Exit"] = Loc.T("❌ Exit(_X)", "❌ 退出(_X)", "❌ Salir(_X)", "❌ 終了(_X)");

            res["Loc_Menu_Monitor"] = Loc.T("Monitor(_M)", "监控操作(_M)", "Monitoreo(_M)", "監視操作(_M)");
            res["Loc_Menu_Monitor_Refresh"] = Loc.T(
                "🔄 Scan & Refresh Now(_R)",
                "🔄 立即扫描刷新(_R)",
                "🔄 Escanear y actualizar ahora(_R)",
                "🔄 今すぐスキャン更新(_R)");
            res["Loc_Menu_Monitor_Pause"] = Loc.T(
                "⏸️ Pause Monitoring(_P)",
                "⏸️ 暂停监控(_P)",
                "⏸️ Pausar monitoreo(_P)",
                "⏸️ 監視の一時停止(_P)");
            res["Loc_Menu_Monitor_ClearSim"] = Loc.T(
                "🧹 Clear All Simulated Alerts(_L)",
                "🧹 清除所有模拟警报(_L)",
                "🧹 Limpiar todas las alertas simuladas(_L)",
                "🧹 テスト発報をすべて解除(_L)");

            res["Loc_Menu_View"] = Loc.T("View(_V)", "视图(_V)", "Ver(_V)", "表示(_V)");
            res["Loc_Menu_View_Tab0"] = Loc.T(
                "🌐 1. Country Traffic Monitor (TCP/UDP)",
                "🌐 1. 国家/地区通信监控 (TCP/UDP)",
                "🌐 1. Monitor de Tráfico por País (TCP/UDP)",
                "🌐 1. 国別通信モニター (TCP/UDP)");
            res["Loc_Menu_View_Tab1"] = Loc.T(
                "🖥️ 2. Screen Share & RDP Monitor",
                "🖥️ 2. 屏幕共享与 RDP 监控",
                "🖥️ 2. Monitor de Pantalla Compartida y RDP",
                "🖥️ 2. 画面共有・RDP監視");
            res["Loc_Menu_View_Tab2"] = Loc.T(
                "⚙️ 3. Process & Command Line Monitor",
                "⚙️ 3. 进程与命令行监控",
                "⚙️ 3. Monitor de Procesos y Línea de Comandos",
                "⚙️ 3. プロセス・コマンドライン監視");
            res["Loc_Menu_View_Tab3"] = Loc.T(
                "🛡️ 4. System Defense & Security Score",
                "🛡️ 4. 系统防御与安全评分",
                "🛡️ 4. Defensa del Sistema y Puntuación",
                "🛡️ 4. システム防御・安全スコア");
            res["Loc_Menu_View_Tab4"] = Loc.T(
                "🤖 5. AI Consultation Logs",
                "🤖 5. AI 安全咨询日志",
                "🤖 5. Registros para Consulta IA",
                "🤖 5. AIに相談すべきログ");

            res["Loc_Menu_Tools"] = Loc.T("Windows Tools(_T)", "Windows 工具(_T)", "Herramientas de Windows(_T)", "Windowsツール(_T)");
            res["Loc_Tool_TaskMgr"] = Loc.T(
                "📊 Task Manager (taskmgr)",
                "📊 任务管理器 (taskmgr)",
                "📊 Administrador de tareas (taskmgr)",
                "📊 タスクマネージャー (taskmgr)");
            res["Loc_Tool_EventVwr"] = Loc.T(
                "📋 Event Viewer (eventvwr.msc)",
                "📋 事件查看器 (eventvwr.msc)",
                "📋 Visor de eventos (eventvwr.msc)",
                "📋 イベントビューアー / イベントマネージャー (eventvwr.msc)");
            res["Loc_Tool_DevMgmt"] = Loc.T(
                "🔌 Device Manager (devmgmt.msc)",
                "🔌 设备管理器 (devmgmt.msc)",
                "🔌 Administrador de dispositivos (devmgmt.msc)",
                "🔌 デバイスマネージャー (devmgmt.msc)");
            res["Loc_Tool_Control"] = Loc.T(
                "🎛️ Control Panel (control)",
                "🎛️ 控制面板 (control)",
                "🎛️ Panel de control (control)",
                "🎛️ コントロールパネル (control)");
            res["Loc_Tool_ResMon"] = Loc.T(
                "📈 Resource Monitor — Network & File Locks (resmon)",
                "📈 资源监视器 — 详细网络与文件锁定 (resmon)",
                "📈 Monitor de recursos — Red y bloqueo de archivos (resmon)",
                "📈 リソースモニター — 詳細通信・ファイルロック確認 (resmon)");
            res["Loc_Tool_Firewall"] = Loc.T(
                "🔥 Windows Firewall with Advanced Security (wf.msc)",
                "🔥 高级安全 Windows 防火墙 (wf.msc)",
                "🔥 Firewall de Windows con seguridad avanzada (wf.msc)",
                "🔥 Windows ファイアウォール詳細設定 — 通信遮断・規則確認 (wf.msc)");
            res["Loc_Tool_Defender"] = Loc.T(
                "🛡️ Windows Security / Defender — Scan & History",
                "🛡️ Windows 安全中心 / Defender — 扫描与保护历史",
                "🛡️ Seguridad de Windows / Defender — Escaneo e historial",
                "🛡️ Windows セキュリティ / Defender — スキャン・保護履歴");
            res["Loc_Tool_TaskSchd"] = Loc.T(
                "⏰ Task Scheduler — Inspect Periodic Tasks (taskschd.msc)",
                "⏰ 任务计划程序 — 排查周期性任务来源 (taskschd.msc)",
                "⏰ Programador de tareas — Investigar tareas periódicas (taskschd.msc)",
                "⏰ タスクスケジューラ — 周期プロセスの登録元調査 (taskschd.msc)");
            res["Loc_Tool_Services"] = Loc.T(
                "⚙️ Services — Stop/Disable Background Services (services.msc)",
                "⚙️ 服务管理 — 停止或禁用后台服务 (services.msc)",
                "⚙️ Servicios — Detener/deshabilitar servicios (services.msc)",
                "⚙️ サービス管理 — 常駐サービス停止・無効化 (services.msc)");
            res["Loc_Tool_StartupApps"] = Loc.T(
                "🚀 Startup Apps Settings — Review Autostart Apps",
                "🚀 启动应用设置 — 查看开机自启应用",
                "🚀 Aplicaciones de inicio — Revisar autoinicio",
                "🚀 スタートアップ アプリ設定 — 自動起動の確認");
            res["Loc_Tool_CertMgr"] = Loc.T(
                "📜 Certificate Manager — Inspect Root Certificates (certmgr.msc)",
                "📜 证书管理器 — 检查根证书 (certmgr.msc)",
                "📜 Administrador de certificados — Revisar certificados raíz (certmgr.msc)",
                "📜 ユーザー証明書マネージャー — ルート証明書確認 (certmgr.msc)");
            res["Loc_Tool_LusrMgr"] = Loc.T(
                "👑 Local Users and Groups — Inspect Admins (lusrmgr.msc)",
                "👑 本地用户和组 — 检查管理员账户 (lusrmgr.msc)",
                "👑 Usuarios y grupos locales — Revisar administradores (lusrmgr.msc)",
                "👑 ローカルユーザーとグループ管理 — 管理者確認 (lusrmgr.msc)");
            res["Loc_Tool_PrivacyCam"] = Loc.T(
                "📷 Camera Privacy Settings — Manage Camera Access",
                "📷 摄像头隐私设置 — 管理摄像头权限",
                "📷 Configuración de privacidad de cámara",
                "📷 カメラのプライバシー設定 — カメラ権限管理");
            res["Loc_Tool_PrivacyMic"] = Loc.T(
                "🎙️ Microphone Privacy Settings — Manage Mic Access",
                "🎙️ 麦克风隐私设置 — 管理麦克风权限",
                "🎙️ Configuración de privacidad de micrófono",
                "🎙️ マイクのプライバシー設定 — マイク権限管理");
            res["Loc_Tool_Ncpa"] = Loc.T(
                "🌐 Network Connections — Adapters & VPNs (ncpa.cpl)",
                "🌐 网络连接适配器 — 紧急断网与 VPN 检查 (ncpa.cpl)",
                "🌐 Conexiones de red — Adaptadores y VPN (ncpa.cpl)",
                "🌐 ネットワーク接続アダプター一覧 — 緊急切断・VPN確認 (ncpa.cpl)");
            res["Loc_Tool_AppWiz"] = Loc.T(
                "📦 Installed Programs & Features — Uninstall Apps (appwiz.cpl)",
                "📦 已安装的程序和功能 — 卸载可疑软件 (appwiz.cpl)",
                "📦 Programas y características — Desinstalar apps (appwiz.cpl)",
                "📦 インストール済みアプリと機能 — 不審ソフト削除 (appwiz.cpl)");
            res["Loc_Tool_NetPlWiz"] = Loc.T(
                "👥 User Accounts — Inspect Accounts (netplwiz)",
                "👥 用户账户管理 — 检查异常账户 (netplwiz)",
                "👥 Cuentas de usuario — Revisar cuentas (netplwiz)",
                "👥 ユーザーアカウント管理 — 不正アカウント確認 (netplwiz)");

            res["Loc_Menu_Settings"] = Loc.T("Settings(_S)", "设置(_S)", "Configuración(_S)", "設定(_S)");
            res["Loc_Menu_Help"] = Loc.T("Help(_H)", "帮助(_H)", "Ayuda(_H)", "ヘルプ(_H)");
            res["Loc_Menu_Help_About"] = Loc.T("ℹ️ About Anzen Security Watcher(_A)...", "ℹ️ 关于 Anzen Security Watcher(_A)...", "ℹ️ Acerca de Anzen Security Watcher(_A)...", "ℹ️ バージョン情報(_A)...");
            res["Loc_Tray_About"] = Loc.T("ℹ️ Version & About...", "ℹ️ 关于与版本信息...", "ℹ️ Acerca de / Versión...", "ℹ️ バージョン情報...");

            // About Window
            res["Loc_About_Title"] = Loc.T("About Anzen Security Watcher", "关于 Anzen Security Watcher", "Acerca de Anzen Security Watcher", "バージョン情報");
            res["Loc_About_AppDescription"] = Loc.T(
                "Windows 11 Real-Time Security Monitor & AI Diagnosis Assistant",
                "Windows 11 实时安全监控与 AI 诊断助手",
                "Monitoreo de seguridad en tiempo real y asistente de diagnóstico por IA para Windows 11",
                "Windows 11 リアルタイム・セキュリティ監視＆AI診断支援ツール");
            res["Loc_About_Version"] = Loc.T("Version", "版本", "Versión", "バージョン");
            res["Loc_About_Runtime"] = Loc.T(".NET Runtime", ".NET 运行环境", "Entorno .NET", ".NET 実行環境");
            res["Loc_About_OS"] = Loc.T("Operating System", "操作系统", "Sistema Operativo", "オペレーティングシステム");
            res["Loc_About_Architecture"] = Loc.T("Process Architecture", "进程架构", "Arquitectura de proceso", "プロセスアーキテクチャ");
            res["Loc_About_Privilege"] = Loc.T("Privilege Level", "运行权限", "Nivel de privilegio", "実行権限レベル");
            res["Loc_About_PrivilegeAdmin"] = Loc.T("Administrator (Elevated)", "管理员权限 (已提权)", "Administrador (Elevado)", "管理者権限 (昇格済み)");
            res["Loc_About_PrivilegeUser"] = Loc.T("Standard User", "标准用户", "Usuario estándar", "標準ユーザー");
            res["Loc_About_Developer"] = Loc.T("Project / Team", "项目 / 团队", "Proyecto / Equipo", "開発 / プロジェクト");
            res["Loc_About_License"] = Loc.T("License", "开源许可", "Licencia", "ライセンス");
            res["Loc_About_LicenseType"] = Loc.T("MIT License (Open Source)", "MIT 许可证 (开源)", "Licencia MIT (Código abierto)", "MIT License (オープンソース)");
            res["Loc_About_GitHub"] = Loc.T("GitHub Repository", "GitHub 仓库", "Repositorio de GitHub", "GitHub リポジトリ");
            res["Loc_About_Copyright"] = Loc.T("© 2026 Anzen Security Project. All rights reserved.", "© 2026 Anzen Security Project. 保留所有权利。", "© 2026 Anzen Security Project. Todos los derechos reservados.", "© 2026 Anzen Security Project. All rights reserved.");
            res["Loc_About_CopyInfo"] = Loc.T("📋 Copy System Info", "📋 复制环境信息", "📋 Copiar info del sistema", "📋 環境情報をコピー");
            res["Loc_About_Copied"] = Loc.T("System information copied to clipboard!", "系统环境信息已复制到剪贴板！", "¡Información del sistema copiada al portapapeles!", "システム環境情報をクリップボードにコピーしました！");
            res["Loc_About_Close"] = Loc.T("Close", "关闭", "Cerrar", "閉じる");

            // Global Banner
            res["Loc_Banner_DetailsBtn"] = Loc.T("Details", "详情", "Detalles", "詳細");
            res["Loc_Banner_ClearSimBtn"] = Loc.T("🧹 Clear Sim", "🧹 清除模拟", "🧹 Limpiar Sim", "🧹 テスト解除");

            // Tab 0: Country Traffic
            res["Loc_Tab0_Header"] = Loc.T("🌐 Country Traffic", "🌐 国家/地区通信", "🌐 Tráfico por País", "🌐 国別通信");
            res["Loc_Tab0_CountryHeader"] = Loc.T(
                "🗺️ Connections by Country (Click to filter)",
                "🗺️ 按国家/地区统计连接（点击筛选）",
                "🗺️ Conexiones por País (Clic para filtrar)",
                "🗺️ 国別通信集計 (クリックで絞り込み)");
            res["Loc_Tab0_ShowAllBtn"] = Loc.T("Show All", "显示全部", "Mostrar todo", "すべて表示");
            res["Loc_Tab0_SearchLabel"] = Loc.T("🔎 Search:", "🔎 搜索:", "🔎 Buscar:", "🔎 検索:");
            res["Loc_Tab0_RiskyOnly"] = Loc.T("⚠️ Attention Only", "⚠️ 仅显示需注意项", "⚠️ Solo atención", "⚠️ 要注意のみ");
            res["Loc_Tab0_ShowUdp"] = Loc.T("📡 Show UDP", "📡 显示 UDP", "📡 Mostrar UDP", "📡 UDPも表示");
            res["Loc_Btn_ToAi"] = Loc.T("🤖 To AI", "🤖 问 AI", "🤖 A IA", "🤖 AIへ");
            res["Loc_Btn_CopyIp"] = Loc.T("🔍 IP", "🔍 IP", "🔍 IP", "🔍 IP");
            res["Loc_Btn_CopyIp_Tooltip"] = Loc.T(
                "Check IP reputation & threat intelligence (AbuseIPDB, VirusTotal, etc.)",
                "查询 IP 威胁情报与信誉（AbuseIPDB、VirusTotal 等）",
                "Consultar inteligencia y reputación de IP (AbuseIPDB, VirusTotal, etc.)",
                "IPアドレスの脅威インテリジェンス調査 (AbuseIPDB, VirusTotal等)");
            res["Loc_Btn_PauseUpdate"] = Loc.T("⏸️ Pause Updates", "⏸️ 暂停刷新", "⏸️ Pausar", "⏸️ 更新一時停止");
            res["Loc_Btn_ResumeUpdate"] = Loc.T("▶️ Resume Updates", "▶️ 恢复刷新", "▶️ Reanudar", "▶️ 更新再開");
            res["Loc_Btn_PauseUpdate_Tooltip"] = Loc.T(
                "Pause automatic table updates to inspect or sort items without disruption",
                "暂停表格自动刷新，以便排序或仔细排查",
                "Pausar actualización automática para ordenar o inspeccionar",
                "自動更新を一時停止し、ソート順や選択行を固定して確認します");
            res["Loc_Btn_ResumeUpdate_Tooltip"] = Loc.T(
                "Resume automatic table updates and refresh with latest data",
                "恢复表格自动刷新并立即同步最新数据",
                "Reanudar actualización automática y sincronizar",
                "自動更新を再開し、最新データへ同期します");

            // Tab 1: Screen Share & RDP
            res["Loc_Tab1_Header"] = Loc.T("🖥️ Screen Share & RDP", "🖥️ 屏幕共享与 RDP", "🖥️ Pantalla y RDP", "🖥️ 画面共有・RDP");
            res["Loc_Tab1_CardRdpTitle"] = Loc.T("🖥️ Windows RDP", "🖥️ Windows 远程桌面 (RDP)", "🖥️ Windows RDP", "🖥️ Windows RDP");
            res["Loc_Tab1_CardRemoteTitle"] = Loc.T("🔑 AnyDesk / TV / VNC", "🔑 AnyDesk / TV / VNC 等", "🔑 AnyDesk / TV / VNC", "🔑 AnyDesk / TV / VNC等");
            res["Loc_Tab1_CardMeetingTitle"] = Loc.T("📹 Teams / Zoom Share", "📹 Teams / Zoom 屏幕共享", "📹 Compartir Teams / Zoom", "📹 Teams / Zoom 共有");
            res["Loc_Btn_KillProc"] = Loc.T("🛑 Kill", "🛑 结束", "🛑 Terminar", "🛑 終了");

            // Tab 2: Process Monitor
            res["Loc_Tab2_Header"] = Loc.T("⚙️ Process Monitor", "⚙️ 进程监控", "⚙️ Monitor de Procesos", "⚙️ プロセス監視");
            res["Loc_Tab2_FilterAnomaly"] = Loc.T(
                "🔥 Notable (Flash/Periodic/New)",
                "🔥 重点关注 (瞬时/周期/首次)",
                "🔥 Destacados (Fugaz/Periódico/Nuevo)",
                "🔥 注目 (瞬間窓/周期/初出)");
            res["Loc_Tab2_FilterTransient"] = Loc.T(
                "⚡ Flash Terminal / Short-lived (0.3s)",
                "⚡ 瞬时终端/短命进程 (0.3秒捕捉)",
                "⚡ Terminal Fugaz / Corto (0.3s)",
                "⚡ 瞬間ターミナル/短命 (0.3秒捕捉)");
            res["Loc_Tab2_FilterPeriodic"] = Loc.T("⏱️ Periodic Only", "⏱️ 仅周期性进程", "⏱️ Solo periódicos", "⏱️ 周期出現のみ");
            res["Loc_Tab2_FilterRare"] = Loc.T("🆕 New / Rare Only", "🆕 仅首次/罕见进程", "🆕 Solo nuevos / raros", "🆕 初出・レアのみ");
            res["Loc_Tab2_FilterAll"] = Loc.T("📋 All Processes", "📋 全部进程", "📋 Todos los procesos", "📋 全プロセス");
            res["Loc_Tab2_ExcludeMs"] = Loc.T("Exclude MS Signed", "排除微软签名", "Excluir firmados por MS", "MS製品除外");
            res["Loc_Tab2_IncludeHistorical"] = Loc.T("Past History", "历史记录", "Historial", "過去の履歴");
            res["Loc_Tab2_ScanTasksBtn"] = Loc.T(
                "⏰ Inspect Recent Scheduled Tasks",
                "⏰ 排查近期计划任务",
                "⏰ Investigar tareas recientes",
                "⏰ 直近実行タスク調査");
            res["Loc_Btn_Trust"] = Loc.T("✅ Safe", "✅ 信任", "✅ Seguro", "✅ 安全");

            // Tab 3: System Defense & Score
            res["Loc_Tab3_Header"] = Loc.T("🛡️ System Defense & Score", "🛡️ 系统防御与评分", "🛡️ Defensa y Puntuación", "🛡️ システム防御・スコア");
            res["Loc_Tab3_FilterRisky"] = Loc.T("🔥 Attention Only", "🔥 仅显示需注意项", "🔥 Solo atención", "🔥 要注意のみ");
            res["Loc_Tab3_FilterAll"] = Loc.T("📋 All", "📋 全部", "📋 Todos", "📋 すべて");
            res["Loc_Tab3_FilterAutostart"] = Loc.T("🚀 Autostart / 👻 WMI", "🚀 自启动 / 👻 WMI持久化", "🚀 Autoinicio / 👻 WMI", "🚀 自動起動 / 👻 WMI永続化");
            res["Loc_Tab3_FilterCmd"] = Loc.T("⌨️ Command / 🧩 DLL", "⌨️ 命令行 / 🧩 DLL", "⌨️ Comandos / 🧩 DLL", "⌨️ コマンド/🧩DLL");
            res["Loc_Tab3_FilterPrivacy"] = Loc.T("📷 Cam / 🎹 Key / 📋 Clip / 🔌 USB", "📷 摄像头/🎹按键/📋剪贴板/🔌USB", "📷 Cámara/🎹Teclas/📋Portapapeles/🔌USB", "📷 カメラ/🎹キー/📋クリップ/🔌USB");
            res["Loc_Tab3_FilterCert"] = Loc.T("📜 Cert / 🔐 Logon / 👑 Admin", "📜 证书 / 🔐 登录 / 👑 管理员", "📜 Cert / 🔐 Inicio / 👑 Admin", "📜 証明書/🔐ログオン/👑管理者");
            res["Loc_Btn_Ack"] = Loc.T("✅ Ack", "✅ 确认", "✅ Aceptar", "✅ 承認");
            res["Loc_Btn_OpenLoc"] = Loc.T("📂 Open", "📂 位置", "📂 Abrir", "📂 場所");
            res["Loc_Btn_OpenSetting"] = Loc.T("🔧 Open Settings", "🔧 打开设置", "🔧 Abrir config.", "🔧 設定を開く");

            // Tab 4: AI Consultation Logs
            res["Loc_Tab4_Header"] = Loc.T("🤖 AI Consultation", "🤖 AI 咨询日志", "🤖 Consulta IA", "🤖 AI相談ログ");
            res["Loc_Tab4_AddSnapshotBtn"] = Loc.T("📸 Add Full PC Snapshot", "📸 添加电脑完整快照", "📸 Añadir instantánea del PC", "📸 PC全体スナップショット追加");
            res["Loc_Tab4_LogsTitle"] = Loc.T("📋 Logs for AI Consultation", "📋 待咨询 AI 的安全日志", "📋 Registros para Consulta IA", "📋 AI相談対象ログ");
            res["Loc_Tab4_SelectAllBtn"] = Loc.T("☑️ Select All", "☑️ 全选", "☑️ Seleccionar todo", "☑️ 全選択");
            res["Loc_Tab4_DeselectAllBtn"] = Loc.T("⬜ Deselect All", "⬜ 取消全选", "⬜ Deseleccionar todo", "⬜ 全解除");
            res["Loc_Tab4_ClearBtn"] = Loc.T("🗑️ Clear", "🗑️ 清空", "🗑️ Limpiar", "🗑️ クリア");
            res["Loc_Tab4_UserNoteLabel"] = Loc.T("💬 Note for AI:", "💬 给 AI 的补充说明:", "💬 Nota para la IA:", "💬 AIへの補足メモ:");
            res["Loc_Tab4_CopyPromptBtn"] = Loc.T("📋 Copy AI Consultation Prompt", "📋 复制 AI 咨询提示词", "📋 Copiar Prompt para IA", "📋 AI相談用プロンプトをコピー");
            res["Loc_Tab4_IncludeHistory"] = Loc.T("🕒 Include Past History", "🕒 包含并显示历史记录", "🕒 Incluir y mostrar historial", "🕒 過去履歴も含めて表示・チェック");
            res["Loc_Tab4_IncludeHistoryTooltip"] = Loc.T(
                "When unchecked (default), past historical traces and inactive processes are excluded from the list. Check this to show and select past history for AI consultation.",
                "未勾选（默认）时，从列表中排除历史痕迹及非活跃进程。勾选后将一并在列表中显示并纳入咨询。",
                "Sin marcar (predeterminado), los registros históricos e inactivos se excluyen de la lista. Marque para mostrarlos e incluirlos.",
                "未チェック（原則）時は過去履歴・非稼働プロセスを一覧から除外（非表示）します。チェックを入れると過去履歴もリストアップしAI相談の選択対象に含めます。");

            // IP Threat Intelligence Check Dialog
            res["Loc_IpLookup_Title"] = Loc.T(
                "IP Threat Intelligence Check",
                "IP 威胁情报与信誉查询",
                "Verificación de Inteligencia de IP",
                "IPアドレス 脅威インテリジェンス調査");
            res["Loc_IpLookup_Header"] = Loc.T(
                "IP Address Threat Intelligence & Reputation Check",
                "IP 地址威胁情报与信誉多源查询",
                "Verificación de Inteligencia de Amenazas y Reputación de IP",
                "IPアドレス 脅威インテリジェンス・レピュテーション調査");
            res["Loc_IpLookup_Desc"] = Loc.T(
                "Investigate suspicious or remote IP addresses using global threat intelligence databases. Clicking a service button will open the search result in your default browser.",
                "使用全球权威威胁情报库查询可疑或远程 IP 地址。点击服务按钮将在默认浏览器中打开查询页面。",
                "Investigue direcciones IP remotas o sospechosas mediante bases de datos globales de inteligencia. Al hacer clic en un botón, se abrirá la página en el navegador predeterminado.",
                "外部セキュリティ調査サービスで対象IPアドレスの脅威・レピュテーション情報を確認します。ボタンをクリックするとデフォルトブラウザで検索結果ページが開きます。");
            res["Loc_IpLookup_TargetIpLabel"] = Loc.T("Target IP Address:", "目标 IP 地址:", "Dirección IP objetivo:", "調査対象 IPアドレス:");
            res["Loc_IpLookup_CopyBtn"] = Loc.T("📋 Copy IP", "📋 复制 IP", "📋 Copiar IP", "📋 IPをコピー");
            res["Loc_IpLookup_PrivateWarning"] = Loc.T(
                "⚠️ Note: This IP address is a private, loopback, or local network address. External threat intelligence services typically only have data for public internet IP addresses.",
                "⚠️ 注意: 该 IP 地址属于私有/环回/本地局域网地址。外部威胁情报服务通常仅记录公网 IP 地址的数据。",
                "⚠️ Nota: Esta dirección IP es privada, de bucle local o de red local. Los servicios externos suelen contener datos únicamente de IPs públicas.",
                "⚠️ 注意: このIPアドレスはプライベートIP / ループバック / ローカルIPです。外部の脅威インテリジェンスサービスは通常パブリックIPのみを対象としているため、検索結果が表示されない場合があります。");
            res["Loc_IpLookup_OpenAllBtn"] = Loc.T("🚀 Open All (7 Services)", "🚀 一键打开全部 (7 个服务)", "🚀 Abrir todos (7 servicios)", "🚀 すべてブラウザで開く (7サービス)");
            res["Loc_IpLookup_CloseBtn"] = Loc.T("Close", "关闭", "Cerrar", "閉じる");

            // Service Descriptions
            res["Loc_Service_AbuseIpDb_Desc"] = Loc.T(
                "Crowdsourced malicious IP reports & abuse confidence score",
                "众包恶意 IP 举报数据库与滥用置信度评分",
                "Base de datos colaborativa de reportes de IP maliciosas y puntuación de abuso",
                "不正アクセス・攻撃通報データベース & Abuseスコア確認");
            res["Loc_Service_GreyNoise_Desc"] = Loc.T(
                "Mass internet scanner classification & malicious vs benign intent",
                "全网扫描器特征分类与恶意/无害意图分析",
                "Clasificación de escáneres masivos de Internet y análisis de intención",
                "全網スキャナー識別 & 悪意/無害性判定");
            res["Loc_Service_VirusTotal_Desc"] = Loc.T(
                "Comprehensive detection by 70+ antivirus engines and threat feeds",
                "聚合 70+ 家杀毒引擎与威胁情报源的综合检出",
                "Detección exhaustiva por más de 70 motores antivirus y fuentes de amenazas",
                "70社以上のマルウェア・セキュリティベンダー総合判定");
            res["Loc_Service_LevelBlueOtx_Desc"] = Loc.T(
                "LevelBlue (formerly AlienVault) Open Threat Exchange indicators",
                "LevelBlue（原 AlienVault）开放威胁情报交换 (OTX) 指标",
                "Indicadores de Open Threat Exchange de LevelBlue (anteriormente AlienVault)",
                "LevelBlue (旧AlienVault) OTX オープン脅威インテリジェンス");
            res["Loc_Service_Spamhaus_Desc"] = Loc.T(
                "World-leading IP blocklist & reputation query for spam & botnets",
                "全球权威的反垃圾邮件、僵尸网络与恶意 IP 黑名单查询",
                "Consulta de lista de bloqueo y reputación de IP para spam y botnets",
                "世界的スパム・ボットネットIPブロックリスト (DNSBL)");
            res["Loc_Service_Talos_Desc"] = Loc.T(
                "Global threat intelligence telemetry, web & email reputation scores",
                "思科全球威胁遥测网络、Web 与电子邮件信誉综合评估",
                "Telemetría de inteligencia de amenazas global de Cisco, reputación web y de correo",
                "シスコの世界的脅威リサーチ・Web/メールレピュテーション評価");
            res["Loc_Service_Censys_Desc"] = Loc.T(
                "Internet-wide host scanner for open ports, services & TLS certificates",
                "全网主机空间探测：开放端口、运行服务与 TLS 证书指纹",
                "Escáner de hosts en toda la red para puertos abiertos, servicios y certificados TLS",
                "インターネット公開機器調査・オープンポート & SSL証明書情報");
        }

        OnLanguageChanged?.Invoke(language);
    }

    public static string GetLanguageDisplayName(AppLanguage lang) => lang switch
    {
        AppLanguage.Chinese => "🇨🇳 中文 (简体)",
        AppLanguage.Spanish => "🇪🇸 Español",
        AppLanguage.Japanese => "🇯🇵 日本語",
        _ => "🇺🇸 English"
    };
}
