using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using AnzenSecurityWatcher.Models;
using AnzenSecurityWatcher.Services;
using WinForms = System.Windows.Forms;

namespace AnzenSecurityWatcher;

public partial class MainWindow : Window
{
    private readonly GeoIpService _geoIpService;
    private readonly NetworkMonitorService _networkService;
    private readonly ScreenShareMonitorService _screenShareService;
    private readonly ProcessMonitorService _processService;
    private readonly SystemDefenseService _systemDefenseService;
    private readonly AiPromptBuilderService _aiPromptService;

    private readonly DispatcherTimer _monitorTimer;
    private bool _isPaused = false;
    private bool _isScanning = false;
    private bool _showingPostureChecklist = false;
    private bool _isNetworkPaused = false;
    private bool _isProcessPaused = false;

    private List<NetworkConnectionItem> _latestConnections = new();
    private List<ScreenShareDetectionItem> _latestScreenShares = new();
    private List<ProcessAnalysisItem> _latestProcesses = new();
    private List<SystemFindingItem> _latestFindings = new();
    private SecurityPostureReport _latestPosture = new();

    private string? _selectedCountryFilter = null;
    private readonly HashSet<string> _notifiedScreenShareKeys = new(StringComparer.OrdinalIgnoreCase);

    private WinForms.NotifyIcon? _notifyIcon;
    private AlertPopupWindow? _alertPopupWindow;
    private SettingsWindow? _settingsWindow;
    private AboutWindow? _aboutWindow;

    public ScanIntervalMode ScanIntervalOption { get; private set; } = ScanIntervalMode.Fast;
    public bool IncludeLoopbackOption { get; private set; } = false;
    public bool IncludeListenOption { get; private set; } = false;
    public bool IncludeUdpOption { get; private set; } = true;
    public bool MaskPersonalInfoOption { get; private set; } = true;
    public bool EnableDllSideloadCheckOption { get; private set; } = false;
    public bool DisableOnlineGeoIpOption { get; private set; } = false;

    public ObservableCollection<CountryTrafficSummary> CountrySummaries { get; } = new();

    private static readonly HashSet<string> DefaultUserNotes = new(StringComparer.Ordinal)
    {
        "I haven't done anything unusual, but I want to verify if my background network connections and processes are safe.",
        "我并没有进行任何可疑操作，但想确认后台的网络通信和进程是否安全。",
        "No he realizado ninguna operación sospechosa, pero quiero verificar si las conexiones y procesos en segundo plano son seguros.",
        "特に怪しい操作はしていませんが、バックグラウンド通信やプロセスが安全か確認したいです。"
    };

    public MainWindow()
    {
        InitializeComponent();

        _geoIpService = new GeoIpService();
        _networkService = new NetworkMonitorService(_geoIpService);
        _screenShareService = new ScreenShareMonitorService();
        _processService = new ProcessMonitorService();
        _systemDefenseService = new SystemDefenseService();
        _aiPromptService = new AiPromptBuilderService();

        // 0.3秒で消える瞬間ターミナル（短命プロセス）を50msスナイパーが捕捉した瞬間にUIへ即時反映
        _processService.OnTransientProcessCaptured += item =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (!IsLoaded) return;
                if (!_latestProcesses.Any(x => x.ProcessKey.Equals(item.ProcessKey, StringComparison.OrdinalIgnoreCase)))
                {
                    _latestProcesses.Insert(0, item);
                }
                ApplyProcessFilter();
                UpdateTopKpis();
                string flashKind = item.HadVisibleConsoleWindow
                    ? Loc.T("💥 Flash Terminal Captured", "💥 捕获瞬时终端窗口", "💥 Terminal fugaz capturada", "💥 瞬間ターミナル窓を捕捉")
                    : Loc.T("⚡ Short-lived Process Captured", "⚡ 捕获短命进程", "⚡ Proceso fugaz capturado", "⚡ 短命プロセスを捕捉");
                FooterStatusText.Text = Loc.T(
                    $"{flashKind}: {item.ProcessName} (Alive:{item.DurationText} / Parent:{item.ParentDisplay})",
                    $"{flashKind}: {item.ProcessName} (存活:{item.DurationText} / 父进程:{item.ParentDisplay})",
                    $"{flashKind}: {item.ProcessName} (Vivo:{item.DurationText} / Padre:{item.ParentDisplay})",
                    $"{flashKind}: {item.ProcessName} (生存:{item.DurationText} / 親:{item.ParentDisplay})");
            });
        };

        CountrySummaryItemsControl.ItemsSource = CountrySummaries;

        // オンラインGeoIP解決完了時にリアルタイムでUI表示を更新
        _geoIpService.OnGeoIpResolved += (ip, info) =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                bool updated = false;
                foreach (var conn in _latestConnections.Where(c => c.RemoteAddress == ip))
                {
                    conn.CountryCode = info.CountryCode;
                    conn.CountryName = info.CountryName;
                    conn.CountryFlag = info.Flag;
                    conn.Organization = info.Organization;
                    conn.City = info.City;
                    _networkService.EvaluateRisk(conn, info);
                    updated = true;
                }
                if (updated)
                {
                    RebuildCountrySummaries();
                    ApplyNetworkFilter();
                }
            });
        };

        SetupSystemTrayIcon();

        // 保存された設定オプションを反映
        var settings = SettingsManager.Current;
        ScanIntervalOption = settings.ScanInterval;
        IncludeLoopbackOption = settings.IncludeLoopback;
        IncludeListenOption = settings.IncludeListen;
        IncludeUdpOption = settings.IncludeUdp;
        MaskPersonalInfoOption = settings.MaskPersonalInfo;
        EnableDllSideloadCheckOption = settings.EnableDllSideloadCheck;
        DisableOnlineGeoIpOption = settings.DisableOnlineGeoIp;
        _geoIpService.DisableOnlineLookup = DisableOnlineGeoIpOption;
        if (IncludeUdpToolbarCheck != null)
        {
            IncludeUdpToolbarCheck.IsChecked = IncludeUdpOption;
        }

        ApplyLocalization();

        ThemeManager.OnThemeChanged += _ =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (!IsLoaded) return;
                UpdateTopKpis();
                UpdateScreenShareTabAndAlerts();
                UpdateSystemDefenseTab();
            });
        };

        LocalizationManager.OnLanguageChanged += _ =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                ApplyLocalization();
            });
        };

        _monitorTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds((int)ScanIntervalOption)
        };
        _monitorTimer.Tick += async (_, _) => await RunScanCycleAsync();

        Loaded += async (_, _) =>
        {
            await RunScanCycleAsync();
            _monitorTimer.Start();
        };

        Closing += MainWindow_Closing;
    }

    private void ApplyLocalization()
    {
        // DataGrid Column Headers (Tab 0: Network)
        Col_Net_Risk.Header = Loc.T("Risk", "判定", "Riesgo", "判定");
        Col_Net_Proto.Header = Loc.T("Proto", "类型", "Tipo", "種別");
        Col_Net_Country.Header = Loc.T("Country / Region", "通信国家/地区", "País de destino", "通信先の国");
        Col_Net_Org.Header = Loc.T("Organization / ISP", "组织 / ISP", "Organización / ISP", "組織 / ISP");
        Col_Net_Proc.Header = Loc.T("Process", "进程名", "Proceso", "プロセス名");
        Col_Net_Pid.Header = "PID";
        Col_Net_Endpoint.Header = Loc.T("Remote / Local Endpoint", "远程/监听端点", "Punto final remoto", "リモート/待受端点");
        Col_Net_State.Header = Loc.T("State", "状态", "Estado", "状態");
        Col_Net_Reason.Header = Loc.T("Reason / Notes", "判定原因与备注", "Motivo / Notas", "判定理由・備考");
        Col_Net_Action.Header = Loc.T("Action", "操作", "Acción", "操作");

        // DataGrid Column Headers (Tab 1: Screen Share & RDP)
        Col_SS_Status.Header = Loc.T("Current Status", "当前状态", "Estado actual", "現在の状態");
        Col_SS_Tool.Header = Loc.T("Tool / Protocol", "工具 / 协议名称", "Herramienta / Protocolo", "ツール / プロトコル名");
        Col_SS_Proc.Header = Loc.T("Process", "进程", "Proceso", "プロセス");
        Col_SS_Pid.Header = "PID";
        Col_SS_Endpoint.Header = Loc.T("Remote Endpoint", "通信目标", "Destino remoto", "通信先");
        Col_SS_Evidence.Header = Loc.T("Detection Evidence", "检测依据与证据", "Evidencia de detección", "検知根拠・証跡");
        Col_SS_Action.Header = Loc.T("Action", "操作", "Acción", "操作");

        // DataGrid Column Headers (Tab 2: Process Monitor)
        Col_Proc_Risk.Header = Loc.T("Risk", "风险", "Riesgo", "リスク");
        Col_Proc_Status.Header = Loc.T("Status / Lifetime", "状态 / 存活时间", "Estado / Duración", "状態 / 生存時間");
        Col_Proc_Name.Header = Loc.T("Process Name", "进程名", "Proceso", "プロセス名");
        Col_Proc_Parent.Header = Loc.T("Parent Process", "父进程 (启动源)", "Proceso padre", "親プロセス (起動元)");
        Col_Proc_Period.Header = Loc.T("Periodicity / Timing", "周期性 / 时机", "Periodicidad / Tiempo", "周期性 / タイミング");
        Col_Proc_Count.Header = Loc.T("Count", "次数", "Veces", "回数");
        Col_Proc_Cmd.Header = Loc.T("Command Line", "命令行参数", "Línea de comandos", "コマンドライン引数");
        Col_Proc_Reason.Header = Loc.T("Reason / Scheduled Task", "判定原因与计划任务", "Motivo / Tarea prog.", "判定理由・該当スケジュールタスク");
        Col_Proc_Sign.Header = Loc.T("Signature / Trust", "签名 / 信任状态", "Firma / Confianza", "署名 / 信頼状態");
        Col_Proc_Path.Header = Loc.T("Executable Path", "可执行路径", "Ruta del ejecutable", "実行パス");
        Col_Proc_Action.Header = Loc.T("Action", "操作", "Acción", "操作");

        // DataGrid Column Headers (Tab 3: System Defense & Score)
        Col_Def_Severity.Header = Loc.T("Severity", "严重度", "Severidad", "重要度");
        Col_Def_State.Header = Loc.T("State", "状态", "Estado", "状態");
        Col_Def_Cat.Header = Loc.T("Category", "分类", "Categoría", "分類");
        Col_Def_Title.Header = Loc.T("Finding Title", "检测标题", "Título del hallazgo", "検知タイトル");
        Col_Def_Detail.Header = Loc.T("Details & Evidence", "详情与证据", "Detalles y evidencia", "詳細・証跡・理由");
        Col_Def_Target.Header = Loc.T("Target Path / ID", "目标路径 / ID", "Ruta / ID", "対象パス / ID");
        Col_Def_Time.Header = Loc.T("Time", "时间", "Hora", "時刻");
        Col_Def_Action.Header = Loc.T("Action", "操作", "Acción", "操作");

        Col_Post_Result.Header = Loc.T("Result", "诊断结果", "Resultado", "診断結果");
        Col_Post_Weight.Header = Loc.T("Points", "分值", "Puntos", "スコア配点");
        Col_Post_Name.Header = Loc.T("Security Check Item", "安全检查项", "Elemento de seguridad", "セキュリティ点検項目");
        Col_Post_Status.Header = Loc.T("Current Status", "当前状态", "Estado actual", "現在の状態");
        Col_Post_Advice.Header = Loc.T("Explanation & Advice", "说明与改进建议", "Explicación y consejo", "解説・推奨アドバイス");
        Col_Post_Fix.Header = Loc.T("Action", "对策", "Acción", "対策");

        // DataGrid Column Headers (Tab 4: AI Consultation Logs)
        Col_Ai_Select.Header = Loc.T("Select", "选择", "Selec.", "選択");
        Col_Ai_Sev.Header = Loc.T("Severity", "严重度", "Severidad", "重要度");
        Col_Ai_Cat.Header = Loc.T("Category", "类别", "Categoría", "カテゴリ");
        Col_Ai_Title.Header = Loc.T("Event Summary", "事件概要", "Resumen del evento", "イベント概要");
        Col_Ai_Count.Header = Loc.T("Count", "次数", "Veces", "回数");
        Col_Ai_Time.Header = Loc.T("Time", "时间", "Hora", "時刻");

        // Toggle Posture View Button
        UpdateTogglePostureButtonText();

        // Pause / Resume Menu Item
        PauseResumeMenuItem.Header = _isPaused
            ? Loc.T("▶️ Resume Monitoring(_P)", "▶️ 恢复监控(_P)", "▶️ Reanudar monitoreo(_P)", "▶️ 監視の再開(_P)")
            : Loc.T("⏸️ Pause Monitoring(_P)", "⏸️ 暂停监控(_P)", "⏸️ Pausar monitoreo(_P)", "⏸️ 監視の一時停止(_P)");

        // Update Pause Buttons in Tab 0 & Tab 2
        UpdatePauseButtonsState();

        // Default User Note in Tab 4
        if (UserNoteTextBox != null && (string.IsNullOrWhiteSpace(UserNoteTextBox.Text) || DefaultUserNotes.Contains(UserNoteTextBox.Text.Trim())))
        {
            UserNoteTextBox.Text = Loc.T(
                "I haven't done anything unusual, but I want to verify if my background network connections and processes are safe.",
                "我并没有进行任何可疑操作，但想确认后台的网络通信和进程是否安全。",
                "No he realizado ninguna operación sospechosa, pero quiero verificar si las conexiones y procesos en segundo plano son seguros.",
                "特に怪しい操作はしていませんが、バックグラウンド通信やプロセスが安全か確認したいです。");
        }

        // CopyStatusText
        if (CopyStatusText != null)
        {
            CopyStatusText.Text = MaskPersonalInfoOption
                ? Loc.T(
                    "💡 Click button to copy prompt (Personal info masking: ON)",
                    "💡 点击按钮即可复制提示词（个人信息打码：开启）",
                    "💡 Haga clic para copiar el prompt (Ocultar datos personales: SÍ)",
                    "💡 ボタンを押すとコピーされます (個人情報マスク: 有効)")
                : Loc.T(
                    "💡 Click button to copy prompt (Personal info masking: OFF)",
                    "💡 点击按钮即可复制提示词（个人信息打码：关闭）",
                    "💡 Haga clic para copiar el prompt (Ocultar datos personales: NO)",
                    "💡 ボタンを押すとコピーされます (個人情報マスク: 無効)");
        }

        // FooterStatusText initial/idle
        UpdateMonitoringStatusText();

        // Re-evaluate connection risk reasons and country names in current language
        foreach (var conn in _latestConnections)
        {
            conn.CountryName = GeoIpService.GetLocalizedCountryName(conn.CountryCode, conn.CountryName);
            var geo = _geoIpService.GetOrResolve(conn.RemoteAddress);
            _networkService.EvaluateRisk(conn, geo);
        }

        // Re-evaluate process anomaly reasons in current language
        foreach (var proc in _latestProcesses)
        {
            ProcessMonitorService.EvaluateProcessAnomaly(proc);
        }

        RebuildTrayContextMenu();

        if (!IsLoaded) return;

        // Re-evaluate security posture and system defense findings in current language
        _latestScreenShares = _screenShareService.ScanScreenShareStatus(_latestConnections);
        (_latestFindings, _latestPosture) = _systemDefenseService.ScanAll(forceFull: true, enableDllSideloadCheck: EnableDllSideloadCheckOption);

        RebuildCountrySummaries();
        ApplyNetworkFilter();
        UpdateScreenShareTabAndAlerts();
        ApplyProcessFilter();
        UpdateSystemDefenseTab();
        RefreshAiAdvisorTab();
        UpdateTopKpis();

        NetworkDataGrid.Items.Refresh();
        ScreenShareDataGrid.Items.Refresh();
        ProcessDataGrid.Items.Refresh();
        DefenseFindingsDataGrid.Items.Refresh();
        SecurityPostureDataGrid.Items.Refresh();
        AiLogsDataGrid.Items.Refresh();
        UpdateFooterScanSummary();
    }

    private void SetupSystemTrayIcon()
    {
        try
        {
            _notifyIcon = new WinForms.NotifyIcon
            {
                Text = "Anzen Security Watcher",
                Visible = true,
                Icon = CreateShieldTrayIcon()
            };

            RebuildTrayContextMenu();
            _notifyIcon.DoubleClick += (_, _) => Dispatcher.Invoke(ShowMainWindow);
        }
        catch
        {
            // Ignore tray setup errors
        }
    }

    private void RebuildTrayContextMenu()
    {
        if (_notifyIcon == null) return;
        try
        {
            _notifyIcon.Text = Loc.T(
                "Anzen Security Watcher (Monitoring)",
                "Anzen Security Watcher (监控中)",
                "Anzen Security Watcher (Monitoreando)",
                "Anzen Security Watcher (監視中)");

            var menu = new WinForms.ContextMenuStrip();
            menu.Items.Add(Loc.T("🛡️ Open Monitor Window", "🛡️ 打开监控界面", "🛡️ Abrir ventana del monitor", "🛡️ 監視画面を開く"), null, (_, _) => Dispatcher.Invoke(ShowMainWindow));
            menu.Items.Add(Loc.T("⚙️ Settings & Simulation Tests...", "⚙️ 设置与模拟测试...", "⚙️ Configuración y pruebas...", "⚙️ 設定・動作テストを開く..."), null, (_, _) => Dispatcher.Invoke(() =>
            {
                ShowMainWindow();
                OpenSettingsMenuItem_Click(this, new RoutedEventArgs());
            }));
            menu.Items.Add(Loc.T("ℹ️ Version & About...", "ℹ️ 关于与版本信息...", "ℹ️ Acerca de / Versión...", "ℹ️ バージョン情報..."), null, (_, _) => Dispatcher.Invoke(() =>
            {
                ShowMainWindow();
                OpenAboutMenuItem_Click(this, new RoutedEventArgs());
            }));

            var toolsMenu = new WinForms.ToolStripMenuItem(Loc.T("🧰 Windows Tools", "🧰 启动 Windows 工具", "🧰 Herramientas de Windows", "🧰 Windowsツール起動"));
            toolsMenu.DropDownItems.Add(Loc.T("📊 Task Manager", "📊 任务管理器", "📊 Administrador de tareas", "📊 タスクマネージャー"), null, (_, _) => Dispatcher.Invoke(() => LaunchSystemTool("taskmgr.exe", "Task Manager")));
            toolsMenu.DropDownItems.Add(Loc.T("📋 Event Viewer", "📋 事件查看器", "📋 Visor de eventos", "📋 イベントビューアー"), null, (_, _) => Dispatcher.Invoke(() => LaunchSystemTool("eventvwr.msc", "Event Viewer")));
            toolsMenu.DropDownItems.Add(Loc.T("🔌 Device Manager", "🔌 设备管理器", "🔌 Administrador de dispositivos", "🔌 デバイスマネージャー"), null, (_, _) => Dispatcher.Invoke(() => LaunchSystemTool("devmgmt.msc", "Device Manager")));
            toolsMenu.DropDownItems.Add(Loc.T("🎛️ Control Panel", "🎛️ 控制面板", "🎛️ Panel de control", "🎛️ コントロールパネル"), null, (_, _) => Dispatcher.Invoke(() => LaunchSystemTool("control.exe", "Control Panel")));
            toolsMenu.DropDownItems.Add(new WinForms.ToolStripSeparator());
            toolsMenu.DropDownItems.Add(Loc.T("📈 Resource Monitor", "📈 资源监视器", "📈 Monitor de recursos", "📈 リソースモニター"), null, (_, _) => Dispatcher.Invoke(() => LaunchSystemTool("resmon.exe", "Resource Monitor")));
            toolsMenu.DropDownItems.Add(Loc.T("🔥 Windows Firewall", "🔥 高级安全 Windows 防火墙", "🔥 Firewall de Windows", "🔥 Windows ファイアウォール詳細設定"), null, (_, _) => Dispatcher.Invoke(() => LaunchSystemTool("wf.msc", "Windows Firewall")));
            toolsMenu.DropDownItems.Add(Loc.T("⏰ Task Scheduler", "⏰ 任务计划程序", "⏰ Programador de tareas", "⏰ タスクスケジューラ"), null, (_, _) => Dispatcher.Invoke(() => LaunchSystemTool("taskschd.msc", "Task Scheduler")));
            toolsMenu.DropDownItems.Add(Loc.T("⚙️ Services", "⚙️ 服务管理", "⚙️ Servicios", "⚙️ サービス管理"), null, (_, _) => Dispatcher.Invoke(() => LaunchSystemTool("services.msc", "Services")));
            menu.Items.Add(toolsMenu);

            menu.Items.Add(new WinForms.ToolStripSeparator());
            menu.Items.Add(Loc.T("❌ Exit", "❌ 退出", "❌ Salir", "❌ 終了"), null, (_, _) =>
            {
                _notifyIcon.Visible = false;
                _notifyIcon.Dispose();
                _notifyIcon = null;
                System.Windows.Application.Current.Shutdown();
            });

            _notifyIcon.ContextMenuStrip = menu;
        }
        catch { }
    }

    private static System.Drawing.Icon CreateShieldTrayIcon()
    {
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.Clear(System.Drawing.Color.Transparent);
            using var brush = new SolidBrush(System.Drawing.Color.FromArgb(31, 111, 235));
            using var pen = new System.Drawing.Pen(System.Drawing.Color.FromArgb(120, 190, 255), 2f);
            System.Drawing.Point[] shieldPts =
            {
                new(16, 2),
                new(28, 7),
                new(26, 20),
                new(16, 30),
                new(6, 20),
                new(4, 7)
            };
            g.FillPolygon(brush, shieldPts);
            g.DrawPolygon(pen, shieldPts);
        }
        IntPtr hIcon = bmp.GetHicon();
        return System.Drawing.Icon.FromHandle(hIcon);
    }

    private void ShowMainWindow()
    {
        Show();
        if (WindowState == WindowState.Minimized)
            WindowState = WindowState.Normal;
        Activate();
    }

    private async Task RunScanCycleAsync()
    {
        if (_isPaused || _isScanning) return;
        _isScanning = true;

        try
        {
            bool includeLoopback = IncludeLoopbackOption;
            bool includeListen = IncludeListenOption;
            bool includeUdp = IncludeUdpOption;
            bool enableDllSideload = EnableDllSideloadCheckOption;

            var scanResult = await Task.Run(() =>
            {
                var conns = _networkService.ScanActiveConnections(includeLoopback, includeListen, includeUdp);
                var shares = _screenShareService.ScanScreenShareStatus(conns);
                var procs = _processService.ScanProcesses();
                var (findings, posture) = _systemDefenseService.ScanAll(enableDllSideloadCheck: enableDllSideload);
                return (conns, shares, procs, findings, posture);
            });

            _latestConnections = scanResult.conns;
            _latestScreenShares = scanResult.shares;
            _latestProcesses = scanResult.procs;
            _latestFindings = scanResult.findings;
            _latestPosture = scanResult.posture;

            if (!_isNetworkPaused)
            {
                RebuildCountrySummaries();
                ApplyNetworkFilter();
            }
            UpdateScreenShareTabAndAlerts();
            if (!_isProcessPaused)
            {
                ApplyProcessFilter();
            }
            UpdateSystemDefenseTab();
            if (AiLogsDataGrid.ItemsSource == null)
            {
                RefreshAiAdvisorTab();
            }

            UpdateTopKpis();
            UpdateFooterScanSummary();
        }
        catch (Exception ex)
        {
            FooterStatusText.Text = Loc.T(
                $"⚠️ Scan error: {ex.Message}",
                $"⚠️ 扫描错误: {ex.Message}",
                $"⚠️ Error de escaneo: {ex.Message}",
                $"⚠️ スキャンエラー: {ex.Message}");
        }
        finally
        {
            _isScanning = false;
        }
    }

    private void UpdateFooterScanSummary()
    {
        int riskyDefCount = _latestFindings.Count(f => f.EffectiveSeverity >= RiskLevel.Medium);
        FooterLastScanText.Text = Loc.T(
            $"Updated: {DateTime.Now:HH:mm:ss} (Net:{_latestConnections.Count} / Proc:{_latestProcesses.Count} / Def:{riskyDefCount} / Score:{_latestPosture.Score})",
            $"更新: {DateTime.Now:HH:mm:ss} (通信:{_latestConnections.Count} / 进程:{_latestProcesses.Count} / 防御关注:{riskyDefCount} / 评分:{_latestPosture.Score}分)",
            $"Actualizado: {DateTime.Now:HH:mm:ss} (Red:{_latestConnections.Count} / Proc:{_latestProcesses.Count} / Def:{riskyDefCount} / Puntaje:{_latestPosture.Score})",
            $"更新: {DateTime.Now:HH:mm:ss} (通信:{_latestConnections.Count} / プロセス:{_latestProcesses.Count} / 防御注目:{riskyDefCount} / スコア:{_latestPosture.Score}点)");
    }

    private void UpdateTopKpis()
    {
        int distinctCountries = _latestConnections
            .Where(c => c.CountryCode != "LOCAL" && c.CountryCode != "LAN" && c.CountryCode != "MCAST")
            .Select(c => c.CountryCode)
            .Distinct()
            .Count();

        KpiConnectionsText.Text = Loc.T(
            $"🌐 {_latestConnections.Count} ({distinctCountries} countries)",
            $"🌐 {_latestConnections.Count}个 ({distinctCountries}个国家)",
            $"🌐 {_latestConnections.Count} ({distinctCountries} países)",
            $"🌐 {_latestConnections.Count}件 ({distinctCountries}カ国)");

        int activeShares = _latestScreenShares.Count(s => s.Status == ScreenShareStatus.ActiveStreaming);
        int standbyShares = _latestScreenShares.Count(s => s.Status == ScreenShareStatus.StandbyService);
        bool isDark = ThemeManager.IsCurrentlyDark;

        if (activeShares > 0)
        {
            KpiScreenShareText.Text = Loc.T(
                $"🚨 Sharing({activeShares})",
                $"🚨 外泄/共享中({activeShares})",
                $"🚨 Compartiendo({activeShares})",
                $"🚨 流出/共有中({activeShares})");
            KpiScreenShareText.Foreground = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(255, 85, 95)
                : System.Windows.Media.Color.FromRgb(207, 34, 46));
        }
        else if (standbyShares > 0)
        {
            KpiScreenShareText.Text = Loc.T(
                $"🖥️ Standby({standbyShares})",
                $"🖥️ 待机({standbyShares})",
                $"🖥️ En espera({standbyShares})",
                $"🖥️ 待機({standbyShares})");
            KpiScreenShareText.Foreground = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(230, 175, 45)
                : System.Windows.Media.Color.FromRgb(154, 103, 0));
        }
        else
        {
            KpiScreenShareText.Text = Loc.T("🖥️ Safe", "🖥️ 安全", "🖥️ Seguro", "🖥️ 安全");
            KpiScreenShareText.Foreground = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(63, 185, 80)
                : System.Windows.Media.Color.FromRgb(26, 127, 55));
        }

        bool excludeMs = ExcludeMicrosoftProcCheck?.IsChecked == true;
        var kpiProcSource = excludeMs ? _latestProcesses.Where(p => !p.IsMicrosoftSigned) : _latestProcesses;
        int transientCount = kpiProcSource.Count(p => p.IsTransientFlash && !p.IsUserTrusted && (!p.IsHistoricalOnly || p.IsCurrentlyRunning));
        int periodicCount = kpiProcSource.Count(p => p.IsPeriodic && !p.IsUserTrusted);
        int rareCount = kpiProcSource.Count(p => p.IsRareOrNew && !p.IsUserTrusted && (!p.IsHistoricalOnly || p.IsCurrentlyRunning));
        KpiProcessText.Text = Loc.T(
            $"⚙️ Flash:{transientCount}/Per:{periodicCount}/New:{rareCount}",
            $"⚙️ 瞬时{transientCount}/周期{periodicCount}/首次{rareCount}",
            $"⚙️ Fugaz:{transientCount}/Per:{periodicCount}/Nuevo:{rareCount}",
            $"⚙️ 瞬間{transientCount}/周期{periodicCount}/初出{rareCount}");

        var allLogs = _aiPromptService.GetAllLogs();
        bool incHist = IncludeHistoryAiLogsCheckBox?.IsChecked == true;
        int activeLogCount = allLogs.Count(x => !x.IsHistoricalRecord);
        string countDisplay = incHist ? $"{allLogs.Count}" : $"{activeLogCount}";
        KpiAiLogsText.Text = Loc.T(
            $"🤖 Logs:{countDisplay}",
            $"🤖 日志{countDisplay}条",
            $"🤖 Reg:{countDisplay}",
            $"🤖 ログ{countDisplay}件");

        if (KpiDefenseScoreText != null && _latestPosture.Checks.Count > 0)
        {
            int score = _latestPosture.Score;
            int highDefs = _latestFindings.Count(f => f.EffectiveSeverity >= RiskLevel.High);
            KpiDefenseScoreText.Text = highDefs > 0
                ? Loc.T(
                    $"🛡️ Score {score}({_latestPosture.Grade}) / Alerts:{highDefs}",
                    $"🛡️ 评分{score}分({_latestPosture.Grade}) / 警报{highDefs}项",
                    $"🛡️ Puntaje {score}({_latestPosture.Grade}) / Alertas:{highDefs}",
                    $"🛡️ スコア{score}点({_latestPosture.Grade}) / 警戒{highDefs}件")
                : Loc.T(
                    $"🛡️ Score {score}({_latestPosture.Grade})",
                    $"🛡️ 评分{score}分({_latestPosture.Grade})",
                    $"🛡️ Puntaje {score}({_latestPosture.Grade})",
                    $"🛡️ スコア{score}点({_latestPosture.Grade})");
            KpiDefenseScoreText.Foreground = new SolidColorBrush(score >= 80 && highDefs == 0
                ? (isDark ? System.Windows.Media.Color.FromRgb(63, 185, 80) : System.Windows.Media.Color.FromRgb(26, 127, 55))
                : score >= 60 && highDefs == 0
                    ? (isDark ? System.Windows.Media.Color.FromRgb(230, 175, 45) : System.Windows.Media.Color.FromRgb(154, 103, 0))
                    : (isDark ? System.Windows.Media.Color.FromRgb(255, 85, 95) : System.Windows.Media.Color.FromRgb(207, 34, 46)));
        }
    }

    // ====================================================================
    // TAB 1: 国別通信集計＆フィルタ
    // ====================================================================
    private void RebuildCountrySummaries()
    {
        var groups = _latestConnections
            .GroupBy(c => new { c.CountryCode, c.CountryName, c.CountryFlag })
            .Select(g => new CountryTrafficSummary
            {
                CountryCode = g.Key.CountryCode,
                CountryName = GeoIpService.GetLocalizedCountryName(g.Key.CountryCode, g.Key.CountryName),
                CountryFlag = g.Key.CountryFlag,
                ConnectionCount = g.Count(),
                ProcessCount = g.Select(x => x.ProcessName).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                HasWarning = g.Any(x => x.RiskLevel >= RiskLevel.Medium),
                SampleProcesses = string.Join(", ", g.Select(x => x.ProcessName).Distinct(StringComparer.OrdinalIgnoreCase).Take(4))
            })
            .OrderByDescending(x => x.HasWarning)
            .ThenBy(x => x.CountryCode is "LOCAL" or "LAN" ? 1 : 0)
            .ThenByDescending(x => x.ConnectionCount)
            .ToList();

        CountrySummaries.Clear();
        foreach (var item in groups)
        {
            CountrySummaries.Add(item);
        }
    }

    private void ApplyNetworkFilter()
    {
        IEnumerable<NetworkConnectionItem> query = _latestConnections;

        if (!string.IsNullOrWhiteSpace(_selectedCountryFilter))
        {
            query = query.Where(c => c.CountryCode.Equals(_selectedCountryFilter, StringComparison.OrdinalIgnoreCase));
            ActiveCountryFilterLabel.Text = Loc.T(
                $"🎯 Country: {_selectedCountryFilter}",
                $"🎯 国家/地区: {_selectedCountryFilter}",
                $"🎯 País: {_selectedCountryFilter}",
                $"🎯 国: {_selectedCountryFilter}");
        }
        else
        {
            ActiveCountryFilterLabel.Text = Loc.T(
                "Showing: All Countries",
                "显示: 所有国家/地区",
                "Mostrando: Todos los países",
                "表示: 全カ国");
        }

        if (ShowOnlyRiskyNetworkCheck?.IsChecked == true)
        {
            query = query.Where(c => c.RiskLevel >= RiskLevel.Medium);
        }

        string search = NetworkSearchBox?.Text?.Trim() ?? "";
        if (!string.IsNullOrEmpty(search))
        {
            query = query.Where(c =>
                c.ProcessName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                c.RemoteAddress.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                c.CountryDisplay.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                c.CountryCode.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                c.Organization.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                c.RiskReason.Contains(search, StringComparison.OrdinalIgnoreCase));
        }

        SetItemsSourcePreservingSort(NetworkDataGrid, query.ToList());
    }

    private void CountryCardButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button btn && btn.Tag is string code)
        {
            _selectedCountryFilter = (_selectedCountryFilter == code) ? null : code;
            ApplyNetworkFilter();
        }
    }

    private void ResetCountryFilter_Click(object sender, RoutedEventArgs e)
    {
        _selectedCountryFilter = null;
        ApplyNetworkFilter();
    }

    private void NetworkFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        ApplyNetworkFilter();
    }

    private async void IncludeUdpToolbarCheck_Click(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        IncludeUdpOption = IncludeUdpToolbarCheck.IsChecked == true;
        SettingsManager.Current.IncludeUdp = IncludeUdpOption;
        SettingsManager.Save();
        await RunScanCycleAsync();
    }

    private void AddNetworkToAiButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is NetworkConnectionItem item)
        {
            _aiPromptService.AddManualNetworkLog(item);
            RefreshAiAdvisorTab();
            UpdateTopKpis();
            MainTabControl.SelectedIndex = 4;
        }
    }

    private void OpenIpLookupButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is NetworkConnectionItem item)
        {
            var dialog = new IpLookupWindow(item)
            {
                Owner = this
            };
            dialog.ShowDialog();
        }
    }

    private void CopyRemoteIpButton_Click(object sender, RoutedEventArgs e)
    {
        OpenIpLookupButton_Click(sender, e);
    }

    // ====================================================================
    // TAB 2: リモートデスクトップ・画面共有検知＆アラート表示
    // ====================================================================
    private void UpdateScreenShareTabAndAlerts()
    {
        ScreenShareDataGrid.ItemsSource = _latestScreenShares.ToList();

        var activeList = _latestScreenShares.Where(s => s.Status == ScreenShareStatus.ActiveStreaming).ToList();
        var standbyList = _latestScreenShares.Where(s => s.Status == ScreenShareStatus.StandbyService).ToList();
        bool hasSim = _latestScreenShares.Any(s => s.IsSimulated)
                   || _latestProcesses.Any(p => p.ProcessKey.StartsWith("sim:"))
                   || _latestFindings.Any(f => f.IsSimulated);
        BannerClearSimButton.Visibility = hasSim ? Visibility.Visible : Visibility.Collapsed;

        UpdateCategoryCard(
            CardRdpBorder, CardRdpStatusText,
            _latestScreenShares.Where(s => s.Category == ScreenShareCategory.WindowsRdp).ToList(),
            Loc.T("✅ No connection", "✅ 无连接", "✅ Sin conexión", "✅ 接続なし"));

        UpdateCategoryCard(
            CardRemoteToolBorder, CardRemoteToolStatusText,
            _latestScreenShares.Where(s => s.Category == ScreenShareCategory.RemoteDesktopTool).ToList(),
            Loc.T("✅ No active session", "✅ 无活动会话", "✅ Sin sesión", "✅ セッションなし"));

        UpdateCategoryCard(
            CardMeetingBorder, CardMeetingStatusText,
            _latestScreenShares.Where(s => s.Category == ScreenShareCategory.MeetingScreenShare).ToList(),
            Loc.T("✅ Not sharing", "✅ 未共享屏幕", "✅ Sin compartir", "✅ 画面共有なし"));

        bool isDark = ThemeManager.IsCurrentlyDark;

        if (activeList.Count > 0)
        {
            GlobalAlertBanner.Background = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(88, 18, 30)
                : System.Windows.Media.Color.FromRgb(255, 230, 233));
            GlobalAlertBanner.BorderBrush = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(255, 68, 85)
                : System.Windows.Media.Color.FromRgb(207, 34, 46));
            BannerIconText.Text = "🚨";
            string details = string.Join(" / ", activeList.Select(a => $"{a.ToolName} ({a.ProcessName} -> {a.RemoteEndpoints})"));
            BannerMessageText.Text = Loc.T(
                $"[SCREEN LEAK / SHARE WARNING!] {details}",
                $"【屏幕外泄/共享警报！】 {details}",
                $"¡[ALERTA DE PANTALLA COMPARTIDA!] {details}",
                $"【画面流出警告！】 {details}");
            BannerMessageText.Foreground = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(255, 210, 215)
                : System.Windows.Media.Color.FromRgb(164, 14, 38));

            foreach (var act in activeList)
            {
                if (_notifiedScreenShareKeys.Add(act.DetectionKey))
                {
                    TriggerScreenSharePopupAndToast(act);
                }
            }
        }
        else if (standbyList.Count > 0)
        {
            GlobalAlertBanner.Background = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(48, 38, 16)
                : System.Windows.Media.Color.FromRgb(255, 248, 219));
            GlobalAlertBanner.BorderBrush = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(210, 153, 34)
                : System.Windows.Media.Color.FromRgb(191, 135, 0));
            BannerIconText.Text = "⚠️";
            string tools = string.Join(", ", standbyList.Select(s => s.ToolName));
            BannerMessageText.Text = Loc.T(
                $"Standby tools detected: {tools} (No active screen stream)",
                $"检测到待机工具: {tools} (当前无活动屏幕外泄)",
                $"Herramientas en espera detectadas: {tools} (Sin transmisión activa)",
                $"待機ツール検出: {tools} (アクティブな画面流出はありません)");
            BannerMessageText.Foreground = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(255, 223, 140)
                : System.Windows.Media.Color.FromRgb(125, 78, 0));
            _notifiedScreenShareKeys.Clear();
        }
        else
        {
            GlobalAlertBanner.Background = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(18, 38, 30)
                : System.Windows.Media.Color.FromRgb(226, 248, 233));
            GlobalAlertBanner.BorderBrush = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(35, 134, 54)
                : System.Windows.Media.Color.FromRgb(45, 164, 78));
            BannerIconText.Text = "✅";
            BannerMessageText.Text = Loc.T(
                "No screen leak or sharing detected (Monitoring RDP / AnyDesk / TeamViewer / VNC / Zoom / Teams)",
                "无屏幕外泄或共享 (正在监控 RDP / AnyDesk / TeamViewer / VNC / Zoom / Teams)",
                "Sin fuga ni pantalla compartida (Monitoreando RDP / AnyDesk / TeamViewer / VNC / Zoom / Teams)",
                "画面流出・共有なし (RDP / AnyDesk / TeamViewer / VNC / Zoom / Teams 監視中)");
            BannerMessageText.Foreground = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(126, 231, 135)
                : System.Windows.Media.Color.FromRgb(17, 99, 41));
            _notifiedScreenShareKeys.Clear();
        }
    }

    private static void UpdateCategoryCard(
        Border border,
        TextBlock statusText,
        List<ScreenShareDetectionItem> items,
        string safeDefaultText)
    {
        var active = items.FirstOrDefault(x => x.Status == ScreenShareStatus.ActiveStreaming);
        var standby = items.FirstOrDefault(x => x.Status == ScreenShareStatus.StandbyService);
        bool isDark = ThemeManager.IsCurrentlyDark;

        if (active != null)
        {
            border.Background = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(68, 18, 28)
                : System.Windows.Media.Color.FromRgb(255, 235, 238));
            border.BorderBrush = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(248, 81, 73)
                : System.Windows.Media.Color.FromRgb(207, 34, 46));
            statusText.Text = Loc.T(
                $"🚨 Active: {active.ToolName}",
                $"🚨 外泄中: {active.ToolName}",
                $"🚨 Activo: {active.ToolName}",
                $"🚨 流出中: {active.ToolName}");
            statusText.Foreground = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(255, 130, 140)
                : System.Windows.Media.Color.FromRgb(164, 14, 38));
        }
        else if (standby != null)
        {
            border.Background = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(44, 36, 20)
                : System.Windows.Media.Color.FromRgb(255, 248, 224));
            border.BorderBrush = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(210, 153, 34)
                : System.Windows.Media.Color.FromRgb(191, 135, 0));
            statusText.Text = Loc.T(
                $"⚠️ Standby: {standby.ToolName}",
                $"⚠️ 待机: {standby.ToolName}",
                $"⚠️ En espera: {standby.ToolName}",
                $"⚠️ 待機: {standby.ToolName}");
            statusText.Foreground = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(240, 195, 90)
                : System.Windows.Media.Color.FromRgb(125, 78, 0));
        }
        else
        {
            border.Background = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(25, 34, 49)
                : System.Windows.Media.Color.FromRgb(237, 242, 248));
            border.BorderBrush = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(46, 60, 84)
                : System.Windows.Media.Color.FromRgb(208, 215, 222));
            statusText.Text = safeDefaultText;
            statusText.Foreground = new SolidColorBrush(isDark
                ? System.Windows.Media.Color.FromRgb(63, 185, 80)
                : System.Windows.Media.Color.FromRgb(26, 127, 55));
        }
    }

    private void TriggerScreenSharePopupAndToast(ScreenShareDetectionItem item)
    {
        try
        {
            _notifyIcon?.ShowBalloonTip(
                5000,
                Loc.T(
                    $"🚨 Screen Share / Remote Access Detected: {item.ToolName}",
                    $"🚨 检测到屏幕共享/远程连接: {item.ToolName}",
                    $"🚨 Pantalla compartida / acceso remoto: {item.ToolName}",
                    $"🚨 画面共有・遠隔接続検知: {item.ToolName}"),
                $"{item.Evidence}\n{item.RemoteEndpoints}",
                WinForms.ToolTipIcon.Warning);

            if (_alertPopupWindow == null)
            {
                _alertPopupWindow = new AlertPopupWindow();
                _alertPopupWindow.OnInspectRequested += () =>
                {
                    ShowMainWindow();
                    MainTabControl.SelectedIndex = 1;
                };
            }
            _alertPopupWindow.UpdateAlertContent(item);
            _alertPopupWindow.Show();
        }
        catch { }
    }

    private void BannerInspectButton_Click(object sender, RoutedEventArgs e)
    {
        MainTabControl.SelectedIndex = 1;
    }

    private async void ClearSimulationButton_Click(object sender, RoutedEventArgs e)
    {
        await ClearAllSimulationsAsync();
    }

    private async void KillScreenShareProcessButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is ScreenShareDetectionItem item)
        {
            if (item.IsSimulated)
            {
                await ClearAllSimulationsAsync();
                return;
            }

            if (item.ProcessId <= 4)
            {
                System.Windows.MessageBox.Show(
                    Loc.T("System processes cannot be terminated.", "系统进程无法被终止。", "Los procesos del sistema no pueden terminarse.", "システムプロセスは終了できません。"),
                    Loc.T("Information", "提示", "Información", "確認"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            var ans = System.Windows.MessageBox.Show(
                Loc.T(
                    $"Are you sure you want to forcibly terminate '{item.ProcessName} (PID: {item.ProcessId})' to cut off screen sharing / remote access?\n\n*If it is a privileged service, a UAC elevation prompt will appear.",
                    $"确定要强制结束进程“{item.ProcessName} (PID: {item.ProcessId})”以切断屏幕共享/远程连接吗？\n\n※如果是高权限服务进程，将会弹出 UAC 管理员权限确认。",
                    $"¿Desea terminar forzosamente el proceso '{item.ProcessName} (PID: {item.ProcessId})' para cortar la pantalla compartida / acceso remoto?\n\n*Si es un servicio con privilegios, aparecerá una confirmación UAC.",
                    $"プロセス「{item.ProcessName} (PID: {item.ProcessId})」を強制終了して画面共有・遠隔接続を遮断しますか？\n\n※サービス等の高権限プロセスの場合、UAC（管理者権限の確認）が表示されます。"),
                Loc.T("Confirm Process Termination", "确认强制结束进程", "Confirmar terminación de proceso", "プロセス強制終了の確認"),
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (ans == MessageBoxResult.Yes)
            {
                await KillProcessWithUacFallbackAsync(item.ProcessId, item.ProcessName);
            }
        }
    }

    private async Task KillProcessWithUacFallbackAsync(int pid, string processName)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            proc.Kill(entireProcessTree: true);
            await Task.Delay(250);
            FooterStatusText.Text = Loc.T(
                $"🛑 Terminated process {processName} (PID:{pid}).",
                $"🛑 已结束进程 {processName} (PID:{pid})。",
                $"🛑 Proceso {processName} (PID:{pid}) terminado.",
                $"🛑 プロセス {processName} (PID:{pid}) を終了しました。");
            await RunScanCycleAsync();
            return;
        }
        catch (ArgumentException)
        {
            FooterStatusText.Text = Loc.T(
                $"ℹ️ Process {processName} (PID:{pid}) has already exited.",
                $"ℹ️ 进程 {processName} (PID:{pid}) 已经退出。",
                $"ℹ️ El proceso {processName} (PID:{pid}) ya ha terminado.",
                $"ℹ️ プロセス {processName} (PID:{pid}) は既に終了しています。");
            await RunScanCycleAsync();
            return;
        }
        catch (Exception)
        {
            // Fall through to UAC taskkill
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "taskkill.exe",
                Arguments = $"/F /PID {pid} /T",
                Verb = "runas",
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            using var elevatedProc = Process.Start(psi);
            if (elevatedProc != null)
            {
                await elevatedProc.WaitForExitAsync();
                await Task.Delay(300);

                bool stillRunning = true;
                try
                {
                    using var check = Process.GetProcessById(pid);
                    stillRunning = !check.HasExited;
                }
                catch (ArgumentException)
                {
                    stillRunning = false;
                }

                if (!stillRunning || elevatedProc.ExitCode == 0)
                {
                    FooterStatusText.Text = Loc.T(
                        $"🛡️ Terminated process {processName} (PID:{pid}) via UAC elevation.",
                        $"🛡️ 已通过管理员权限(UAC)强制结束进程 {processName} (PID:{pid})。",
                        $"🛡️ Proceso {processName} (PID:{pid}) terminado con privilegios de administrador (UAC).",
                        $"🛡️ 管理者権限(UAC)でプロセス {processName} (PID:{pid}) を強制終了しました。");
                    await RunScanCycleAsync();
                }
                else
                {
                    System.Windows.MessageBox.Show(
                        Loc.T(
                            $"Could not terminate '{processName} (PID:{pid})' even with administrator privileges (ExitCode: {elevatedProc.ExitCode}).",
                            $"即使使用管理员权限也无法结束进程“{processName} (PID:{pid})” (退出代码: {elevatedProc.ExitCode})。",
                            $"No se pudo terminar '{processName} (PID:{pid})' ni con privilegios de administrador (Código: {elevatedProc.ExitCode}).",
                            $"管理者権限でもプロセス「{processName} (PID:{pid})」を終了できませんでした (終了コード: {elevatedProc.ExitCode})。"),
                        Loc.T("Error", "错误", "Error", "エラー"),
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }
        catch (System.ComponentModel.Win32Exception w32Ex) when (w32Ex.NativeErrorCode == 1223)
        {
            FooterStatusText.Text = Loc.T(
                $"ℹ️ UAC prompt was canceled; termination of {processName} aborted.",
                $"ℹ️ 已取消 UAC 管理员权限确认，已中止结束 {processName}。",
                $"ℹ️ Confirmación UAC cancelada; se abortó la terminación de {processName}.",
                $"ℹ️ UAC（管理者権限）の確認がキャンセルされたため、{processName} の終了を中断しました。");
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(
                Loc.T($"Failed to terminate process:\n{ex.Message}", $"结束进程失败:\n{ex.Message}", $"Error al terminar el proceso:\n{ex.Message}", $"プロセスの終了に失敗しました:\n{ex.Message}"),
                Loc.T("Error", "错误", "Error", "エラー"),
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // ====================================================================
    // TAB 3: プロセス監視（瞬間ターミナル・周期的出現・未知プロセス）
    // ====================================================================
    private void ApplyProcessFilter()
    {
        if (ProcessDataGrid == null) return;

        IEnumerable<ProcessAnalysisItem> query = _latestProcesses;

        if (ExcludeMicrosoftProcCheck?.IsChecked == true)
        {
            query = query.Where(p => !p.IsMicrosoftSigned);
        }

        if (IncludeHistoricalProcCheck?.IsChecked != true)
        {
            // 過去の履歴（非稼働かつファイル不在、または24時間以上前の過去レコード）はデフォルトで除外
            query = query.Where(p => p.IsCurrentlyRunning || (!p.IsHistoricalOnly && p.IsFilePresent));
        }

        if (ProcFilterAnomalyRadio?.IsChecked == true)
        {
            query = query.Where(p => !p.IsUserTrusted && (p.IsTransientFlash || p.IsPeriodic || p.IsRareOrNew || p.RiskLevel >= RiskLevel.Medium || p.IsSelfProcess));
        }
        else if (ProcFilterTransientRadio?.IsChecked == true)
        {
            query = query.Where(p => p.IsTransientFlash && !p.IsUserTrusted);
        }
        else if (ProcFilterPeriodicRadio?.IsChecked == true)
        {
            query = query.Where(p => p.IsPeriodic);
        }
        else if (ProcFilterRareRadio?.IsChecked == true)
        {
            query = query.Where(p => (p.IsRareOrNew || p.IsSelfProcess) && !p.IsUserTrusted);
        }

        string search = ProcessSearchBox?.Text?.Trim() ?? "";
        if (!string.IsNullOrEmpty(search))
        {
            query = query.Where(p =>
                p.ProcessName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                p.ExecutablePath.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                p.CommandLine.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                p.ParentDisplay.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                p.MatchedScheduledTask.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                p.AnomalyReason.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                p.SignerName.Contains(search, StringComparison.OrdinalIgnoreCase));
        }

        var list = query.ToList();
        SetItemsSourcePreservingSort(ProcessDataGrid, list);
        if (ProcessSummaryCountText != null)
        {
            ProcessSummaryCountText.Text = Loc.T(
                $"{list.Count} / {_latestProcesses.Count} total",
                $"{list.Count}项 / 共{_latestProcesses.Count}项",
                $"{list.Count} / {_latestProcesses.Count} total",
                $"{list.Count}件 / 全{_latestProcesses.Count}件");
        }
    }

    private async void ScanRecentTasksButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ScanRecentTasksButton.IsEnabled = false;
            FooterStatusText.Text = Loc.T(
                "⏰ Scanning Windows Task Scheduler for tasks executed within the last 60 minutes...",
                "⏰ 正在从任务计划程序扫描最近 60 分钟内自动运行的计划任务...",
                "⏰ Escaneando el Programador de tareas en busca de tareas ejecutadas en los últimos 60 min...",
                "⏰ タスクスケジューラの全フォルダから直近60分以内に動いた定期タスクを調査中...");
            int count = await Task.Run(() => _processService.ImportRecentScheduledTasksToProcessList(withinMinutes: 60));
            await RunScanCycleAsync();
            if (ProcFilterTransientRadio != null)
                ProcFilterTransientRadio.IsChecked = true;
            ApplyProcessFilter();
            FooterStatusText.Text = Loc.T(
                $"⏰ Matched and imported {count} scheduled task(s) executed within the last 60 minutes.",
                $"⏰ 已比对并导入最近 60 分钟内执行的 {count} 个计划任务。",
                $"⏰ Se importaron {count} tarea(s) programada(s) ejecutadas en los últimos 60 minutos.",
                $"⏰ 直近60分以内に実行されたスケジュールタスク {count} 件を照合・一覧に反映しました。");
        }
        catch (Exception ex)
        {
            FooterStatusText.Text = Loc.T(
                $"⚠️ Scheduled task scan error: {ex.Message}",
                $"⚠️ 计划任务扫描错误: {ex.Message}",
                $"⚠️ Error al escanear tareas programadas: {ex.Message}",
                $"⚠️ 直近スケジュールタスク調査エラー: {ex.Message}");
        }
        finally
        {
            ScanRecentTasksButton.IsEnabled = true;
        }
    }

    private void ProcessFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        ApplyProcessFilter();
        UpdateTopKpis();
    }

    private void ProcessSearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!IsLoaded) return;
        ApplyProcessFilter();
    }

    private void TrustProcessButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is ProcessAnalysisItem item)
        {
            _processService.MarkAsTrusted(item);
            ApplyProcessFilter();
            UpdateTopKpis();
            FooterStatusText.Text = Loc.T(
                $"✅ Marked '{item.ProcessName}' as trusted (baseline).",
                $"✅ 已将“{item.ProcessName}”注册为信任（基线）进程。",
                $"✅ Se registró '{item.ProcessName}' como proceso confiable.",
                $"✅ 「{item.ProcessName}」を安全（ベースライン）として登録しました。");
        }
    }

    private void AddProcessToAiButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is ProcessAnalysisItem item)
        {
            if (item.IsSimulated || item.ProcessKey.StartsWith("sim:", StringComparison.OrdinalIgnoreCase))
            {
                FooterStatusText.Text = Loc.T(
                    "ℹ️ Simulated test items are not added to AI consultation logs.",
                    "ℹ️ 模拟测试数据不会添加到 AI 咨询日志中。",
                    "ℹ️ Los datos de simulación no se añaden a los registros de consulta IA.",
                    "ℹ️ テスト模擬データはAI相談ログには追加されません。");
                return;
            }

            _aiPromptService.AddManualProcessLog(item);
            RefreshAiAdvisorTab();
            UpdateTopKpis();
            MainTabControl.SelectedIndex = 4;
        }
    }

    // ====================================================================
    // TAB 4: システム防御・安全スコア
    // ====================================================================
    private void UpdateSystemDefenseTab()
    {
        if (DefenseFindingsDataGrid == null) return;

        bool isDark = ThemeManager.IsCurrentlyDark;
        int score = _latestPosture.Score;
        string grade = _latestPosture.Grade;

        ScoreGradeText.Text = grade;
        ScoreValueText.Text = Loc.T(
            $"Security Score: {score} / 100",
            $"安全评分: {score} / 100分",
            $"Puntuación: {score} / 100",
            $"安全スコア: {score} / 100点");
        ScoreCommentText.Text = _latestPosture.GradeComment;

        var gradeColor = score >= 80
            ? (isDark ? System.Windows.Media.Color.FromRgb(63, 185, 80) : System.Windows.Media.Color.FromRgb(26, 127, 55))
            : score >= 60
                ? (isDark ? System.Windows.Media.Color.FromRgb(230, 175, 45) : System.Windows.Media.Color.FromRgb(154, 103, 0))
                : (isDark ? System.Windows.Media.Color.FromRgb(255, 85, 95) : System.Windows.Media.Color.FromRgb(207, 34, 46));
        ScoreGradeText.Foreground = new SolidColorBrush(gradeColor);
        ScoreBadgeBorder.BorderBrush = new SolidColorBrush(gradeColor);

        int autoCnt = _latestFindings.Count(f => f.Category == FindingCategory.Autostart && f.EffectiveSeverity >= RiskLevel.Medium);
        int wmiCnt = _latestFindings.Count(f => f.Category == FindingCategory.WmiSubscription && f.EffectiveSeverity >= RiskLevel.Medium);
        int cmdCnt = _latestFindings.Count(f => f.Category == FindingCategory.CommandLine && f.EffectiveSeverity >= RiskLevel.Medium);
        int camCnt = _latestFindings.Count(f => f.Category == FindingCategory.CameraMic && (f.State == FindingState.Active || f.EffectiveSeverity >= RiskLevel.Medium));
        int keyClipCnt = _latestFindings.Count(f => f.Category is FindingCategory.Keylogger or FindingCategory.Clipboard && f.EffectiveSeverity >= RiskLevel.Medium);
        int usbDllCnt = _latestFindings.Count(f => f.Category is FindingCategory.UsbDevice or FindingCategory.DllSideload && f.EffectiveSeverity >= RiskLevel.Medium);
        int certAccCnt = _latestFindings.Count(f => f.Category is FindingCategory.RootCertificate or FindingCategory.Account or FindingCategory.AdminGroup && f.EffectiveSeverity >= RiskLevel.Medium);

        DefenseSummaryCountsText.Text = Loc.T(
            $"Notable — 🚀Autostart:{autoCnt}  👻WMI:{wmiCnt}  ⌨️Cmd:{cmdCnt}  📷Cam/Mic:{camCnt}  🎹Key/📋Clip:{keyClipCnt}  🔌USB/🧩DLL:{usbDllCnt}  📜Cert/🔐Logon/👑Admin:{certAccCnt}",
            $"需注意项 — 🚀自启动:{autoCnt}  👻WMI:{wmiCnt}  ⌨️命令:{cmdCnt}  📷摄像/麦克:{camCnt}  🎹按键/📋剪贴:{keyClipCnt}  🔌USB/🧩DLL:{usbDllCnt}  📜证书/🔐登录/👑管理员:{certAccCnt}",
            $"Atención — 🚀Autoinicio:{autoCnt}  👻WMI:{wmiCnt}  ⌨️Cmd:{cmdCnt}  📷Cám/Mic:{camCnt}  🎹Tecla/📋Portap:{keyClipCnt}  🔌USB/🧩DLL:{usbDllCnt}  📜Cert/🔐Sesión/👑Admin:{certAccCnt}",
            $"要注意内訳 — 🚀自動起動:{autoCnt}  👻WMI:{wmiCnt}  ⌨️コマンド:{cmdCnt}  📷カメラ/マイク:{camCnt}  🎹キー/📋クリップ:{keyClipCnt}  🔌USB/🧩DLL:{usbDllCnt}  📜証明書/🔐ログオン/👑管理者:{certAccCnt}");

        SecurityPostureDataGrid.ItemsSource = _latestPosture.Checks.ToList();
        ApplyDefenseFilter();
    }

    private void ApplyDefenseFilter()
    {
        if (DefenseFindingsDataGrid == null) return;

        IEnumerable<SystemFindingItem> query = _latestFindings;

        if (DefFilterRiskyRadio?.IsChecked == true)
        {
            query = query.Where(f => !f.IsAcknowledged && (f.EffectiveSeverity >= RiskLevel.Medium || f.State == FindingState.Active || f.State == FindingState.New || f.IsSimulated));
        }
        else if (DefFilterAutostartRadio?.IsChecked == true)
        {
            query = query.Where(f => f.Category is FindingCategory.Autostart or FindingCategory.WmiSubscription);
        }
        else if (DefFilterCmdRadio?.IsChecked == true)
        {
            query = query.Where(f => f.Category is FindingCategory.CommandLine or FindingCategory.DllSideload);
        }
        else if (DefFilterPrivacyRadio?.IsChecked == true)
        {
            query = query.Where(f => f.Category is FindingCategory.CameraMic or FindingCategory.Keylogger or FindingCategory.Clipboard or FindingCategory.UsbDevice);
        }
        else if (DefFilterCertAccountRadio?.IsChecked == true)
        {
            query = query.Where(f => f.Category is FindingCategory.RootCertificate or FindingCategory.Account or FindingCategory.AdminGroup);
        }

        string search = DefenseSearchBox?.Text?.Trim() ?? "";
        if (!string.IsNullOrEmpty(search))
        {
            query = query.Where(f =>
                f.Title.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                f.Detail.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                f.Target.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                f.CategoryLabel.Contains(search, StringComparison.OrdinalIgnoreCase));
        }

        var list = query.ToList();
        DefenseFindingsDataGrid.ItemsSource = list;
        if (DefenseCountText != null)
        {
            DefenseCountText.Text = Loc.T(
                $"{list.Count} / {_latestFindings.Count} total",
                $"{list.Count}项 / 共{_latestFindings.Count}项",
                $"{list.Count} / {_latestFindings.Count} total",
                $"{list.Count}件 / 全{_latestFindings.Count}件");
        }
    }

    private void UpdateTogglePostureButtonText()
    {
        if (TogglePostureViewButton == null) return;
        TogglePostureViewButton.Content = _showingPostureChecklist
            ? Loc.T(
                "🛡️ Back to System Defense Findings",
                "🛡️ 返回系统防御检测列表",
                "🛡️ Volver a hallazgos de defensa",
                "🛡️ システム防御検知一覧に戻る")
            : Loc.T(
                "📊 View 10-Item Security Score Checklist",
                "📊 查看安全评分 10 项诊断详情",
                "📊 Ver diagnóstico de 10 puntos de seguridad",
                "📊 安全スコア10項目診断を表示");
    }

    private void DefenseFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        if (_showingPostureChecklist)
        {
            _showingPostureChecklist = false;
            SecurityPostureDataGrid.Visibility = Visibility.Collapsed;
            DefenseFindingsDataGrid.Visibility = Visibility.Visible;
            UpdateTogglePostureButtonText();
        }
        ApplyDefenseFilter();
    }

    private void DefenseSearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!IsLoaded) return;
        ApplyDefenseFilter();
    }

    private void TogglePostureViewButton_Click(object sender, RoutedEventArgs e)
    {
        _showingPostureChecklist = !_showingPostureChecklist;
        if (_showingPostureChecklist)
        {
            DefenseFindingsDataGrid.Visibility = Visibility.Collapsed;
            SecurityPostureDataGrid.Visibility = Visibility.Visible;
        }
        else
        {
            SecurityPostureDataGrid.Visibility = Visibility.Collapsed;
            DefenseFindingsDataGrid.Visibility = Visibility.Visible;
        }
        UpdateTogglePostureButtonText();
    }

    private void AcknowledgeFindingButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is SystemFindingItem item)
        {
            _systemDefenseService.AcknowledgeFinding(item);
            ApplyDefenseFilter();
            UpdateSystemDefenseTab();
            UpdateTopKpis();
            FooterStatusText.Text = Loc.T(
                $"✅ Acknowledged '{item.Title}'.",
                $"✅ 已将“{item.Title}”标记为已确认。",
                $"✅ Se marcó '{item.Title}' como aceptado.",
                $"✅ 「{item.Title}」を承認済みとして登録しました。");
        }
    }

    private void OpenFindingLocationButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is SystemFindingItem item)
        {
            try
            {
                string path = !string.IsNullOrWhiteSpace(item.OpenLocationPath) ? item.OpenLocationPath : item.Target;
                if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
                {
                    Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
                    FooterStatusText.Text = Loc.T(
                        $"📂 Opened file location: {path}",
                        $"📂 已打开文件所在位置: {path}",
                        $"📂 Ubicación abierta: {path}",
                        $"📂 ファイルの場所を開きました: {path}");
                }
                else if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
                {
                    Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true });
                }
                else
                {
                    System.Windows.Clipboard.SetText(item.Target);
                    FooterStatusText.Text = Loc.T(
                        $"📋 Copied target path/ID to clipboard: {item.Target}",
                        $"📋 已将目标路径/ID复制到剪贴板: {item.Target}",
                        $"📋 Ruta/ID copiada al portapapeles: {item.Target}",
                        $"📋 対象パス/IDをクリップボードにコピーしました: {item.Target}");
                }
            }
            catch { }
        }
    }

    private void AddFindingToAiButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is SystemFindingItem item)
        {
            _aiPromptService.AddManualDefenseFindingLog(item);
            RefreshAiAdvisorTab();
            UpdateTopKpis();
            MainTabControl.SelectedIndex = 4;
        }
    }

    private void OpenPostureFixButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is SecurityCheckItem chk && !string.IsNullOrWhiteSpace(chk.FixCommand))
        {
            LaunchSystemTool(chk.FixCommand, chk.Name);
        }
    }

    // ====================================================================
    // TAB 5: AIに相談すべきログ＆プロンプト生成
    // ====================================================================
    private void RefreshAiAdvisorTab()
    {
        bool includeHistorical = IncludeHistoryAiLogsCheckBox?.IsChecked == true;
        var allLogs = _aiPromptService.GetAllLogs();
        var displayLogs = includeHistorical
            ? allLogs.ToList()
            : allLogs.Where(x => !x.IsHistoricalRecord).ToList();

        AiLogsDataGrid.ItemsSource = displayLogs;
        RebuildAiPromptPreview();
    }

    private void RebuildAiPromptPreview()
    {
        if (AiPromptPreviewBox == null) return;
        bool includeHistorical = IncludeHistoryAiLogsCheckBox?.IsChecked == true;
        var selectedLogs = _aiPromptService.GetAllLogs()
            .Where(x => x.IsSelected && (includeHistorical || !x.IsHistoricalRecord))
            .ToList();
        string userNote = UserNoteTextBox?.Text ?? "";

        AiPromptPreviewBox.Text = _aiPromptService.BuildAiConsultationPrompt(selectedLogs, MaskPersonalInfoOption, userNote);
    }

    private void AiLogSelection_Changed(object sender, RoutedEventArgs e)
    {
        RebuildAiPromptPreview();
    }

    private void PromptOptions_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        RebuildAiPromptPreview();
    }

    private void IncludeHistoryAiLogsCheckBox_Click(object sender, RoutedEventArgs e)
    {
        bool includeHistorical = IncludeHistoryAiLogsCheckBox?.IsChecked == true;
        _aiPromptService.SetHistoricalSelection(includeHistorical);
        RefreshAiAdvisorTab();
    }

    private void SelectAllAiLogs_Click(object sender, RoutedEventArgs e)
    {
        bool includeHistorical = IncludeHistoryAiLogsCheckBox?.IsChecked == true;
        _aiPromptService.SelectAllLogs(includeHistorical);
        RefreshAiAdvisorTab();
    }

    private void DeselectAllAiLogs_Click(object sender, RoutedEventArgs e)
    {
        if (AiLogsDataGrid.ItemsSource is IEnumerable<SecurityLogEntry> displayList)
        {
            foreach (var log in displayList)
                log.IsSelected = false;
        }
        else
        {
            foreach (var log in _aiPromptService.GetAllLogs())
                log.IsSelected = false;
        }
        RefreshAiAdvisorTab();
    }

    private void AddSystemSnapshotLog_Click(object sender, RoutedEventArgs e)
    {
        _aiPromptService.IngestFromMonitors(
            _latestConnections,
            _latestScreenShares,
            _latestProcesses,
            out _,
            _latestFindings);
        _aiPromptService.AddSystemSnapshotLog(_latestConnections, _latestScreenShares, _latestProcesses, _latestPosture, _latestFindings);
        RefreshAiAdvisorTab();
        UpdateTopKpis();
        MainTabControl.SelectedIndex = 4;
        CopyStatusText.Text = Loc.T(
            $"📸 Captured full PC snapshot & notable logs ({DateTime.Now:HH:mm:ss})",
            $"📸 已采集电脑完整快照与检测日志 ({DateTime.Now:HH:mm:ss})",
            $"📸 Instantánea completa del PC y registros capturados ({DateTime.Now:HH:mm:ss})",
            $"📸 PC全体スナップショットと検出ログを採取しました ({DateTime.Now:HH:mm:ss})");
    }

    private void ClearAiLogs_Click(object sender, RoutedEventArgs e)
    {
        _aiPromptService.ClearLogs();
        RefreshAiAdvisorTab();
        UpdateTopKpis();
    }

    private void CopyAiPromptButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            RebuildAiPromptPreview();
            System.Windows.Clipboard.SetText(AiPromptPreviewBox.Text);
            CopyStatusText.Text = Loc.T(
                $"✨ Copied! ({DateTime.Now:HH:mm:ss}) — Paste into your AI assistant",
                $"✨ 复制成功 ({DateTime.Now:HH:mm:ss}) — 请粘贴给 AI 助手",
                $"✨ ¡Copiado! ({DateTime.Now:HH:mm:ss}) — Péguelo en su asistente de IA",
                $"✨ コピー完了 ({DateTime.Now:HH:mm:ss}) — AIに貼り付けてください");
            CopyStatusText.Foreground = new SolidColorBrush(ThemeManager.IsCurrentlyDark
                ? System.Windows.Media.Color.FromRgb(126, 231, 135)
                : System.Windows.Media.Color.FromRgb(26, 127, 55));
            FooterStatusText.Text = Loc.T(
                "📋 Copied AI consultation prompt to clipboard.",
                "📋 已将 AI 咨询提示词复制到剪贴板。",
                "📋 Prompt de consulta IA copiado al portapapeles.",
                "📋 AI相談用プロンプトをクリップボードにコピーしました。");
        }
        catch (Exception ex)
        {
            CopyStatusText.Text = Loc.T(
                $"⚠️ Copy failed: {ex.Message}",
                $"⚠️ 复制失败: {ex.Message}",
                $"⚠️ Error al copiar: {ex.Message}",
                $"⚠️ コピー失敗: {ex.Message}");
        }
    }

    // ====================================================================
    // MENU BAR & SETTINGS DIALOG API
    // ====================================================================
    private void OpenSettingsMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_settingsWindow == null || !_settingsWindow.IsLoaded)
        {
            _settingsWindow = new SettingsWindow(this);
            _settingsWindow.Closed += (_, _) => _settingsWindow = null;
            _settingsWindow.Show();
        }
        else
        {
            _settingsWindow.Activate();
        }
    }

    private void OpenAboutMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_aboutWindow == null || !_aboutWindow.IsLoaded)
        {
            _aboutWindow = new AboutWindow
            {
                Owner = this
            };
            _aboutWindow.Closed += (_, _) => _aboutWindow = null;
            _aboutWindow.Show();
        }
        else
        {
            _aboutWindow.Activate();
        }
    }

    private void SwitchTab0_Click(object sender, RoutedEventArgs e) => MainTabControl.SelectedIndex = 0;
    private void SwitchTab1_Click(object sender, RoutedEventArgs e) => MainTabControl.SelectedIndex = 1;
    private void SwitchTab2_Click(object sender, RoutedEventArgs e) => MainTabControl.SelectedIndex = 2;
    private void SwitchTab3_Click(object sender, RoutedEventArgs e) => MainTabControl.SelectedIndex = 3;
    private void SwitchTab4_Click(object sender, RoutedEventArgs e) => MainTabControl.SelectedIndex = 4;

    private void LaunchWindowsTool_Click(object sender, RoutedEventArgs e)
    {
        if (sender is MenuItem mi && mi.Tag is string targetCommand)
        {
            string label = mi.Header?.ToString() ?? targetCommand;
            LaunchSystemTool(targetCommand, label);
        }
    }

    private void LaunchSystemTool(string targetCommand, string displayName)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = targetCommand,
                UseShellExecute = true
            };
            Process.Start(psi);
            FooterStatusText.Text = Loc.T(
                $"🚀 Launched: {displayName} ({targetCommand})",
                $"🚀 已启动: {displayName} ({targetCommand})",
                $"🚀 Iniciado: {displayName} ({targetCommand})",
                $"🚀 起動しました: {displayName} ({targetCommand})");
        }
        catch (Exception ex)
        {
            FooterStatusText.Text = Loc.T(
                $"⚠️ Tool launch canceled or failed ({targetCommand}): {ex.Message}",
                $"⚠️ 工具启动被取消或失败 ({targetCommand}): {ex.Message}",
                $"⚠️ Inicio de herramienta cancelado o fallido ({targetCommand}): {ex.Message}",
                $"⚠️ ツール起動キャンセルまたは失敗 ({targetCommand}): {ex.Message}");
        }
    }

    private void ExitMenuItem_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void TogglePauseButton_Click(object sender, RoutedEventArgs e)
    {
        _isPaused = !_isPaused;
        if (_isPaused)
        {
            PauseResumeMenuItem.Header = Loc.T("▶️ Resume Monitoring(_P)", "▶️ 恢复监控(_P)", "▶️ Reanudar monitoreo(_P)", "▶️ 監視の再開(_P)");
            UpdateMonitoringStatusText();
        }
        else
        {
            PauseResumeMenuItem.Header = Loc.T("⏸️ Pause Monitoring(_P)", "⏸️ 暂停监控(_P)", "⏸️ Pausar monitoreo(_P)", "⏸️ 監視の一時停止(_P)");
            UpdateMonitoringStatusText();
            _ = RunScanCycleAsync();
        }
    }

    private async void ManualRefreshButton_Click(object sender, RoutedEventArgs e)
    {
        await RunScanCycleAsync();
    }

    private void PauseNetworkUpdateButton_Click(object sender, RoutedEventArgs e)
    {
        _isNetworkPaused = !_isNetworkPaused;
        UpdatePauseButtonsState();
        if (!_isNetworkPaused)
        {
            RebuildCountrySummaries();
            ApplyNetworkFilter();
        }
    }

    private void PauseProcessUpdateButton_Click(object sender, RoutedEventArgs e)
    {
        _isProcessPaused = !_isProcessPaused;
        UpdatePauseButtonsState();
        if (!_isProcessPaused)
        {
            ApplyProcessFilter();
        }
    }

    private void UpdatePauseButtonsState()
    {
        if (PauseNetworkUpdateButton != null)
        {
            if (_isNetworkPaused)
            {
                PauseNetworkUpdateButton.Content = Loc.T("▶️ Resume Updates", "▶️ 恢复刷新", "▶️ Reanudar", "▶️ 更新再開");
                PauseNetworkUpdateButton.ToolTip = Loc.T(
                    "Resume automatic table updates and refresh with latest data",
                    "恢复表格自动刷新并立即同步最新数据",
                    "Reanudar actualización automática y sincronizar",
                    "自動更新を再開し、最新データへ同期します");
                PauseNetworkUpdateButton.Background = new SolidColorBrush(System.Windows.Media.Color.FromArgb(60, 234, 179, 8));
            }
            else
            {
                PauseNetworkUpdateButton.Content = Loc.T("⏸️ Pause Updates", "⏸️ 暂停刷新", "⏸️ Pausar", "⏸️ 更新一時停止");
                PauseNetworkUpdateButton.ToolTip = Loc.T(
                    "Pause automatic table updates to inspect or sort items without disruption",
                    "暂停表格自动刷新，以便排序或仔细排查",
                    "Pausar actualización automática para ordenar o inspeccionar",
                    "自動更新を一時停止し、ソート順や選択行を固定して確認します");
                PauseNetworkUpdateButton.ClearValue(BackgroundProperty);
            }
        }

        if (PauseProcessUpdateButton != null)
        {
            if (_isProcessPaused)
            {
                PauseProcessUpdateButton.Content = Loc.T("▶️ Resume Updates", "▶️ 恢复刷新", "▶️ Reanudar", "▶️ 更新再開");
                PauseProcessUpdateButton.ToolTip = Loc.T(
                    "Resume automatic table updates and refresh with latest data",
                    "恢复表格自动刷新并立即同步最新数据",
                    "Reanudar actualización automática y sincronizar",
                    "自動更新を再開し、最新データへ同期します");
                PauseProcessUpdateButton.Background = new SolidColorBrush(System.Windows.Media.Color.FromArgb(60, 234, 179, 8));
            }
            else
            {
                PauseProcessUpdateButton.Content = Loc.T("⏸️ Pause Updates", "⏸️ 暂停刷新", "⏸️ Pausar", "⏸️ 更新一時停止");
                PauseProcessUpdateButton.ToolTip = Loc.T(
                    "Pause automatic table updates to inspect or sort items without disruption",
                    "暂停表格自动刷新，以便排序或仔细排查",
                    "Pausar actualización automática para ordenar o inspeccionar",
                    "自動更新を一時停止し、ソート順や選択行を固定して確認します");
                PauseProcessUpdateButton.ClearValue(BackgroundProperty);
            }
        }
    }

    private static void SetItemsSourcePreservingSort(DataGrid grid, System.Collections.IEnumerable items)
    {
        if (grid == null) return;

        var sortDescriptions = grid.Items.SortDescriptions
            .Select(sd => new SortDescription(sd.PropertyName, sd.Direction))
            .ToList();

        var selectedItem = grid.SelectedItem;

        grid.ItemsSource = items;

        if (sortDescriptions.Count > 0 && grid.ItemsSource != null)
        {
            var view = CollectionViewSource.GetDefaultView(grid.ItemsSource);
            if (view != null)
            {
                using (view.DeferRefresh())
                {
                    view.SortDescriptions.Clear();
                    foreach (var sd in sortDescriptions)
                    {
                        view.SortDescriptions.Add(sd);
                    }
                }
            }
        }

        if (selectedItem != null)
        {
            grid.SelectedItem = selectedItem;
        }
    }

    public void SetLanguage(AppLanguage language)
    {
        LocalizationManager.ApplyLanguage(language);
        SettingsManager.Current.Language = language;
        SettingsManager.Save();
        string langLabel = LocalizationManager.GetLanguageDisplayName(language);
        FooterStatusText.Text = Loc.T(
            $"🌐 Language changed: {langLabel}",
            $"🌐 语言已切换: {langLabel}",
            $"🌐 Idioma cambiado: {langLabel}",
            $"🌐 表示言語を変更: {langLabel}");
    }

    public void SetThemeMode(AppThemeMode mode)
    {
        ThemeManager.ApplyTheme(mode);
        SettingsManager.Current.ThemeMode = mode;
        SettingsManager.Save();
        string modeLabel = mode switch
        {
            AppThemeMode.Light => Loc.T("☀️ Light Mode", "☀️ 浅色模式", "☀️ Modo Claro", "☀️ ライトモード"),
            AppThemeMode.Dark => Loc.T("🌙 Dark Mode", "🌙 深色模式", "🌙 Modo Oscuro", "🌙 ダークモード"),
            _ => Loc.T(
                $"🔄 System Default ({(ThemeManager.IsCurrentlyDark ? "Dark" : "Light")})",
                $"🔄 跟随系统 ({(ThemeManager.IsCurrentlyDark ? "深色" : "浅色")})",
                $"🔄 Sistema ({(ThemeManager.IsCurrentlyDark ? "Oscuro" : "Claro")})",
                $"🔄 システム設定に追従 ({(ThemeManager.IsCurrentlyDark ? "ダーク" : "ライト")})")
        };
        FooterStatusText.Text = Loc.T(
            $"🎨 Theme changed: {modeLabel}",
            $"🎨 主题已更改: {modeLabel}",
            $"🎨 Tema cambiado: {modeLabel}",
            $"🎨 テーマ変更: {modeLabel}");
    }

    public void SetScanInterval(ScanIntervalMode mode)
    {
        ScanIntervalOption = mode;
        SettingsManager.Current.ScanInterval = mode;
        SettingsManager.Save();

        _monitorTimer.Interval = TimeSpan.FromSeconds((int)mode);

        string modeLabel = mode switch
        {
            ScanIntervalMode.Fast => Loc.T("Fast (3s)", "高速 (3秒)", "Rápido (3s)", "高速 (3秒)"),
            ScanIntervalMode.Standard => Loc.T("Standard (5s)", "标准 (5秒)", "Estándar (5s)", "標準 (5秒)"),
            ScanIntervalMode.PowerSaving => Loc.T("Power Saving (15s)", "省电 (15秒)", "Ahorro de energía (15s)", "省電力 (15秒)"),
            _ => $"{mode}"
        };

        FooterStatusText.Text = Loc.T(
            $"⚡ Scan interval changed: {modeLabel}",
            $"⚡ 扫描间隔已更改: {modeLabel}",
            $"⚡ Intervalo de escaneo cambiado: {modeLabel}",
            $"⚡ スキャン間隔を変更: {modeLabel}");
    }

    private void UpdateMonitoringStatusText()
    {
        if (FooterStatusText == null) return;
        if (_isPaused)
        {
            FooterStatusText.Text = Loc.T("⏸️ Monitoring paused", "⏸️ 监控已暂停", "⏸️ Monitoreo en pausa", "⏸️ 監視一時停止中");
        }
        else
        {
            int sec = (int)ScanIntervalOption;
            FooterStatusText.Text = Loc.T(
                $"🟢 Real-time monitoring active ({sec}s cycle)",
                $"🟢 实时监控运行中 ({sec}秒周期)",
                $"🟢 Monitoreo activo en tiempo real (ciclo {sec}s)",
                $"🟢 リアルタイム監視稼働中 ({sec}秒周期)");
        }
    }

    public async Task UpdateScanAndPromptOptionsAsync(
        bool includeLoopback,
        bool includeListen,
        bool includeUdp,
        bool maskPersonalInfo,
        bool enableDllSideloadCheck = false,
        bool disableOnlineGeoIp = false)
    {
        IncludeLoopbackOption = includeLoopback;
        IncludeListenOption = includeListen;
        IncludeUdpOption = includeUdp;
        MaskPersonalInfoOption = maskPersonalInfo;
        EnableDllSideloadCheckOption = enableDllSideloadCheck;
        DisableOnlineGeoIpOption = disableOnlineGeoIp;
        if (IncludeUdpToolbarCheck != null)
            IncludeUdpToolbarCheck.IsChecked = includeUdp;

        SettingsManager.Current.IncludeLoopback = includeLoopback;
        SettingsManager.Current.IncludeListen = includeListen;
        SettingsManager.Current.IncludeUdp = includeUdp;
        SettingsManager.Current.MaskPersonalInfo = maskPersonalInfo;
        SettingsManager.Current.EnableDllSideloadCheck = enableDllSideloadCheck;
        SettingsManager.Current.DisableOnlineGeoIp = disableOnlineGeoIp;
        SettingsManager.Save();

        _geoIpService.DisableOnlineLookup = disableOnlineGeoIp;

        CopyStatusText.Text = MaskPersonalInfoOption
            ? Loc.T(
                "💡 Click button to copy prompt (Personal info masking: ON)",
                "💡 点击按钮即可复制提示词（个人信息打码：开启）",
                "💡 Haga clic para copiar el prompt (Ocultar datos personales: SÍ)",
                "💡 ボタンを押すとコピーされます (個人情報マスク: 有効)")
            : Loc.T(
                "💡 Click button to copy prompt (Personal info masking: OFF)",
                "💡 点击按钮即可复制提示词（个人信息打码：关闭）",
                "💡 Haga clic para copiar el prompt (Ocultar datos personales: NO)",
                "💡 ボタンを押すとコピーされます (個人情報マスク: 無効)");

        await RunScanCycleAsync();
        RefreshAiAdvisorTab();
    }

    public async Task TriggerDemoSimulationAllAsync()
    {
        _notifiedScreenShareKeys.Clear();
        _screenShareService.TriggerSimulation(
            Loc.T("AnyDesk External Remote Connection", "AnyDesk 外部远程连接", "Conexión Remota Externa AnyDesk", "AnyDesk 外部リモート接続"),
            ScreenShareCategory.RemoteDesktopTool,
            Loc.T(
                "AnyDesk.exe is streaming screen frames to external IP (198.51.100.42:7070)",
                "AnyDesk.exe 正在向外部 IP (198.51.100.42:7070) 发送屏幕流",
                "AnyDesk.exe está transmitiendo la pantalla a la IP externa (198.51.100.42:7070)",
                "AnyDesk.exe が外部IP (198.51.100.42:7070) へ画面ストリームを送信中"));
        _processService.InjectSimulatedAnomalies();
        _systemDefenseService.InjectSimulatedFindings();

        await RunScanCycleAsync();
        RefreshAiAdvisorTab();
        FooterStatusText.Text = Loc.T(
            "🧪 All simulations triggered (Click 'Clear Sim' to reset)",
            "🧪 已触发全部模拟警报（点击“清除模拟”可恢复）",
            "🧪 Simulaciones activadas (Clic en 'Limpiar Sim' para restaurar)",
            "🧪 一括テスト発報中（「テスト解除」で元に戻せます）");
    }

    public async Task TriggerSimSystemDefenseAsync()
    {
        _systemDefenseService.InjectSimulatedFindings();
        await RunScanCycleAsync();
        MainTabControl.SelectedIndex = 3;
        FooterStatusText.Text = Loc.T(
            "🧪 Injected System Defense simulations (obfuscated cmd, autostart, webcam, BadUSB, cert, admin).",
            "🧪 已注入系统防御模拟数据（混淆命令、自启动、摄像头、BadUSB、证书、管理员添加）。",
            "🧪 Datos simulados de Defensa del Sistema inyectados (cmd ofuscado, autoinicio, cámara, BadUSB, cert, admin).",
            "🧪 システム防御 (難読化コマンド・自動起動・カメラ・BadUSB・証明書・管理者追加) の模擬データを注入しました。");
    }

    public async Task TriggerSimAnyDeskAsync()
    {
        _notifiedScreenShareKeys.Clear();
        _screenShareService.TriggerSimulation(
            Loc.T("AnyDesk Remote Desktop", "AnyDesk 远程桌面", "Escritorio Remoto AnyDesk", "AnyDesk リモートデスクトップ"),
            ScreenShareCategory.RemoteDesktopTool,
            Loc.T(
                "AnyDesk.exe established session with external relay server (TCP 7070) and is transmitting screen frames",
                "AnyDesk.exe 已与外部中继服务器 (TCP 7070) 建立会话并正在传输屏幕画面",
                "AnyDesk.exe estableció sesión con servidor externo (TCP 7070) y transmite cuadros de pantalla",
                "AnyDesk.exe が外部リレーサーバー (TCP 7070) とセッション確立・画面フレーム送信中"));
        await RunScanCycleAsync();
        RefreshAiAdvisorTab();
    }

    public async Task TriggerSimZoomShareAsync()
    {
        _notifiedScreenShareKeys.Clear();
        _screenShareService.TriggerSimulation(
            Loc.T("Zoom Screen Share (CptHost)", "Zoom 屏幕共享 (CptHost)", "Zoom Pantalla Compartida (CptHost)", "Zoom 画面共有 (CptHost)"),
            ScreenShareCategory.MeetingScreenShare,
            Loc.T(
                "Detected Zoom screen capture host (CptHost.exe) and active screen share overlay frame",
                "检测到 Zoom 屏幕捕获进程 (CptHost.exe) 及屏幕共享叠加边框正在运行",
                "Se detectó el host de captura de Zoom (CptHost.exe) y el marco de pantalla compartida",
                "Zoom画面キャプチャホスト (CptHost.exe) および画面共有オーバーレイ枠の稼働を検知"));
        await RunScanCycleAsync();
        RefreshAiAdvisorTab();
    }

    public async Task TriggerSimRdpAsync()
    {
        _notifiedScreenShareKeys.Clear();
        _screenShareService.TriggerSimulation(
            Loc.T("Windows Remote Desktop (Inbound RDP)", "Windows 远程桌面 (RDP入站)", "Escritorio Remoto de Windows (RDP entrante)", "Windows リモートデスクトップ (RDP着信)"),
            ScreenShareCategory.WindowsRdp,
            Loc.T(
                "Detected active WTS remote session and ESTABLISHED traffic on TCP port 3389",
                "检测到活动 WTS 远程会话及 TCP 3389 端口 ESTABLISHED 连接",
                "Sesión remota WTS activa y conexión ESTABLISHED en puerto TCP 3389 detectadas",
                "WTSリモートセッション確立および TCP 3389番ポート ESTABLISHED 通信を検知"));
        await RunScanCycleAsync();
        RefreshAiAdvisorTab();
    }

    public async Task TriggerSimProcessesAsync()
    {
        _processService.InjectSimulatedAnomalies();
        await RunScanCycleAsync();
        MainTabControl.SelectedIndex = 2;
        RefreshAiAdvisorTab();
        FooterStatusText.Text = Loc.T(
            "🧪 Injected simulated 0.3s flash terminal, periodic, and unknown processes.",
            "🧪 已注入 0.3 秒瞬时终端、周期进程及未知进程的模拟测试数据。",
            "🧪 Se inyectaron datos simulados de terminal fugaz de 0.3s, proceso periódico y desconocido.",
            "🧪 0.3秒の瞬間ターミナル・周期・未知プロセスのテストデータを注入しました。");
    }

    public async Task ClearAllSimulationsAsync()
    {
        _screenShareService.ClearSimulation();
        _processService.RemoveSimulatedAnomalies();
        _systemDefenseService.ClearSimulatedFindings();
        _aiPromptService.RemoveSimulatedLogs();
        _notifiedScreenShareKeys.Clear();
        _alertPopupWindow?.Hide();
        await RunScanCycleAsync();
        RefreshAiAdvisorTab();
        FooterStatusText.Text = Loc.T(
            "🧹 Cleared all simulated alerts and test data.",
            "🧹 已清除所有模拟警报与测试数据。",
            "🧹 Se limpiaron todas las alertas y datos de simulación.",
            "🧹 テスト警報・テストデータを解除しました。");
    }

    private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        _processService.SaveBaselineSafe();
        _processService.Dispose();
        _geoIpService.Dispose();
        _settingsWindow?.Close();
        _alertPopupWindow?.Close();
        if (_notifyIcon != null)
        {
            _notifyIcon.Visible = false;
            _notifyIcon.Dispose();
            _notifyIcon = null;
        }
    }
}
