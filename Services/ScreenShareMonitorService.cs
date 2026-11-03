using System.Diagnostics;
using AnzenSecurityWatcher.Models;

namespace AnzenSecurityWatcher.Services;

public class ScreenShareMonitorService
{
    private record RemoteToolDefinition(
        string ToolName,
        ScreenShareCategory Category,
        string[] ProcessNames,
        string[] ActiveSessionHelperProcesses,
        int[] CharacteristicPorts);

    private static readonly List<RemoteToolDefinition> KnownRemoteTools = new()
    {
        new("AnyDesk", ScreenShareCategory.RemoteDesktopTool,
            new[] { "AnyDesk" },
            new[] { "AnyDesk" },
            new[] { 7070, 6568 }),

        new("TeamViewer", ScreenShareCategory.RemoteDesktopTool,
            new[] { "TeamViewer", "TeamViewer_Service", "tv_w32", "tv_x64" },
            new[] { "TeamViewer_Desktop" },
            new[] { 5938 }),

        new("VNC (UltraVNC / TightVNC / RealVNC)", ScreenShareCategory.RemoteDesktopTool,
            new[] { "winvnc", "tvnserver", "uvnc_service", "vncserver", "vncviewer", "winvnc4" },
            new[] { "winvnc", "tvnserver", "vncserver" },
            new[] { 5900, 5901, 5902, 5800 }),

        new("RustDesk", ScreenShareCategory.RemoteDesktopTool,
            new[] { "rustdesk" },
            new[] { "rustdesk" },
            new[] { 21115, 21116, 21117, 21118, 21119 }),

        new("Chrome Remote Desktop", ScreenShareCategory.RemoteDesktopTool,
            new[] { "remoting_host", "remoting_native_messaging_host" },
            new[] { "remoting_desktop" },
            new[] { 443, 5222 }),

        new("Windows Quick Assist", ScreenShareCategory.RemoteDesktopTool,
            new[] { "QuickAssist" },
            new[] { "QuickAssist" },
            new[] { 443 }),

        new("Parsec", ScreenShareCategory.RemoteDesktopTool,
            new[] { "parsecd", "pservice" },
            new[] { "parsecd" },
            new[] { 8000 }),

        new("Splashtop Remote", ScreenShareCategory.RemoteDesktopTool,
            new[] { "SRServer", "SRService", "SRFeature", "SRStreamer" },
            new[] { "SRStreamer", "SRFeature" },
            new[] { 6783, 6784, 6785 }),

        new("ScreenConnect (ConnectWise)", ScreenShareCategory.RemoteDesktopTool,
            new[] { "ScreenConnect.ClientService", "ScreenConnect.WindowsClient" },
            new[] { "ScreenConnect.WindowsClient" },
            new[] { 8040, 8041 }),

        new("LogMeIn / GoToMyPC", ScreenShareCategory.RemoteDesktopTool,
            new[] { "LogMeIn", "LMIGuardianSvc", "g2comm", "g2host" },
            new[] { "LogMeIn", "g2host" },
            new[] { 443, 8200 })
    };

    // Web会議やブラウザ画面共有時に出現するオーバーレイウィンドウのキーワード
    private static readonly string[] ScreenShareWindowKeywords =
    {
        "画面を共有しています",
        "ウィンドウを共有しています",
        "共有コントロール",
        "共有中",
        "is sharing your screen",
        "is sharing a window",
        "sharing control bar",
        "screen sharing",
        "zoom share",
        "発表中",
        "presenting",
        "正在共享屏幕",
        "共享屏幕",
        "compartiendo pantalla",
        "está compartiendo"
    };

    // Zoom画面共有フレーム・ツールバーの固有ウィンドウクラス名
    private static readonly string[] ZoomShareWindowClasses =
    {
        "ZPFTEWndClass",       // Zoom画面共有時の緑枠ウィンドウ
        "ZPFloatToolbarClass", // Zoom画面共有時のフローティングツールバー
        "ZPShareBarClass"
    };

    private ScreenShareDetectionItem? _simulatedAlert;

    public void TriggerSimulation(string toolName, ScreenShareCategory category, string evidence)
    {
        string simPrefix = Loc.T("[SIMULATION]", "[模拟测试]", "[SIMULACIÓN]", "[テスト模擬]");
        _simulatedAlert = new ScreenShareDetectionItem
        {
            DetectionKey = $"SIM:{toolName}",
            Category = category,
            ToolName = $"{simPrefix} {toolName}",
            ProcessName = "SimulationTest.exe",
            ProcessId = Environment.ProcessId,
            Status = ScreenShareStatus.ActiveStreaming,
            Evidence = evidence,
            RemoteEndpoints = Loc.T(
                "198.51.100.42:7070 (Simulated External Session)",
                "198.51.100.42:7070 (模拟外部会话)",
                "198.51.100.42:7070 (Sesión externa simulada)",
                "198.51.100.42:7070 (模擬外部セッション)"),
            FirstDetected = DateTime.Now,
            LastDetected = DateTime.Now,
            IsSimulated = true
        };
    }

    public void ClearSimulation()
    {
        _simulatedAlert = null;
    }

    public List<ScreenShareDetectionItem> ScanScreenShareStatus(List<NetworkConnectionItem> activeConnections)
    {
        var results = new List<ScreenShareDetectionItem>();

        if (_simulatedAlert != null)
        {
            _simulatedAlert.LastDetected = DateTime.Now;
            results.Add(_simulatedAlert);
        }

        Process[] allProcesses;
        try
        {
            allProcesses = Process.GetProcesses();
        }
        catch
        {
            return results;
        }

        try
        {
            var procByName = allProcesses
                .GroupBy(p => p.ProcessName, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

            var topWindows = NativeMethods.GetTopLevelWindows();

        // ====================================================================
        // 1. Windows RDP (リモートデスクトップ) の検知
        // ====================================================================
        bool hasWtsRdp = NativeMethods.HasActiveRdpSession(out string wtsDetails);
        bool hasRdpClip = procByName.ContainsKey("rdpclip");
        var rdpConnections = activeConnections
            .Where(c => c.State == "ESTABLISHED" && (c.LocalPort == 3389 || c.RemotePort == 3389))
            .ToList();

        if (hasWtsRdp || hasRdpClip || rdpConnections.Count > 0)
        {
            var evidences = new List<string>();
            if (hasWtsRdp) evidences.Add(wtsDetails);
            if (hasRdpClip) evidences.Add(Loc.T(
                "rdpclip.exe (RDP clipboard process) is running",
                "rdpclip.exe (RDP剪贴板共享进程) 正在运行",
                "rdpclip.exe (proceso de portapapeles RDP) está en ejecución",
                "rdpclip.exe (RDPクリップボード共有プロセス) が稼働中"));
            if (rdpConnections.Count > 0)
                evidences.Add(Loc.T(
                    $"Detected {rdpConnections.Count} ESTABLISHED connection(s) on TCP port 3389",
                    $"在 TCP 3389 端口检测到 {rdpConnections.Count} 个 ESTABLISHED 连接",
                    $"Se detectaron {rdpConnections.Count} conexiones ESTABLISHED en TCP 3389",
                    $"TCP 3389番ポートで {rdpConnections.Count} 件のESTABLISHED接続を検出"));

            string endpoints = rdpConnections.Count > 0
                ? string.Join(", ", rdpConnections.Select(c => $"{c.RemoteEndpoint} ({c.CountryName})").Distinct())
                : Loc.T("Local / WTS Session", "本地 / WTS 会话", "Sesión Local / WTS", "ローカル/WTSセッション");

            int rdpPid = rdpConnections.FirstOrDefault()?.ProcessId
                         ?? (hasRdpClip ? procByName["rdpclip"].First().Id : 0);

            results.Add(new ScreenShareDetectionItem
            {
                DetectionKey = "RDP:Session",
                Category = ScreenShareCategory.WindowsRdp,
                ToolName = Loc.T("Windows Remote Desktop (RDP)", "Windows 远程桌面 (RDP)", "Escritorio Remoto de Windows (RDP)", "Windows リモートデスクトップ (RDP)"),
                ProcessName = hasRdpClip ? "rdpclip.exe / termsrv" : "termsrv / mstsc",
                ProcessId = rdpPid,
                Status = ScreenShareStatus.ActiveStreaming,
                Severity = RiskLevel.Caution,
                Confidence = ConfidenceLevel.High,
                Evidence = string.Join(" | ", evidences),
                RemoteEndpoints = endpoints
            });
        }

        // ====================================================================
        // 2. AnyDesk / TeamViewer / VNC / RustDesk 等の遠隔操作ツール検知
        // ====================================================================
        foreach (var tool in KnownRemoteTools)
        {
            var matchedProcs = new List<Process>();
            foreach (var pName in tool.ProcessNames)
            {
                if (procByName.TryGetValue(pName, out var list))
                    matchedProcs.AddRange(list);
            }
            foreach (var helperName in tool.ActiveSessionHelperProcesses)
            {
                if (procByName.TryGetValue(helperName, out var list))
                {
                    foreach (var p in list)
                    {
                        if (!matchedProcs.Any(mp => mp.Id == p.Id))
                            matchedProcs.Add(p);
                    }
                }
            }

            if (matchedProcs.Count == 0)
                continue;

            var pids = matchedProcs.Select(p => p.Id).ToHashSet();
            var toolConns = activeConnections
                .Where(c => pids.Contains(c.ProcessId) && c.State == "ESTABLISHED" && c.CountryCode != "LOCAL")
                .ToList();

            // 特徴的ポートでの通信（プロセス名が別でもVNC/AnyDesk/TeamViewerポートで確立している場合）
            var portConns = activeConnections
                .Where(c => c.State == "ESTABLISHED" && c.CountryCode != "LOCAL" &&
                            (tool.CharacteristicPorts.Contains(c.LocalPort) || tool.CharacteristicPorts.Contains(c.RemotePort)) &&
                            c.RemotePort != 443 && c.LocalPort != 443)
                .ToList();

            foreach (var pc in portConns)
            {
                if (!toolConns.Any(tc => tc.ConnectionKey == pc.ConnectionKey))
                    toolConns.Add(pc);
            }

            // アクティブセッション用ヘルパープロセス（例: TeamViewer_Desktop.exe, remoting_desktop.exe）の有無
            bool hasActiveHelper = tool.ActiveSessionHelperProcesses.Any(h =>
                !h.Equals(tool.ProcessNames[0], StringComparison.OrdinalIgnoreCase) && procByName.ContainsKey(h));

            // 複数プロセス展開（AnyDeskやRustDeskは接続セッション確立時に複数ワーカープロセス＋複数TCP/UDP接続を持つ）
            bool hasMultipleProcessesWithNetwork = matchedProcs.Count >= 2 && toolConns.Count >= 1;

            // 専用ポート通信または2本以上の外部ESTABLISHED接続
            bool hasCharacteristicPortTraffic = toolConns.Any(c =>
                (tool.CharacteristicPorts.Contains(c.RemotePort) || tool.CharacteristicPorts.Contains(c.LocalPort)) &&
                c.RemotePort != 443);

            bool isStreaming = hasActiveHelper || hasCharacteristicPortTraffic || toolConns.Count >= 2 || hasMultipleProcessesWithNetwork;

            // 要件 #16: 状態の5段階分離
            // 1. アクティブ画面操作中 (ActiveStreaming): ヘルパープロセス稼働、または専用ポート/複数外部通信
            // 2. 外部制御チャネル確立 (OutboundControlChannel): 1本の外部ESTABLISHED通信のみ
            // 3. 常駐サービス・待機 (ServiceRunning / StandbyService): 通信なし
            ScreenShareStatus toolStatus;
            RiskLevel toolSeverity;
            ConfidenceLevel toolConfidence = ConfidenceLevel.High;

            if (isStreaming)
            {
                toolStatus = ScreenShareStatus.ActiveStreaming;
                toolSeverity = RiskLevel.High;
            }
            else if (toolConns.Count > 0)
            {
                toolStatus = ScreenShareStatus.OutboundControlChannel;
                toolSeverity = RiskLevel.Informational;
                toolConfidence = ConfidenceLevel.Medium;
            }
            else
            {
                bool isOnlyService = matchedProcs.All(p => p.ProcessName.Contains("Service", StringComparison.OrdinalIgnoreCase) || p.ProcessName.Contains("server", StringComparison.OrdinalIgnoreCase));
                toolStatus = isOnlyService ? ScreenShareStatus.ServiceRunning : ScreenShareStatus.StandbyService;
                toolSeverity = RiskLevel.Safe;
            }

            var evidences = new List<string>
            {
                Loc.T(
                    $"Process detected: {string.Join(", ", matchedProcs.Select(p => $"{p.ProcessName}(PID:{p.Id})").Take(3))}",
                    $"检测到进程: {string.Join(", ", matchedProcs.Select(p => $"{p.ProcessName}(PID:{p.Id})").Take(3))}",
                    $"Proceso detectado: {string.Join(", ", matchedProcs.Select(p => $"{p.ProcessName}(PID:{p.Id})").Take(3))}",
                    $"プロセス検出: {string.Join(", ", matchedProcs.Select(p => $"{p.ProcessName}(PID:{p.Id})").Take(3))}")
            };

            if (hasActiveHelper)
                evidences.Add(Loc.T(
                    "Active remote desktop session helper process is running",
                    "远程桌面屏幕传输会话辅助进程正在运行",
                    "Proceso auxiliar de sesión de escritorio remoto activo",
                    "リモートデスクトップ画面転送用セッションプロセスが稼働中"));
            if (isStreaming && !hasActiveHelper)
                evidences.Add(Loc.T(
                    "Active remote control session streaming traffic detected",
                    "检测到远程桌面活动屏幕传输通信流量",
                    "Tráfico de sesión de control remoto activo detectado",
                    "アクティブな遠隔操作・画面転送通信トラフィックを検知"));
            else if (toolStatus == ScreenShareStatus.OutboundControlChannel)
                evidences.Add(Loc.T(
                    $"{toolConns.Count} outbound control/keepalive connection(s) (Session stream not active)",
                    $"外部控制/心跳连接 {toolConns.Count} 个 (屏幕传输未激活)",
                    $"{toolConns.Count} conexión(es) de control saliente (transmisión no activa)",
                    $"外部制御/キープアライブ通信 {toolConns.Count} 件 (画面転送セッションは未確立)"));
            else
                evidences.Add(Loc.T(
                    "No external screen stream established (service on standby)",
                    "未建立外部屏幕传输连接（服务待机中）",
                    "Sin transmisión externa establecida (servicio en espera)",
                    "外部との画面転送通信は未確立（サービス待機中）"));

            string remoteEps = toolConns.Count > 0
                ? string.Join(", ", toolConns.Select(c => $"{c.RemoteEndpoint} ({c.CountryFlag}{c.CountryName})").Distinct().Take(3))
                : Loc.T("No active connection (Standby)", "无通信 (待机中)", "Sin conexión (En espera)", "通信なし (待機中)");

            results.Add(new ScreenShareDetectionItem
            {
                DetectionKey = $"TOOL:{tool.ToolName}",
                Category = tool.Category,
                ToolName = tool.ToolName,
                ProcessName = matchedProcs[0].ProcessName,
                ProcessId = matchedProcs[0].Id,
                Status = toolStatus,
                Severity = toolSeverity,
                Confidence = toolConfidence,
                Evidence = string.Join(" | ", evidences),
                RemoteEndpoints = remoteEps
            });
        }

        // ====================================================================
        // 3. Web会議 (Zoom / Microsoft Teams / Discord / ブラウザ) の画面共有検知
        // ====================================================================
        // 3-A. Zoom 画面共有 (CptHost.exe プロセスまたは Zoom共有枠ウィンドウ)
        bool hasZoomCptHost = procByName.TryGetValue("CptHost", out var cptProcs) && cptProcs.Count > 0;
        var zoomShareWin = topWindows.FirstOrDefault(w =>
            ZoomShareWindowClasses.Any(cls => w.ClassName.Contains(cls, StringComparison.OrdinalIgnoreCase)));

        if (hasZoomCptHost || zoomShareWin != null)
        {
            int pid = hasZoomCptHost ? cptProcs![0].Id : (zoomShareWin?.ProcessId ?? 0);
            var zoomConns = activeConnections
                .Where(c => c.ProcessName.Contains("Zoom", StringComparison.OrdinalIgnoreCase) || c.ProcessName.Equals("CptHost", StringComparison.OrdinalIgnoreCase))
                .ToList();

            string epText = zoomConns.Count > 0
                ? string.Join(", ", zoomConns.Select(c => $"{c.RemoteEndpoint} ({c.CountryFlag}{c.CountryName})").Distinct().Take(2))
                : "Zoom UDP/TCP Stream";

            results.Add(new ScreenShareDetectionItem
            {
                DetectionKey = "MEETING:ZoomShare",
                Category = ScreenShareCategory.MeetingScreenShare,
                ToolName = Loc.T("Zoom Screen Share", "Zoom 屏幕共享", "Zoom Pantalla Compartida", "Zoom 画面共有"),
                ProcessName = hasZoomCptHost ? "CptHost.exe (Zoom Capture Host)" : "Zoom.exe",
                ProcessId = pid,
                Status = ScreenShareStatus.ActiveStreaming,
                Severity = RiskLevel.Informational,
                Confidence = ConfidenceLevel.High,
                Evidence = hasZoomCptHost
                    ? Loc.T(
                        "Detected Zoom dedicated screen capture process (CptHost.exe)",
                        "检测到 Zoom 专用屏幕捕获进程 (CptHost.exe) 正在运行",
                        "Proceso de captura de pantalla de Zoom (CptHost.exe) detectado",
                        "Zoom画面キャプチャ専用プロセス (CptHost.exe) の稼働を検知")
                    : Loc.T(
                        $"Detected Zoom screen share frame window ({zoomShareWin?.ClassName})",
                        $"检测到 Zoom 屏幕共享边框窗口 ({zoomShareWin?.ClassName})",
                        $"Ventana de marco de Zoom compartido ({zoomShareWin?.ClassName}) detectada",
                        $"Zoom画面共有フレームウィンドウ ({zoomShareWin?.ClassName}) を検知"),
                RemoteEndpoints = epText
            });
        }
        else if (procByName.TryGetValue("Zoom", out var zoomProcs) && zoomProcs.Count > 0)
        {
            // Zoom自体は起動しているが画面共有はしていない場合
            results.Add(new ScreenShareDetectionItem
            {
                DetectionKey = "MEETING:ZoomStandby",
                Category = ScreenShareCategory.MeetingScreenShare,
                ToolName = Loc.T("Zoom (Screen Share Off)", "Zoom (未共享屏幕)", "Zoom (Sin compartir pantalla)", "Zoom (画面共有オフ)"),
                ProcessName = "Zoom.exe",
                ProcessId = zoomProcs[0].Id,
                Status = ScreenShareStatus.StandbyService,
                Severity = RiskLevel.Safe,
                Confidence = ConfidenceLevel.High,
                Evidence = Loc.T(
                    "Zoom app is running (screen capture host CptHost.exe is not active)",
                    "Zoom 正在运行（屏幕捕获进程 CptHost.exe 未启动）",
                    "Zoom está en ejecución (el proceso de captura CptHost.exe no está activo)",
                    "Zoomアプリ起動中（画面キャプチャプロセス CptHost.exe は未起動）"),
                RemoteEndpoints = Loc.T("Not sharing screen", "未共享屏幕", "Sin compartir pantalla", "画面共有なし")
            });
        }

        // 3-B. Teams / ブラウザ / Discord 等の画面共有インジケータウィンドウ検知
        var sharingWindows = topWindows.Where(w =>
            !string.IsNullOrWhiteSpace(w.Title) &&
            !w.Title.Contains("Anzen Security Watcher", StringComparison.OrdinalIgnoreCase) &&
            ScreenShareWindowKeywords.Any(kw => w.Title.Contains(kw, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        foreach (var win in sharingWindows)
        {
            string procName = "Unknown";
            try
            {
                var p = allProcesses.FirstOrDefault(x => x.Id == win.ProcessId);
                if (p != null) procName = p.ProcessName;
            }
            catch { }

            // Visual Studio Code や通常エディタのファイル名誤検知を除外するため、会議/ブラウザ系プロセスに限定
            if (!IsMeetingOrBrowserProcess(procName))
                continue;

            string friendlyApp = GetFriendlyMeetingAppName(procName);
            var appConns = activeConnections
                .Where(c => c.ProcessId == win.ProcessId || c.ProcessName.Equals(procName, StringComparison.OrdinalIgnoreCase))
                .ToList();

            string epText = appConns.Count > 0
                ? string.Join(", ", appConns.Select(c => $"{c.RemoteEndpoint} ({c.CountryFlag}{c.CountryName})").Distinct().Take(2))
                : "WebRTC / Media Stream";

            results.Add(new ScreenShareDetectionItem
            {
                DetectionKey = $"MEETING:Win:{win.ProcessId}",
                Category = ScreenShareCategory.MeetingScreenShare,
                ToolName = Loc.T($"{friendlyApp} Screen Share", $"{friendlyApp} 屏幕共享", $"{friendlyApp} Pantalla Compartida", $"{friendlyApp} 画面共有"),
                ProcessName = procName,
                ProcessId = win.ProcessId,
                Status = ScreenShareStatus.ActiveStreaming,
                Severity = RiskLevel.Informational,
                Confidence = ConfidenceLevel.High,
                Evidence = Loc.T(
                    $"Screen share indicator window detected: \"{win.Title}\"",
                    $"检测到屏幕共享指示窗口: “{win.Title}”",
                    $"Ventana indicadora de pantalla compartida detectada: \"{win.Title}\"",
                    $"画面共有インジケータウィンドウを検知: 「{win.Title}」"),
                RemoteEndpoints = epText
            });
        }

        // 3-C. Microsoft Teams が起動中（かつ上記で画面共有が検出されていない場合は待機中として表示）
        if (!results.Any(r => r.ToolName.Contains("Teams", StringComparison.OrdinalIgnoreCase)))
        {
            var teamsProcs = new List<Process>();
            if (procByName.TryGetValue("ms-teams", out var t1)) teamsProcs.AddRange(t1);
            if (procByName.TryGetValue("Teams", out var t2)) teamsProcs.AddRange(t2);

            if (teamsProcs.Count > 0)
            {
                results.Add(new ScreenShareDetectionItem
                {
                    DetectionKey = "MEETING:TeamsStandby",
                    Category = ScreenShareCategory.MeetingScreenShare,
                    ToolName = Loc.T("Microsoft Teams (Screen Share Off)", "Microsoft Teams (未共享屏幕)", "Microsoft Teams (Sin compartir pantalla)", "Microsoft Teams (画面共有オフ)"),
                    ProcessName = teamsProcs[0].ProcessName,
                    ProcessId = teamsProcs[0].Id,
                    Status = ScreenShareStatus.StandbyService,
                    Severity = RiskLevel.Safe,
                    Confidence = ConfidenceLevel.High,
                    Evidence = Loc.T(
                        "Teams app is running (screen sharing bar not detected)",
                        "Teams 应用正在运行（未检测到屏幕共享控制栏）",
                        "Aplicación Teams en ejecución (barra de pantalla compartida no detectada)",
                        "Teamsアプリ稼働中（画面共有バーは未検出）"),
                    RemoteEndpoints = Loc.T("Not sharing screen", "未共享屏幕", "Sin compartir pantalla", "画面共有なし")
                });
            }
        }
        }
        finally
        {
            // プロセスオブジェクトの破棄
            foreach (var p in allProcesses)
            {
                try { p.Dispose(); } catch { }
            }
        }

        return results
            .OrderByDescending(r => r.Status)
            .ThenBy(r => r.Category)
            .ToList();
    }

    private static bool IsMeetingOrBrowserProcess(string procName)
    {
        string lower = procName.ToLowerInvariant();
        return lower.Contains("teams") ||
               lower.Contains("zoom") ||
               lower.Contains("discord") ||
               lower.Contains("slack") ||
               lower.Contains("webex") ||
               lower.Contains("chrome") ||
               lower.Contains("msedge") ||
               lower.Contains("firefox") ||
               lower.Contains("brave") ||
               lower.Contains("obs");
    }

    private static string GetFriendlyMeetingAppName(string procName)
    {
        string lower = procName.ToLowerInvariant();
        if (lower.Contains("teams")) return "Microsoft Teams";
        if (lower.Contains("zoom")) return "Zoom";
        if (lower.Contains("discord")) return "Discord";
        if (lower.Contains("slack")) return "Slack";
        if (lower.Contains("webex")) return "Cisco Webex";
        if (lower.Contains("msedge")) return "Microsoft Edge";
        if (lower.Contains("chrome")) return "Google Chrome";
        if (lower.Contains("firefox")) return "Firefox";
        if (lower.Contains("obs")) return "OBS Studio";
        return procName;
    }
}
