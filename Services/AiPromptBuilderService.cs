using System.Text;
using System.Text.RegularExpressions;
using AnzenSecurityWatcher.Models;

namespace AnzenSecurityWatcher.Services;

public class AiPromptBuilderService
{
    private readonly Dictionary<string, SecurityLogEntry> _logMap = new(StringComparer.OrdinalIgnoreCase);
    private List<ProcessAnalysisItem> _cachedProcesses = new();
    private List<SystemFindingItem> _cachedFindings = new();

    /// <summary>過去履歴（非稼働/古いイベント）もデフォルトで選択対象に含めるかどうか</summary>
    public bool IncludeHistoricalLogsByDefault { get; set; } = false;

    public void SetHistoricalSelection(bool includeHistorical)
    {
        IncludeHistoricalLogsByDefault = includeHistorical;
        foreach (var entry in _logMap.Values)
        {
            if (entry.IsHistoricalRecord)
            {
                entry.IsSelected = includeHistorical;
            }
        }
    }

    public void SelectAllLogs(bool includeHistorical)
    {
        foreach (var entry in _logMap.Values)
        {
            if (entry.IsHistoricalRecord)
            {
                entry.IsSelected = includeHistorical;
            }
            else
            {
                entry.IsSelected = true;
            }
        }
    }

    public IReadOnlyCollection<SecurityLogEntry> GetAllLogs()
        => _logMap.Values
            .OrderByDescending(x => x.Severity)
            .ThenByDescending(x => x.LastTimestamp)
            .ToList();

    public bool IngestFromMonitors(
        IEnumerable<NetworkConnectionItem> connections,
        IEnumerable<ScreenShareDetectionItem> screenShares,
        IEnumerable<ProcessAnalysisItem> processes,
        out List<SecurityLogEntry> newlyAddedHighRiskLogs,
        IEnumerable<SystemFindingItem>? defenseFindings = null)
    {
        bool changed = RemoveSimulatedLogs();
        newlyAddedHighRiskLogs = new List<SecurityLogEntry>();

        var procList = processes as IList<ProcessAnalysisItem> ?? processes.ToList();
        _cachedProcesses = procList.ToList();
        if (defenseFindings != null)
            _cachedFindings = (defenseFindings as IList<SystemFindingItem> ?? defenseFindings.ToList()).ToList();

        // 1. 画面共有・リモートデスクトップ検知からのログ取り込み（※テスト模擬は除外）
        foreach (var ss in screenShares.Where(s =>
            !s.IsSimulated &&
            !s.DetectionKey.StartsWith("SIM:", StringComparison.OrdinalIgnoreCase) &&
            !s.ToolName.Contains("テスト模擬", StringComparison.OrdinalIgnoreCase) &&
            !s.ToolName.Contains("[SIM", StringComparison.OrdinalIgnoreCase)))
        {
            string key = $"SS:{ss.DetectionKey}:{ss.Status}";
            var severity = ss.Status == ScreenShareStatus.ActiveStreaming ? RiskLevel.Critical : RiskLevel.Medium;

            string title = ss.Status == ScreenShareStatus.ActiveStreaming
                ? Loc.T(
                    $"[Screen Share / Remote Access ACTIVE] {ss.ToolName} is streaming",
                    $"【屏幕共享/远程连接活动中】{ss.ToolName} 正在运行并通信",
                    $"[Pantalla Compartida / Acceso Remoto ACTIVO] {ss.ToolName} en curso",
                    $"【画面共有/遠隔接続アクティブ】{ss.ToolName} が稼働・通信中")
                : Loc.T(
                    $"[Remote / Meeting Tool Standby] {ss.ToolName} running in background",
                    $"【远程/会议工具待机】{ss.ToolName} 正在后台运行",
                    $"[Herramienta Remota / Reunión en Espera] {ss.ToolName} en segundo plano",
                    $"【遠隔操作/会議ツール待機】{ss.ToolName} がバックグラウンド稼働中");

            string details = Loc.T(
                $"Category: {ss.CategoryLabel}\nTool: {ss.ToolName}\nProcess: {ss.ProcessName} (PID: {ss.ProcessId})\nStatus: {ss.StatusBadge}\nEvidence: {ss.Evidence}\nRemote: {ss.RemoteEndpoints}",
                $"类别: {ss.CategoryLabel}\n工具名: {ss.ToolName}\n进程: {ss.ProcessName} (PID: {ss.ProcessId})\n状态: {ss.StatusBadge}\n检测依据: {ss.Evidence}\n通信目标: {ss.RemoteEndpoints}",
                $"Categoría: {ss.CategoryLabel}\nHerramienta: {ss.ToolName}\nProceso: {ss.ProcessName} (PID: {ss.ProcessId})\nEstado: {ss.StatusBadge}\nEvidencia: {ss.Evidence}\nDestino: {ss.RemoteEndpoints}",
                $"カテゴリ: {ss.CategoryLabel}\nツール名: {ss.ToolName}\nプロセス: {ss.ProcessName} (PID: {ss.ProcessId})\n状態: {ss.StatusBadge}\n検知根拠: {ss.Evidence}\n通信先: {ss.RemoteEndpoints}");

            string action = Loc.T(
                "Verify whether you intentionally started this screen share/remote tool. If unrecognized, terminate the process and block network access immediately.",
                "请确认该工具是否为您本人主动开启。若非本人操作，请立即结束进程并断开网络连接。",
                "Verifique si inició intencionalmente esta herramienta. Si no la reconoce, termine el proceso y bloquee la red de inmediato.",
                "自分が意図して起動・共有しているツールか確認し、心当たりがない場合は直ちにプロセス終了とネットワーク遮断を検討してください。");

            if (AddOrUpdateLog(key, LogCategory.ScreenShare, ss.Severity, title, ss.Evidence, details,
                $"{ss.ProcessName} (PID:{ss.ProcessId})", ss.RemoteEndpoints, action, out var addedEntry,
                confidence: ss.Confidence, storyKey: $"Story:ScreenShare:{ss.ToolName}"))
            {
                changed = true;
                if (ss.Severity >= RiskLevel.High && addedEntry != null)
                    newlyAddedHighRiskLogs.Add(addedEntry);
            }
        }

        // 2. TCP/IP不審通信・注目通信からのログ取り込み
        foreach (var conn in connections.Where(c => c.RiskLevel >= RiskLevel.Medium))
        {
            string key = $"NET:{conn.ProcessName}:{conn.RemoteAddress}:{conn.RemotePort}";
            string title = Loc.T(
                $"[Notable Traffic] {conn.ProcessName} communicating with {conn.CountryFlag}{conn.CountryName} ({conn.RemoteAddress}:{conn.RemotePort})",
                $"【需注意通信】{conn.ProcessName} 正在与 {conn.CountryFlag}{conn.CountryName} ({conn.RemoteAddress}:{conn.RemotePort}) 通信",
                $"[Tráfico Notable] {conn.ProcessName} comunicándose con {conn.CountryFlag}{conn.CountryName} ({conn.RemoteAddress}:{conn.RemotePort})",
                $"【要注意通信】{conn.ProcessName} が {conn.CountryFlag}{conn.CountryName} ({conn.RemoteAddress}:{conn.RemotePort}) と通信");

            string details = Loc.T(
                $"Protocol/State: {conn.Protocol} ({conn.State})\nProcess: {conn.ProcessName} (PID: {conn.ProcessId})\nPath: {conn.ProcessPath}\nLocal: {conn.LocalEndpoint}\nRemote: {conn.RemoteEndpoint}\nCountry/Org: {conn.CountryDisplay} / {conn.Organization} ({conn.City})\nReason: {conn.RiskReason}",
                $"协议/状态: {conn.Protocol} ({conn.State})\n进程名: {conn.ProcessName} (PID: {conn.ProcessId})\n可执行路径: {conn.ProcessPath}\n本地端点: {conn.LocalEndpoint}\n远程端点: {conn.RemoteEndpoint}\n国家/组织: {conn.CountryDisplay} / {conn.Organization} ({conn.City})\n风险判定原因: {conn.RiskReason}",
                $"Protocolo/Estado: {conn.Protocol} ({conn.State})\nProceso: {conn.ProcessName} (PID: {conn.ProcessId})\nRuta: {conn.ProcessPath}\nLocal: {conn.LocalEndpoint}\nRemoto: {conn.RemoteEndpoint}\nPaís/Org: {conn.CountryDisplay} / {conn.Organization} ({conn.City})\nMotivo: {conn.RiskReason}",
                $"プロトコル/状態: {conn.Protocol} ({conn.State})\nプロセス名: {conn.ProcessName} (PID: {conn.ProcessId})\n実行ファイルパス: {conn.ProcessPath}\nローカル端点: {conn.LocalEndpoint}\nリモート端点: {conn.RemoteEndpoint}\n通信先の国/組織: {conn.CountryDisplay} / {conn.Organization} ({conn.City})\nリスク判定理由: {conn.RiskReason}");

            string action = Loc.T(
                "Ask AI whether it is normal for this process to communicate with servers in this country/organization (e.g., updates or cloud sync).",
                "请向 AI 确认此进程与该国家/组织的服务器通信是否属于正常行为（如软件更新或云同步）。",
                "Consulte a la IA si es normal que este proceso se comunique con servidores en ese país/organización.",
                "このプロセスが該当国・組織のサーバーと通信するのが正常な仕様（アップデートやクラウド同期など）かAIに確認してください。");

            if (AddOrUpdateLog(key, LogCategory.Network, conn.RiskLevel, title, conn.RiskReason, details,
                $"{conn.ProcessName} (PID:{conn.ProcessId})", $"{conn.RemoteEndpoint} [{conn.CountryName}]",
                action, out var addedEntry))
            {
                changed = true;
                if (conn.RiskLevel >= RiskLevel.High && addedEntry != null)
                    newlyAddedHighRiskLogs.Add(addedEntry);
            }
        }

        // 3. プロセス異常からのログ取り込み
        foreach (var proc in processes.Where(p =>
            !p.IsSimulated &&
            !p.ProcessKey.StartsWith("sim:", StringComparison.OrdinalIgnoreCase) &&
            !p.ProcessName.Contains("テスト模擬", StringComparison.OrdinalIgnoreCase) &&
            !p.IsSelfProcess &&
            !ProcessMonitorService.CheckIsSelfProcess(p.CurrentPid, p.ProcessName, p.ExecutablePath) &&
            !p.IsUserTrusted &&
            (p.IsCurrentlyRunning || p.IsTransientFlash || p.IsPeriodic || p.IsRareOrNew || p.RiskLevel >= RiskLevel.Medium)))
        {
            string key = $"PROC:{proc.ProcessKey}";
            bool isHistorical = proc.IsHistoricalOnly || (!proc.IsCurrentlyRunning && !proc.IsFilePresent) || (!proc.IsCurrentlyRunning && (DateTime.Now - proc.LastSeenTime).TotalMinutes >= 15);

            RiskLevel severity;
            if (isHistorical)
            {
                severity = proc.RiskLevel >= RiskLevel.High ? RiskLevel.Caution : (proc.RiskLevel == RiskLevel.Safe ? RiskLevel.Safe : RiskLevel.Low);
            }
            else
            {
                severity = proc.RiskLevel >= RiskLevel.Medium ? proc.RiskLevel : RiskLevel.Medium;
            }

            string tag = isHistorical
                ? (!proc.IsFilePresent
                    ? Loc.T("[Historical Trace (File Deleted)]", "【历史痕迹(文件已删除)】", "[Historial (Archivo Eliminado)]", "【過去履歴(ファイル削除済・非稼働)】")
                    : Loc.T("[Historical Trace (Inactive)]", "【历史痕迹(非活跃)】", "[Historial (Inactivo)]", "【過去履歴(非稼働)】"))
                : (proc.IsTransientFlash
                    ? (proc.HadVisibleConsoleWindow
                        ? Loc.T("[Flash Terminal Detected]", "【检测到瞬时终端闪烁】", "[Terminal Fugaz Detectada]", "【瞬間ターミナル出現(フラッシュ検知)】")
                        : Loc.T("[Short-Lived Command Detected]", "【检测到短命命令执行】", "[Comando de Corta Duración]", "【短命コマンド実行検知】"))
                    : (proc.IsPeriodic
                        ? Loc.T("[Periodic Process]", "【周期性进程】", "[Proceso Periódico]", "【周期出現プロセス】")
                        : Loc.T("[New / Rare Process]", "【首次/罕见进程】", "[Proceso Nuevo / Raro]", "【初出/レアプロセス】")));
            string title = $"{tag} {proc.ProcessName} ({proc.AnomalyReason})";
            string launchHistory = string.Join(", ", proc.LaunchTimestamps.TakeLast(6).Select(t => t.ToString("HH:mm:ss")));
            string safeCmd = CommandLineAnalyzer.MaskSensitiveArguments(proc.CommandLine);
            string safeTree = CommandLineAnalyzer.MaskSensitiveArguments(proc.ProcessTreeDetail);

            string details = Loc.T(
                $"Process: {proc.ProcessName} (PID: {proc.CurrentPid}, Status: {proc.RunningStatusText})\nPath: {proc.ExecutablePath}\n" +
                (string.IsNullOrWhiteSpace(safeCmd) ? "" : $"Command Line: {safeCmd}\n") +
                $"Parent Process: {proc.ParentDisplay}\n" +
                (string.IsNullOrWhiteSpace(safeTree) ? "" : $"Process Tree (ancestors -> self):\n{safeTree}\n") +
                (string.IsNullOrWhiteSpace(proc.MatchedScheduledTask) ? "" : $"Matched Scheduled Task: {proc.MatchedScheduledTask}\n") +
                (proc.LastDurationMs > 0 ? $"Last Duration: {proc.DurationText}\n" : "") +
                $"Digital Signature: {(proc.IsSigned ? $"Signed ({proc.SignerName})" : "Unsigned")}\n" +
                $"First Seen: {proc.FirstSeenText} / Total Launches: {proc.TotalSeenCount}\n" +
                $"Periodicity: {proc.PeriodicitySummary}\n" +
                $"Recent Launch Times: [{launchHistory}]\n" +
                $"Reason: {proc.AnomalyReason}",
                $"进程名: {proc.ProcessName} (当前PID: {proc.CurrentPid}, 状态: {proc.RunningStatusText})\n可执行路径: {proc.ExecutablePath}\n" +
                (string.IsNullOrWhiteSpace(safeCmd) ? "" : $"命令行参数: {safeCmd}\n") +
                $"父进程(启动源): {proc.ParentDisplay}\n" +
                (string.IsNullOrWhiteSpace(safeTree) ? "" : $"Process Tree (ancestors -> self):\n{safeTree}\n") +
                (string.IsNullOrWhiteSpace(proc.MatchedScheduledTask) ? "" : $"关联计划任务: {proc.MatchedScheduledTask}\n") +
                (proc.LastDurationMs > 0 ? $"最近存活时间: {proc.DurationText}\n" : "") +
                $"数字签名: {(proc.IsSigned ? $"已签名 ({proc.SignerName})" : "无 (未签名)")}\n" +
                $"首次发现: {proc.FirstSeenText} / 累计出现次数: {proc.TotalSeenCount}次\n" +
                $"周期性判定: {proc.PeriodicitySummary}\n" +
                $"最近启动时间历史: [{launchHistory}]\n" +
                $"检测原因: {proc.AnomalyReason}",
                $"Proceso: {proc.ProcessName} (PID: {proc.CurrentPid}, Estado: {proc.RunningStatusText})\nRuta: {proc.ExecutablePath}\n" +
                (string.IsNullOrWhiteSpace(safeCmd) ? "" : $"Línea de comandos: {safeCmd}\n") +
                $"Proceso padre: {proc.ParentDisplay}\n" +
                (string.IsNullOrWhiteSpace(safeTree) ? "" : $"Process Tree (ancestors -> self):\n{safeTree}\n") +
                (string.IsNullOrWhiteSpace(proc.MatchedScheduledTask) ? "" : $"Tarea programada: {proc.MatchedScheduledTask}\n") +
                (proc.LastDurationMs > 0 ? $"Duración: {proc.DurationText}\n" : "") +
                $"Firma digital: {(proc.IsSigned ? $"Firmado ({proc.SignerName})" : "Sin firma")}\n" +
                $"Primera vez: {proc.FirstSeenText} / Total apariciones: {proc.TotalSeenCount}\n" +
                $"Periodicidad: {proc.PeriodicitySummary}\n" +
                $"Historial reciente: [{launchHistory}]\n" +
                $"Motivo: {proc.AnomalyReason}",
                $"プロセス名: {proc.ProcessName} (現在のPID: {proc.CurrentPid}, 状態: {proc.RunningStatusText})\n実行ファイルパス: {proc.ExecutablePath}\n" +
                (string.IsNullOrWhiteSpace(safeCmd) ? "" : $"コマンドライン引数: {safeCmd}\n") +
                $"親プロセス(起動元): {proc.ParentDisplay}\n" +
                (string.IsNullOrWhiteSpace(safeTree) ? "" : $"Process Tree (ancestors -> self):\n{safeTree}\n") +
                (string.IsNullOrWhiteSpace(proc.MatchedScheduledTask) ? "" : $"関連スケジュールタスク: {proc.MatchedScheduledTask}\n") +
                (proc.LastDurationMs > 0 ? $"直近の生存時間: {proc.DurationText}\n" : "") +
                $"デジタル署名: {(proc.IsSigned ? $"あり ({proc.SignerName})" : "なし (未署名)")}\n" +
                $"初回確認日時: {proc.FirstSeenText} / 累計出現回数: {proc.TotalSeenCount}回\n" +
                $"周期性判定: {proc.PeriodicitySummary}\n" +
                $"直近の起動時刻履歴: [{launchHistory}]\n" +
                $"検出理由: {proc.AnomalyReason}");

            string actionNote = proc.IsTransientFlash
                ? Loc.T(
                    "Candidate cause for a brief flashing terminal window. Please determine its identity and safety from the parent process, command line, and scheduled task.",
                    "这是导致屏幕瞬间闪现终端窗口的候选原因。请根据父进程、命令行参数和计划任务判断其真实身份与安全性。",
                    "Candidato causante de una ventana de terminal fugaz. Determine su identidad y seguridad según el proceso padre y argumentos.",
                    "一瞬だけ画面にターミナル（コンソール）が出現して消える現象の元凶候補です。親プロセス・コマンドライン引数・スケジュールタスクから正体と安全性を判定し、正規タスクであれば非表示化または停止して問題ないか、不審であれば駆除手順を教えてください。")
                : (isHistorical
                    ? Loc.T(
                        "This is a historical record of an inactive/exited process. Check if any unwanted residual tasks or files remain.",
                        "这是已停止/退出进程的历史记录。请排查是否存在不需要的残留任务或文件。",
                        "Registro histórico de un proceso inactivo. Verifique si quedan archivos o tareas residuales.",
                        "非稼働・終了済みプロセスの過去履歴です。アンインストール後の残存タスクやファイルがないか確認してください。")
                    : Loc.T(
                        "Ask AI whether this executable name, path, signature, and launch interval belong to a legitimate Windows service/app or a suspicious task.",
                        "请向 AI 确认此可执行文件名、路径、签名状态及启动周期是正常的 Windows 服务/常驻软件，还是可疑任务。",
                        "Consulte a la IA si este ejecutable, ruta, firma e intervalo pertenecen a un servicio legítimo de Windows o a una tarea sospechosa.",
                        "この実行ファイル名・パス・署名状態・起動周期が正規のWindowsサービスや常駐ソフトのものか、不審なタスク（ビーコン等）かAIに確認してください。"));

            if (AddOrUpdateLog(key, LogCategory.ProcessAnomaly, severity, title, proc.AnomalyReason, details,
                $"{proc.ProcessName}", proc.ExecutablePath,
                actionNote,
                out var addedEntry,
                confidence: proc.Confidence,
                storyKey: proc.StoryKey,
                processLineage: proc.ProcessTreeDetail,
                isHistorical: isHistorical))
            {
                changed = true;
                if (!isHistorical && severity >= RiskLevel.High && addedEntry != null)
                    newlyAddedHighRiskLogs.Add(addedEntry);
            }
        }

        // 4. システム防御エンジンからの取り込み
        if (defenseFindings != null)
        {
            var findingsList = defenseFindings as IList<SystemFindingItem> ?? defenseFindings.ToList();
            if (!findingsList.Any(x => !x.IsSimulated && x.Category == FindingCategory.DllSideload))
            {
                var staleSideloadKeys = _logMap.Keys
                    .Where(k => k.StartsWith("DEF:SIDELOAD:", StringComparison.OrdinalIgnoreCase))
                    .ToList();
                foreach (var k in staleSideloadKeys)
                {
                    if (_logMap.Remove(k))
                        changed = true;
                }
            }

            foreach (var f in findingsList.Where(x => !x.IsAcknowledged && !x.IsSimulated && x.EffectiveSeverity >= RiskLevel.Medium))
            {
                string key = $"DEF:{f.Key}";
                string title = $"[{f.CategoryLabel}] {f.Title}";
                if (AddOrUpdateLog(key, LogCategory.SystemSecurity, f.EffectiveSeverity, title, f.Detail,
                    string.IsNullOrWhiteSpace(f.TechnicalDetails) ? f.Detail : f.TechnicalDetails,
                    f.CategoryLabel, f.Target, f.RecommendedAction,
                    out var addedDef,
                    confidence: f.Confidence,
                    storyKey: f.StoryKey))
                {
                    changed = true;
                    if (f.EffectiveSeverity >= RiskLevel.High && addedDef != null)
                        newlyAddedHighRiskLogs.Add(addedDef);
                }
            }
        }

        return changed;
    }

    public void AddManualDefenseFindingLog(SystemFindingItem f)
    {
        string key = $"MANUAL_DEF:{f.Key}";
        string prefix = Loc.T("Manual Pick", "手动选择", "Selección Manual", "手動ピックアップ");
        string title = $"[{prefix}: {f.CategoryLabel}] {f.Title}";
        var sev = f.Severity == RiskLevel.Safe ? RiskLevel.Low : f.Severity;
        AddOrUpdateLog(key, LogCategory.SystemSecurity, sev, title, f.Detail,
            string.IsNullOrWhiteSpace(f.TechnicalDetails) ? f.Detail : f.TechnicalDetails,
            f.CategoryLabel, f.Target,
            string.IsNullOrWhiteSpace(f.RecommendedAction)
                ? Loc.T(
                    "Please evaluate the safety of this finding and recommend remediation steps.",
                    "请诊断此检测项的安全性并提供建议的处置步骤。",
                    "Evalúe la seguridad de este hallazgo y recomiende pasos de remediación.",
                    "この検知項目の安全性と推奨される対処手順を診断してください。")
                : f.RecommendedAction,
            out _);
    }

    public void AddManualNetworkLog(NetworkConnectionItem conn)
    {
        bool isSelf = ProcessMonitorService.CheckIsSelfProcess(conn.ProcessId, conn.ProcessName, conn.ProcessPath);
        string selfSuffix = isSelf
            ? Loc.T(" [*Self process that generated this log]", " [※生成此日志的自身程序]", " [*Proceso propio que generó este registro]", " [※このログを生成した自分自身のプログラム]")
            : "";
        string key = $"MANUAL_NET:{conn.ProcessName}:{conn.RemoteAddress}:{conn.RemotePort}";
        string prefix = Loc.T("[Manual Network Pick]", "【手动选择的通信】", "[Conexión Seleccionada]", "【手動ピックアップ通信】");
        string title = $"{prefix} {conn.ProcessName}{selfSuffix} -> {conn.CountryFlag}{conn.CountryName} ({conn.RemoteEndpoint})";
        string details =
            (isSelf ? Loc.T(
                "*Important Note: This connection was made by Anzen Security Watcher itself for GeoIP country lookup.\n",
                "※重要说明: 此通信是由生成本日志的监控程序自身 (Anzen Security Watcher) 为进行 IP 国家/地区查询 (GeoIP) 而发起的。\n",
                "*Nota importante: Esta conexión fue realizada por el propio programa Anzen Security Watcher para consulta GeoIP.\n",
                "※重要注記: この通信は、このログを生成した自分自身のプログラム (Anzen Security Watcher) がIPアドレスの国別判定(GeoIP)等のために行った通信です。\n") : "") +
            Loc.T(
                $"Protocol/State: {conn.Protocol} ({conn.State})\nProcess: {conn.ProcessName}{selfSuffix} (PID: {conn.ProcessId})\nPath: {conn.ProcessPath}\nRemote: {conn.RemoteEndpoint}\nCountry/Org: {conn.CountryDisplay} / {conn.Organization} ({conn.City})\nNote: {conn.RiskReason}",
                $"协议/状态: {conn.Protocol} ({conn.State})\n进程名: {conn.ProcessName}{selfSuffix} (PID: {conn.ProcessId})\n可执行路径: {conn.ProcessPath}\n远程端点: {conn.RemoteEndpoint}\n国家/组织: {conn.CountryDisplay} / {conn.Organization} ({conn.City})\n判定备注: {conn.RiskReason}",
                $"Protocolo/Estado: {conn.Protocol} ({conn.State})\nProceso: {conn.ProcessName}{selfSuffix} (PID: {conn.ProcessId})\nRuta: {conn.ProcessPath}\nRemoto: {conn.RemoteEndpoint}\nPaís/Org: {conn.CountryDisplay} / {conn.Organization} ({conn.City})\nNota: {conn.RiskReason}",
                $"プロトコル/状態: {conn.Protocol} ({conn.State})\nプロセス名: {conn.ProcessName}{selfSuffix} (PID: {conn.ProcessId})\n実行ファイルパス: {conn.ProcessPath}\nリモート端点: {conn.RemoteEndpoint}\n通信先の国/組織: {conn.CountryDisplay} / {conn.Organization} ({conn.City})\n判定メモ: {conn.RiskReason}");

        AddOrUpdateLog(key, LogCategory.Network,
            conn.RiskLevel == RiskLevel.Safe ? RiskLevel.Low : conn.RiskLevel,
            title,
            Loc.T("Network connection manually selected for AI consultation", "用户手动选择用于 AI 咨询的通信日志", "Conexión seleccionada manualmente para consulta IA", "ユーザーがAI相談対象として手動選択した通信ログ"),
            details,
            $"{conn.ProcessName} (PID:{conn.ProcessId})", $"{conn.RemoteEndpoint} ({conn.CountryName})",
            Loc.T("Please evaluate whether this remote IP/organization and process combination is safe.", "请评估此远程 IP/组织与进程的组合是否安全。", "Evalúe si la combinación de esta IP/organización remota y proceso es segura.", "この通信先IP・組織およびプロセスの組み合わせが安全かどうか診断を依頼します。"),
            out _);
    }

    public void AddManualProcessLog(ProcessAnalysisItem proc)
    {
        if (proc.IsSimulated ||
            proc.ProcessKey.StartsWith("sim:", StringComparison.OrdinalIgnoreCase) ||
            proc.ProcessName.Contains("テスト模擬", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        bool isSelf = proc.IsSelfProcess || ProcessMonitorService.CheckIsSelfProcess(proc.CurrentPid, proc.ProcessName, proc.ExecutablePath);
        string selfSuffix = isSelf
            ? Loc.T(" [*Self process that generated this log]", " [※生成此日志的自身程序]", " [*Proceso propio que generó este registro]", " [※このログを生成した自分自身のプログラム]")
            : "";
        string key = $"MANUAL_PROC:{proc.ProcessKey}";
        string prefix = Loc.T("[Manual Process Pick]", "【手动选择的进程】", "[Proceso Seleccionado]", "【手動ピックアッププロセス】");
        string title = $"{prefix} {proc.ProcessName}{selfSuffix} ({proc.TrustBadge})";
        string launchHistory = string.Join(", ", proc.LaunchTimestamps.TakeLast(6).Select(t => t.ToString("HH:mm:ss")));
        string safeCmd = CommandLineAnalyzer.MaskSensitiveArguments(proc.CommandLine);
        string safeTree = CommandLineAnalyzer.MaskSensitiveArguments(proc.ProcessTreeDetail);
        string details =
            (isSelf ? Loc.T(
                "*Important Note: This process is Anzen Security Watcher itself (unsigned because it is a local build).\n",
                "※重要说明: 此进程是生成并输出此日志的自身监控程序 (Anzen Security Watcher)（因本地构建而未签名）。\n",
                "*Nota importante: Este proceso es el propio Anzen Security Watcher (sin firmar por ser compilación local).\n",
                "※重要注記: このプロセスは、このログを生成・出力している自分自身のプログラム (Anzen Security Watcher) です（ローカルビルドのため未署名）。\n") : "") +
            Loc.T(
                $"Process: {proc.ProcessName}{selfSuffix} (PID: {proc.CurrentPid}, Status: {proc.RunningStatusText})\nPath: {proc.ExecutablePath}\n" +
                (string.IsNullOrWhiteSpace(safeCmd) ? "" : $"Command Line: {safeCmd}\n") +
                $"Parent Process: {proc.ParentDisplay}\n" +
                (string.IsNullOrWhiteSpace(safeTree) ? "" : $"Process Tree (ancestors -> self):\n{safeTree}\n") +
                (string.IsNullOrWhiteSpace(proc.MatchedScheduledTask) ? "" : $"Matched Scheduled Task: {proc.MatchedScheduledTask}\n") +
                (proc.LastDurationMs > 0 ? $"Last Duration: {proc.DurationText}\n" : "") +
                $"Digital Signature: {(proc.IsSigned ? $"Signed ({proc.SignerName})" : "Unsigned")}\n" +
                $"Total Seen: {proc.TotalSeenCount} / Periodicity: {proc.PeriodicitySummary}\n" +
                $"Recent Launches: [{launchHistory}]\n" +
                $"Note: {proc.AnomalyReason}",
                $"进程名: {proc.ProcessName}{selfSuffix} (PID: {proc.CurrentPid}, 状态: {proc.RunningStatusText})\n可执行路径: {proc.ExecutablePath}\n" +
                (string.IsNullOrWhiteSpace(safeCmd) ? "" : $"命令行参数: {safeCmd}\n") +
                $"父进程(启动源): {proc.ParentDisplay}\n" +
                (string.IsNullOrWhiteSpace(safeTree) ? "" : $"Process Tree (ancestors -> self):\n{safeTree}\n") +
                (string.IsNullOrWhiteSpace(proc.MatchedScheduledTask) ? "" : $"关联计划任务: {proc.MatchedScheduledTask}\n") +
                (proc.LastDurationMs > 0 ? $"最近存活时间: {proc.DurationText}\n" : "") +
                $"数字签名: {(proc.IsSigned ? $"已签名 ({proc.SignerName})" : "无 (未签名)")}\n" +
                $"累计出现次数: {proc.TotalSeenCount}次 / 周期性: {proc.PeriodicitySummary}\n" +
                $"最近启动时刻: [{launchHistory}]\n" +
                $"状态备注: {proc.AnomalyReason}",
                $"Proceso: {proc.ProcessName}{selfSuffix} (PID: {proc.CurrentPid}, Estado: {proc.RunningStatusText})\nRuta: {proc.ExecutablePath}\n" +
                (string.IsNullOrWhiteSpace(safeCmd) ? "" : $"Línea de comandos: {safeCmd}\n") +
                $"Proceso padre: {proc.ParentDisplay}\n" +
                (string.IsNullOrWhiteSpace(safeTree) ? "" : $"Process Tree (ancestors -> self):\n{safeTree}\n") +
                (string.IsNullOrWhiteSpace(proc.MatchedScheduledTask) ? "" : $"Tarea programada: {proc.MatchedScheduledTask}\n") +
                (proc.LastDurationMs > 0 ? $"Duración: {proc.DurationText}\n" : "") +
                $"Firma digital: {(proc.IsSigned ? $"Firmado ({proc.SignerName})" : "Sin firma")}\n" +
                $"Apariciones: {proc.TotalSeenCount} / Periodicidad: {proc.PeriodicitySummary}\n" +
                $"Inicios recientes: [{launchHistory}]\n" +
                $"Nota: {proc.AnomalyReason}",
                $"プロセス名: {proc.ProcessName}{selfSuffix} (PID: {proc.CurrentPid}, 状態: {proc.RunningStatusText})\n実行ファイルパス: {proc.ExecutablePath}\n" +
                (string.IsNullOrWhiteSpace(safeCmd) ? "" : $"コマンドライン引数: {safeCmd}\n") +
                $"親プロセス(起動元): {proc.ParentDisplay}\n" +
                (string.IsNullOrWhiteSpace(safeTree) ? "" : $"Process Tree (ancestors -> self):\n{safeTree}\n") +
                (string.IsNullOrWhiteSpace(proc.MatchedScheduledTask) ? "" : $"関連スケジュールタスク: {proc.MatchedScheduledTask}\n") +
                (proc.LastDurationMs > 0 ? $"直近の生存時間: {proc.DurationText}\n" : "") +
                $"デジタル署名: {(proc.IsSigned ? $"あり ({proc.SignerName})" : "なし (未署名)")}\n" +
                $"累計出現回数: {proc.TotalSeenCount}回 / 周期性: {proc.PeriodicitySummary}\n" +
                $"直近の起動時刻: [{launchHistory}]\n" +
                $"状態メモ: {proc.AnomalyReason}");

        AddOrUpdateLog(key, LogCategory.ProcessAnomaly,
            proc.RiskLevel == RiskLevel.Safe ? RiskLevel.Low : proc.RiskLevel,
            title,
            Loc.T("Process manually selected for AI consultation", "用户手动选择用于 AI 咨询的进程", "Proceso seleccionado manualmente para consulta IA", "ユーザーがAI相談対象として手動選択したプロセス"),
            details,
            proc.ProcessName, proc.ExecutablePath,
            Loc.T("Please identify this process, assess its safety, and advise if it can be safely stopped if unnecessary.", "请判断此进程的真实身份、安全性，以及如果不需要是否可以安全停止。", "Identifique este proceso, evalúe su seguridad e indique si se puede detener de forma segura.", "このプロセスの正体・安全性・不要な場合に停止して問題ないかを診断してください。"),
            out _,
            storyKey: proc.StoryKey,
            processLineage: proc.ProcessTreeDetail);
    }

    public void AddSystemSnapshotLog(
        IReadOnlyCollection<NetworkConnectionItem> connections,
        IReadOnlyCollection<ScreenShareDetectionItem> screenShares,
        IReadOnlyCollection<ProcessAnalysisItem> processes,
        SecurityPostureReport? posture = null,
        IReadOnlyCollection<SystemFindingItem>? findings = null)
    {
        var realScreenShares = screenShares
            .Where(s => !s.IsSimulated && !s.DetectionKey.StartsWith("SIM:", StringComparison.OrdinalIgnoreCase) && !s.ToolName.Contains("テスト模擬", StringComparison.OrdinalIgnoreCase) && !s.ToolName.Contains("[SIM", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var realProcesses = processes
            .Where(p => !p.IsSimulated && !p.ProcessKey.StartsWith("sim:", StringComparison.OrdinalIgnoreCase) && !p.ProcessName.Contains("テスト模擬", StringComparison.OrdinalIgnoreCase))
            .ToList();

        string key = $"SNAPSHOT:{DateTime.Now:HHmmss}";
        var countries = connections
            .GroupBy(c => $"{c.CountryFlag}{GeoIpService.GetLocalizedCountryName(c.CountryCode, c.CountryName)}({c.CountryCode})")
            .Select(g => $"{g.Key}: {g.Count()}")
            .ToList();

        var topProcs = connections
            .Where(c => c.CountryCode != "LOCAL" && c.CountryCode != "LAN")
            .GroupBy(c =>
            {
                bool isSelf = ProcessMonitorService.CheckIsSelfProcess(c.ProcessId, c.ProcessName, c.ProcessPath);
                string pLabel = isSelf ? $"{c.ProcessName} [Self]" : c.ProcessName;
                return $"{pLabel} -> {GeoIpService.GetLocalizedCountryName(c.CountryCode, c.CountryName)}({c.Organization})";
            })
            .Select(g => $"  - {g.Key} ({g.Count()})")
            .Take(12)
            .ToList();

        string postureSummary = posture != null
            ? Loc.T(
                $"- Security Score: {posture.Score}/100 (Grade {posture.Grade} — {posture.GradeComment})\n",
                $"・安全评分: {posture.Score}分 (等级 {posture.Grade} — {posture.GradeComment})\n",
                $"- Puntuación de Seguridad: {posture.Score}/100 (Grado {posture.Grade} — {posture.GradeComment})\n",
                $"・セキュリティ安全スコア: {posture.Score}点 (グレード {posture.Grade} — {posture.GradeComment})\n")
            : "";
        string defenseSummary = findings != null
            ? Loc.T(
                $"- System Defense Findings: Total {findings.Count(f => !f.IsSimulated)} (Medium+ Risk: {findings.Count(f => !f.IsSimulated && f.EffectiveSeverity >= RiskLevel.Medium)})\n",
                $"・系统防御检测数: 总计 {findings.Count(f => !f.IsSimulated)} 项 (其中需注意以上: {findings.Count(f => !f.IsSimulated && f.EffectiveSeverity >= RiskLevel.Medium)}项)\n",
                $"- Hallazgos de Defensa del Sistema: Total {findings.Count(f => !f.IsSimulated)} (Riesgo Medio+: {findings.Count(f => !f.IsSimulated && f.EffectiveSeverity >= RiskLevel.Medium)})\n",
                $"・システム防御検知数: 総数 {findings.Count(f => !f.IsSimulated)} 件 (うち要注意以上: {findings.Count(f => !f.IsSimulated && f.EffectiveSeverity >= RiskLevel.Medium)}件)\n")
            : "";

        string details = Loc.T(
            $"[Full PC Traffic, Process & System Defense Snapshot]\n" +
            postureSummary +
            defenseSummary +
            $"- Total Active TCP/UDP Connections: {connections.Count}\n" +
            $"- By Country: {(countries.Count > 0 ? string.Join(", ", countries) : "No external connections")}\n" +
            $"- Screen Share / Remote Tools Detected: {realScreenShares.Count}\n" +
            $"- Monitored Processes: {realProcesses.Count} (Periodic: {realProcesses.Count(p => p.IsPeriodic)}, New/Rare: {realProcesses.Count(p => p.IsRareOrNew && !p.IsSelfProcess)})\n" +
            $"- Top External Communicating Processes:\n{(topProcs.Count > 0 ? string.Join("\n", topProcs) : "  (None)")}",
            $"【当前电脑网络通信、进程与系统防御快照】\n" +
            postureSummary +
            defenseSummary +
            $"・活动 TCP/UDP 连接总数: {connections.Count}\n" +
            $"・按国家/地区统计: {(countries.Count > 0 ? string.Join(", ", countries) : "无外部通信")}\n" +
            $"・屏幕共享/远程工具检测数: {realScreenShares.Count}\n" +
            $"・监控进程总数: {realProcesses.Count} (周期性: {realProcesses.Count(p => p.IsPeriodic)}, 首次/罕见: {realProcesses.Count(p => p.IsRareOrNew && !p.IsSelfProcess)})\n" +
            $"・主要外部通信进程列表:\n{(topProcs.Count > 0 ? string.Join("\n", topProcs) : "  (无)")}",
            $"[Instantánea Completa de Red, Procesos y Defensa del PC]\n" +
            postureSummary +
            defenseSummary +
            $"- Total Conexiones TCP/UDP Activas: {connections.Count}\n" +
            $"- Por País: {(countries.Count > 0 ? string.Join(", ", countries) : "Sin conexiones externas")}\n" +
            $"- Herramientas de Pantalla Compartida / Remoto: {realScreenShares.Count}\n" +
            $"- Procesos Monitoreados: {realProcesses.Count} (Periódicos: {realProcesses.Count(p => p.IsPeriodic)}, Nuevos/Raros: {realProcesses.Count(p => p.IsRareOrNew && !p.IsSelfProcess)})\n" +
            $"- Principales Procesos con Tráfico Externo:\n{(topProcs.Count > 0 ? string.Join("\n", topProcs) : "  (Ninguno)")}",
            $"【現在のPC通信・プロセス・システム防御スナップショット】\n" +
            postureSummary +
            defenseSummary +
            $"・アクティブTCP/UDP接続総数: {connections.Count} 件\n" +
            $"・国別内訳: {(countries.Count > 0 ? string.Join(", ", countries) : "外部通信なし")}\n" +
            $"・画面共有/遠隔ツール検出数: {realScreenShares.Count} 件\n" +
            $"・監視プロセス総数: {realProcesses.Count} 件 (うち周期性検出: {realProcesses.Count(p => p.IsPeriodic)}件, 初出/レア: {realProcesses.Count(p => p.IsRareOrNew && !p.IsSelfProcess)}件)\n" +
            $"・主な外部通信プロセス一覧:\n{(topProcs.Count > 0 ? string.Join("\n", topProcs) : "  (なし)")}");

        AddOrUpdateLog(key, LogCategory.SystemSecurity, RiskLevel.Low,
            Loc.T(
                $"[Full System Snapshot] Country Traffic & Process Summary ({DateTime.Now:HH:mm:ss})",
                $"【全系统诊断快照】当前国家通信与进程状态摘要 ({DateTime.Now:HH:mm:ss})",
                $"[Instantánea del Sistema] Resumen de Tráfico y Procesos ({DateTime.Now:HH:mm:ss})",
                $"【全体診断スナップショット】現在の国別通信・プロセス状況サマリー ({DateTime.Now:HH:mm:ss})"),
            Loc.T(
                "Summary for periodic PC health check",
                "用于电脑整体通信与进程健康检查的摘要",
                "Resumen general para revisión de salud del PC",
                "PC全体の通信傾向・プロセス稼働状況の定期ヘルスチェック用サマリー"),
            details, "System Overview", string.Join(", ", countries.Take(4)),
            Loc.T(
                "Please provide an overall security assessment of the current external traffic and process activity on this PC.",
                "请对当前电脑的外部通信趋势和进程活动进行整体安全评估，检查是否存在可疑之处。",
                "Por favor, realice una evaluación general de seguridad sobre el tráfico externo y los procesos actuales de este PC.",
                "現在のPCの外部通信傾向に不審な点がないか全体的なセキュリティ評価をお願いします。"),
            out _);
    }

    public bool RemoveSimulatedLogs()
    {
        var simKeys = _logMap
            .Where(kv =>
                kv.Key.Contains(":SIM:", StringComparison.OrdinalIgnoreCase) ||
                kv.Key.Contains(":sim:", StringComparison.OrdinalIgnoreCase) ||
                kv.Value.Title.Contains("テスト模擬", StringComparison.OrdinalIgnoreCase) ||
                kv.Value.Title.Contains("[SIM", StringComparison.OrdinalIgnoreCase) ||
                kv.Value.TechnicalDetails.Contains("テスト模擬", StringComparison.OrdinalIgnoreCase) ||
                kv.Value.TechnicalDetails.Contains("SimulationTest.exe", StringComparison.OrdinalIgnoreCase))
            .Select(kv => kv.Key)
            .ToList();

        foreach (var k in simKeys)
        {
            _logMap.Remove(k);
        }

        return simKeys.Count > 0;
    }

    public void ClearLogs() => _logMap.Clear();

    private bool AddOrUpdateLog(
        string key,
        LogCategory category,
        RiskLevel severity,
        string title,
        string summary,
        string technicalDetails,
        string relatedProcess,
        string relatedEndpoint,
        string recommendedAction,
        out SecurityLogEntry? newlyCreated,
        ConfidenceLevel confidence = ConfidenceLevel.Medium,
        string storyKey = "",
        string processLineage = "",
        bool isHistorical = false)
    {
        newlyCreated = null;
        if (_logMap.TryGetValue(key, out var existing))
        {
            existing.LastTimestamp = DateTime.Now;
            existing.OccurrenceCount++;
            existing.Severity = severity;
            existing.Confidence = confidence;
            if (!existing.IsHistorical && isHistorical && !IncludeHistoricalLogsByDefault)
            {
                existing.IsSelected = false; // 過去履歴に変化したため除外
            }
            existing.IsHistorical = isHistorical;
            if (!string.IsNullOrEmpty(storyKey)) existing.StoryKey = storyKey;
            if (!string.IsNullOrEmpty(processLineage)) existing.ProcessLineage = processLineage;
            existing.Title = title;
            existing.Summary = summary;
            existing.TechnicalDetails = technicalDetails;
            existing.RecommendedAction = recommendedAction;
            return false;
        }

        bool defaultSelected = isHistorical ? IncludeHistoricalLogsByDefault : true;
        var entry = new SecurityLogEntry
        {
            LogKey = key,
            Timestamp = DateTime.Now,
            LastTimestamp = DateTime.Now,
            OccurrenceCount = 1,
            Category = category,
            Severity = severity,
            Confidence = confidence,
            IsHistorical = isHistorical,
            StoryKey = storyKey,
            ProcessLineage = processLineage,
            Title = title,
            Summary = summary,
            TechnicalDetails = technicalDetails,
            RelatedProcess = relatedProcess,
            RelatedEndpoint = relatedEndpoint,
            RecommendedAction = recommendedAction,
            IsSelected = defaultSelected
        };
        _logMap[key] = entry;
        newlyCreated = entry;
        return true;
    }

    public string BuildAiConsultationPrompt(
        IEnumerable<SecurityLogEntry> selectedLogs,
        bool maskPersonalInfo,
        string additionalUserNote = "")
    {
        var list = selectedLogs.ToList();
        var sb = new StringBuilder();

        sb.AppendLine(Loc.T(
            "# Security Log Consultation Request (Anzen Security Watcher Output)",
            "# 安全日志诊断请求 (Anzen Security Watcher 输出)",
            "# Solicitud de Diagnóstico de Registros de Seguridad (Anzen Security Watcher)",
            "# セキュリティログ診断依頼 (Anzen Security Watcher 出力)"));
        sb.AppendLine();
        sb.AppendLine(Loc.T(
            "You are an expert SOC analyst specializing in Windows OS, network security, and malware analysis.",
            "您是一位精通 Windows 操作系统、网络安全与恶意软件分析的专家（SOC 分析师）。",
            "Actúa como un analista SOC experto en Windows OS, seguridad de redes y análisis de malware.",
            "あなたはWindows OS・ネットワークセキュリティ・マルウェア解析の専門家（SOCアナリスト）です。"));
        sb.AppendLine(Loc.T(
            "A security monitoring tool running on my Windows 11 PC detected the following notable network connections, processes, or screen-sharing events.",
            "我的 Windows 11 电脑上运行的安全监控工具检测到了以下值得注意的网络通信、进程或屏幕共享事件。",
            "Una herramienta de monitoreo de seguridad en mi PC con Windows 11 detectó las siguientes conexiones de red, procesos o eventos de pantalla compartida.",
            "私のWindows 11 PCで稼働しているセキュリティ監視ツールが以下の気になる通信・プロセス・画面共有イベントを検知しました。"));
        sb.AppendLine(Loc.T(
            "Please analyze each log entry from an expert perspective and provide actionable advice.",
            "请从专业角度分析每条日志并提供处理建议。",
            "Por favor, analiza cada registro desde una perspectiva experta y proporciona recomendaciones claras.",
            "それぞれのログについて、専門家の視点から分析とアドバイスをお願いします。"));
        sb.AppendLine();
        sb.AppendLine(Loc.T(
            "## 1. Environment Information",
            "## 1. 运行环境信息",
            "## 1. Información del Entorno",
            "## 1. 実行環境情報"));
        sb.AppendLine($"- **OS**: Windows 11 ({Environment.OSVersion.VersionString}, 64-bit)");
        sb.AppendLine(Loc.T(
            $"- **Timestamp**: {DateTime.Now:yyyy-MM-dd HH:mm:ss}",
            $"- **日志输出时间**: {DateTime.Now:yyyy-MM-dd HH:mm:ss}",
            $"- **Fecha y hora**: {DateTime.Now:yyyy-MM-dd HH:mm:ss}",
            $"- **ログ出力日時**: {DateTime.Now:yyyy-MM-dd HH:mm:ss}"));
        sb.AppendLine(Loc.T(
            $"- **Monitoring Program (Self)**: `AnzenSecurityWatcher` (Executable: `{Environment.ProcessPath ?? "AnzenSecurityWatcher.exe"}`, PID: {Environment.ProcessId})",
            $"- **生成此日志的监控程序自身**: `AnzenSecurityWatcher` (可执行文件: `{Environment.ProcessPath ?? "AnzenSecurityWatcher.exe"}`, PID: {Environment.ProcessId})",
            $"- **Programa de monitoreo (Propio)**: `AnzenSecurityWatcher` (Ejecutable: `{Environment.ProcessPath ?? "AnzenSecurityWatcher.exe"}`, PID: {Environment.ProcessId})",
            $"- **このログを生成した監視プログラム自身**: `AnzenSecurityWatcher` (実行ファイル: `{Environment.ProcessPath ?? "AnzenSecurityWatcher.exe"}`, PID: {Environment.ProcessId})"));
        string geoIpSelfNote = SettingsManager.Current.DisableOnlineGeoIp
            ? Loc.T(
                "  - **Note for AI**: `AnzenSecurityWatcher` is the monitoring application that generated this report. It is locally built (unsigned) and running in **Offline Mode (Online GeoIP disabled)**, so it sends NO external network requests. Do not misclassify it as suspicious.",
                "  - **※致 AI 的重要说明**: 日志中出现的 `AnzenSecurityWatcher` 是生成并输出本日志的监控程序自身。因系本地构建故无数字签名；当前处于**离线模式（已禁用在线 GeoIP 查询）**，完全不向外部发送网络请求，请勿将其误判为可疑程序。",
                "  - **Nota importante para la IA**: `AnzenSecurityWatcher` es el propio programa que generó este informe. Es una compilación local (sin firma) y funciona en **Modo sin conexión (GeoIP desactivado)**, por lo que NO realiza solicitudes de red externas. No lo clasifique erróneamente como sospechoso.",
                "  - **※AIへの重要注記**: ログ内に登場する `AnzenSecurityWatcher` は、**このログ自体を生成・出力している自分自身のプログラム**です。ローカルでビルドされたプログラムのためデジタル署名は付与されていません。現在は**オフラインモード（オンラインGeoIP無効化）**で動作しており外部への通信は一切行いません。未署名の不審なアプリとして誤判定しないようご注意ください。")
            : Loc.T(
                "  - **Note for AI**: `AnzenSecurityWatcher` is the monitoring application that generated this report. It is locally built (unsigned) and queries external GeoIP APIs to resolve IP countries. Do not misclassify it as suspicious.",
                "  - **※致 AI 的重要说明**: 日志中出现的 `AnzenSecurityWatcher` 是生成并输出本日志的监控程序自身。因系本地构建故无数字签名，且会访问外部 GeoIP API 查询 IP 所属国家，请勿将其误判为可疑程序。",
                "  - **Nota importante para la IA**: `AnzenSecurityWatcher` es el propio programa que generó este informe. Es una compilación local (sin firma) y consulta APIs GeoIP externas; no lo clasifique erróneamente como sospechoso.",
                "  - **※AIへの重要注記**: ログ内に登場する `AnzenSecurityWatcher` は、**このログ自体を生成・出力している自分自身のプログラム**です。ローカルでビルドされたプログラムのためデジタル署名は付与されておらず、またIPアドレスの国別判定(GeoIP)のために外部APIと通信を行います。未署名の不審なアプリとして誤判定しないようご注意ください。");
        sb.AppendLine(geoIpSelfNote);
        sb.AppendLine(Loc.T(
            $"- **Selected Logs Count**: {list.Count}",
            $"- **咨询日志数量**: {list.Count} 条",
            $"- **Cantidad de registros seleccionados**: {list.Count}",
            $"- **相談対象ログ件数**: {list.Count} 件"));
        if (!string.IsNullOrWhiteSpace(additionalUserNote))
        {
            sb.AppendLine(Loc.T(
                $"- **User Note**: {additionalUserNote.Trim()}",
                $"- **用户补充说明**: {additionalUserNote.Trim()}",
                $"- **Nota del usuario**: {additionalUserNote.Trim()}",
                $"- **ユーザーからの補足状況**: {additionalUserNote.Trim()}"));
        }
        sb.AppendLine();

        // 1.5 Security Stories 相関サマリー（Office更新、ベンダーツール群、Per-Userサービス等の文脈統合）
        var stories = SecurityStoryEngine.BuildStories(list, _cachedProcesses, _cachedFindings);
        if (stories.Count > 0)
        {
            sb.Append(SecurityStoryEngine.FormatStoriesForAiPrompt(stories));
        }

        sb.AppendLine(Loc.T(
            "## 2. Detected Security Log Details",
            "## 2. 检测到的安全日志详情",
            "## 2. Detalles de los Registros de Seguridad Detectados",
            "## 2. 検知されたセキュリティログ詳細"));
        sb.AppendLine();

        if (list.Count == 0)
        {
            sb.AppendLine(Loc.T(
                "*(No logs are currently selected. Click the '📸 Add Full PC Snapshot' button at the top left to capture a snapshot, or check the logs you want to consult about from the list.)*",
                "*(当前未选择任何日志。请点击左上角的“📸 添加电脑完整快照”按钮采集快照，或在列表中勾选您想咨询 AI 的日志。)*",
                "*(Actualmente no hay registros seleccionados. Haga clic en '📸 Añadir instantánea del PC' arriba a la izquierda o marque los registros en la lista.)*",
                "*(現在選択されているログはありません。左上の「📸 PC全体スナップショット追加」ボタンを押してログを採取するか、一覧からAIに相談したいログにチェックを入れてください)*"));
        }
        else
        {
            int idx = 1;
            foreach (var log in list)
            {
                sb.AppendLine($"### [{idx}] {log.Title}");
                sb.AppendLine(Loc.T(
                    $"- **Severity**: {log.SeverityLabel}",
                    $"- **严重程度**: {log.SeverityLabel}",
                    $"- **Severidad**: {log.SeverityLabel}",
                    $"- **重要度**: {log.SeverityLabel}"));
                sb.AppendLine(Loc.T(
                    $"- **Category**: {log.CategoryLabel}",
                    $"- **类别**: {log.CategoryLabel}",
                    $"- **Categoría**: {log.CategoryLabel}",
                    $"- **カテゴリ**: {log.CategoryLabel}"));
                sb.AppendLine(Loc.T(
                    $"- **Detected Time**: First {log.Timestamp:HH:mm:ss} / Last {log.LastTimestamp:HH:mm:ss} (Count: {log.OccurrenceCount})",
                    $"- **检测时间**: 首次 {log.Timestamp:HH:mm:ss} / 最近 {log.LastTimestamp:HH:mm:ss} (共 {log.OccurrenceCount} 次)",
                    $"- **Hora de detección**: Primera {log.Timestamp:HH:mm:ss} / Última {log.LastTimestamp:HH:mm:ss} (Total: {log.OccurrenceCount})",
                    $"- **検知時刻**: 初回 {log.Timestamp:HH:mm:ss} / 最終 {log.LastTimestamp:HH:mm:ss} (計 {log.OccurrenceCount} 回検知)"));
                sb.AppendLine(Loc.T(
                    "- **Technical Details**:",
                    "- **技术详情**:",
                    "- **Detalles técnicos**:",
                    "- **技術的詳細**:"));
                sb.AppendLine("```text");
                sb.AppendLine(log.TechnicalDetails.Trim());
                sb.AppendLine("```");

                if (!string.IsNullOrWhiteSpace(log.ProcessLineage))
                {
                    sb.AppendLine(Loc.T(
                        "- **Process Lineage (Parent → Grandparent → Great-grandparent | CommandLine & StartTime)**:",
                        "- **进程祖先系谱 (父进程 → 祖父进程 → 曾祖父进程 | 命令行与启动时间)**:",
                        "- **Linaje de Procesos (Padre → Abuelo → Bisabuelo | CommandLine y StartTime)**:",
                        "- **プロセス祖先系譜 (親 → 祖父 → 曾祖父 | コマンドライン・開始時刻付き)**:"));
                    sb.AppendLine("```text");
                    sb.AppendLine(log.ProcessLineage.Trim());
                    sb.AppendLine("```");
                }
                sb.AppendLine(Loc.T(
                    $"- **Question / Focus**: {log.RecommendedAction}",
                    $"- **需要确认的重点**: {log.RecommendedAction}",
                    $"- **Punto a verificar**: {log.RecommendedAction}",
                    $"- **確認したいポイント**: {log.RecommendedAction}"));
                sb.AppendLine();
                idx++;
            }
        }

        sb.AppendLine(Loc.T(
            "## 3. Questions for AI (Please structure your response as follows)",
            "## 3. 请 AI 回答的问题（请按以下结构回答）",
            "## 3. Preguntas para la IA (Responda con la siguiente estructura)",
            "## 3. AIへの質問事項（以下の構成で回答してください）"));
        sb.AppendLine(Loc.T(
            "1. **Overall Risk Assessment**: Classify each log entry as 'Safe (Normal OS/app behavior)', 'Caution (Unwanted software or configuration review recommended)', or 'Danger (Suspected unauthorized access or malware)'.",
            "1. **综合风险评估**: 请针对每条日志说明其属于“安全（系统或正规软件的正常行为）”、“注意（建议检查的软件或配置）”还是“危险（疑似未授权访问或恶意软件）”。",
            "1. **Evaluación General de Riesgo**: Clasifique cada registro como 'Seguro (Comportamiento normal del SO/app)', 'Precaución (Revisar configuración o software)' o 'Peligro (Sospecha de acceso no autorizado o malware)'.",
            "1. **総合危険度判定**: 各ログについて「安全（OSや正規アプリの通常動作）」「注意（不要ソフトや設定確認推奨）」「危険（不正アクセス・マルウェア等の疑い）」のどれに該当するか教えてください。"));
        sb.AppendLine(Loc.T(
            "2. **Explanation of Process & Remote Host**: Clearly explain what the listed process name, executable path, destination country/organization, or periodic behavior is normally used for.",
            "2. **进程与通信目标解析**: 请通俗易懂地解释日志中的进程名称、执行路径、通信目标国家/组织或周期性行为原本的用途。",
            "2. **Explicación del Proceso y Destino**: Explique claramente para qué sirven normalmente el proceso, la ruta, el país/organización de destino o el comportamiento periódico.",
            "2. **プロセス・通信先の正体解説**: 記載されているプロセス名、実行パス、通信先の国・組織、または周期的動作が本来何の目的で行われるものか分かりやすく解説してください。"));
        sb.AppendLine(Loc.T(
            "3. **Recommended Verification & Remediation Steps**: Provide concrete PowerShell commands to further verify safety, and step-by-step instructions to block or remove anything suspicious.",
            "3. **建议的具体排查与处置步骤**: 请提供用于进一步验证安全性的 PowerShell 命令，以及在确认可疑时的具体阻断与清除步骤。",
            "3. **Pasos Recomendados de Verificación y Remediación**: Proporcione comandos concretos de PowerShell para verificar la seguridad y pasos detallados para bloquear o eliminar elementos sospechosos.",
            "3. **推奨される具体的な確認手順・対処法**: 安全性を追加検証するためのPowerShellコマンドや、もし不審だった場合の遮断・駆除手順を具体的に教えてください。"));
        sb.AppendLine(Loc.T(
            "4. **Corporate PC Policy & Shadow IT Considerations**: If remote access tools (e.g. TeamViewer, AnyDesk) or personal productivity tools (e.g. Wox, AutoHotkey) are detected, please advise whether they may require verification or approval by the organization's IT/security department under company security policies.",
            "4. **企业电脑政策与影子IT注意**: 若检测到远程控制工具（如 TeamViewer、AnyDesk）或个人效能工具（如 Wox、AutoHotkey），请提示在公司电脑环境下是否需要确认内部 IT/安全规程或报备许可。",
            "4. **Consideraciones de Políticas Corporativas / Shadow IT**: Si se detectan herramientas remotas (p. ej. TeamViewer, AnyDesk) o utilidades personales (Wox, AutoHotkey), oriente si requieren verificación con el departamento de TI de la empresa según normativas internas.",
            "4. **社用PCのセキュリティ規程・シャドーITに関する注意点**: リモートアクセスツール（TeamViewer、AnyDesk等）や個人導入のランチャー・自動化ツール（Wox、AutoHotkey等）が検知された場合、社用PCでは社内規程（シャドーIT・利用申請制）の対象となるケースがあるため、情シス部門への確認を促すアドバイスも含めてください。"));

        string rawPrompt = sb.ToString();
        return maskPersonalInfo ? MaskSensitiveData(rawPrompt) : rawPrompt;
    }

    private static string MaskSensitiveData(string input)
    {
        string result = input;

        // 1. Windows ユーザー名のマスク
        string userName = Environment.UserName;
        if (!string.IsNullOrWhiteSpace(userName) && userName.Length >= 2)
        {
            result = Regex.Replace(
                result,
                Regex.Escape($"\\Users\\{userName}"),
                "\\Users\\[USER_NAME]",
                RegexOptions.IgnoreCase);

            // 単語境界 \b を追加して、admin -> [USER_NAME]istrator 等の破壊的置換を防止
            result = Regex.Replace(
                result,
                $@"\b{Regex.Escape(userName)}\b",
                "[USER_NAME]",
                RegexOptions.IgnoreCase);
        }

        // 2. コンピュータ名 (ホスト名) のマスク
        string machineName = Environment.MachineName;
        if (!string.IsNullOrWhiteSpace(machineName) && machineName.Length >= 2)
        {
            result = Regex.Replace(
                result,
                $@"\b{Regex.Escape(machineName)}\b",
                "[MY_PC]",
                RegexOptions.IgnoreCase);
        }

        // 3. プライベートIPアドレス (192.168.x.x, 10.x.x.x, 172.16-31.x.x) の末尾オクテットをマスク
        result = Regex.Replace(result, @"\b192\.168\.\d{1,3}\.\d{1,3}\b", "192.168.x.x");
        result = Regex.Replace(result, @"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "10.x.x.x");
        result = Regex.Replace(result, @"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b", "172.16.x.x");

        // 4. コマンドライン引数内のトークン、APIキー、シークレット、パスワードのマスク
        result = CommandLineAnalyzer.MaskSensitiveArguments(result);

        return result;
    }
}
