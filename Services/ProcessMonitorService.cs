using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using AnzenSecurityWatcher.Models;

namespace AnzenSecurityWatcher.Services;

public class ProcessMonitorService : IDisposable
{
    private readonly ConcurrentDictionary<string, ProcessAnalysisItem> _processMap = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<int> _previousActivePids = new();
    private bool _isInitialSnapshotDone = false;
    private readonly string _baselineFilePath;

    // --- 50ms 高速スナイパー監視（0.3秒で消える瞬間ターミナル・短命プロセス捕捉用） ---
    private readonly ConcurrentDictionary<int, SniperTrackedProcess> _sniperActivePids = new();
    private readonly ConcurrentQueue<int> _pendingTaskMatchPids = new();
    private CancellationTokenSource? _sniperCts;
    private bool _sniperInitialized = false;
    private DateTime _lastTaskCacheUpdate = DateTime.MinValue;
    private List<RecentScheduledTaskInfo> _cachedRecentTasks = new();
    private readonly object _taskCacheLock = new();

    /// <summary>瞬間ターミナル（短命プロセス）を新たに捕捉した際に発火するイベント</summary>
    public event Action<ProcessAnalysisItem>? OnTransientProcessCaptured;

    private class SniperTrackedProcess
    {
        public int Pid { get; init; }
        public int ParentPid { get; set; }
        public string ProcessName { get; init; } = "";
        public string ExecutablePath { get; set; } = "";
        public string CommandLine { get; set; } = "";
        public string ParentName { get; set; } = "";
        public string ParentCommandLine { get; set; } = "";
        public string ParentDisplay { get; set; } = "—";
        public int GrandparentPid { get; set; }
        public string GrandparentName { get; set; } = "";
        public string TreeSummary { get; set; } = "";
        public string TreeDetail { get; set; } = "";
        public string ProcessKey { get; set; } = "";
        public DateTime DetectedAt { get; init; }
        public DateTime KernelCreationTime { get; set; }
        public bool IsConsoleOrShell { get; set; }
        public bool HadVisibleConsoleWindow { get; set; }
        public string ConsoleWindowTitle { get; set; } = "";
    }

    public record RecentScheduledTaskInfo(
        string TaskPath,
        string TaskName,
        DateTime LastRunTime,
        DateTime NextRunTime,
        int LastTaskResult,
        string ActionCommand,
        string Author);

    // 初期起動時に存在する標準的なOSプロセスのホワイトリスト補助
    // ※ conhost 等は短命ターミナルのホストになるため、後から新規起動した際は個別追跡する
    private static readonly HashSet<string> CoreWindowsProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Registry", "smss", "csrss", "wininit", "services", "lsass",
        "svchost", "fontdrvhost", "winlogon", "dwm", "explorer", "sihost",
        "taskhostw", "RuntimeBroker", "SearchHost", "StartMenuExperienceHost",
        "ctfmon", "dllhost", "WmiPrvSE", "spoolsv", "audiodg",
        "SecurityHealthService", "SecurityHealthSystray", "MsMpEng", "NisSrv"
    };

    // 0.3秒で消えるターミナルの原因になりやすいコンソール・シェル・コマンド系プロセス
    private static readonly HashSet<string> ConsoleAndShellProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd", "powershell", "pwsh", "conhost", "openconsole", "windowsterminal", "wt",
        "wscript", "cscript", "mshta", "schtasks", "reg", "sc", "net", "net1",
        "rundll32", "regsvr32", "certutil", "bitsadmin", "wmic", "curl", "wget",
        "winget", "msiexec", "taskkill", "attrib", "icacls", "takeown", "bcdedit",
        "vssadmin", "wbadmin", "wevtutil", "netsh", "ipconfig", "whoami", "systeminfo",
        "nltest", "dsquery", "csvde", "ldifde", "robocopy", "xcopy", "findstr", "where",
        "forfiles", "pcalua", "bash", "wsl", "wslhost", "python", "pythonw", "node", "git"
    };

    private static readonly System.Text.RegularExpressions.Regex AiAgentChainRegex = new(
        @"hermes|nousresearch|hermes_cli|_launchers\.py|\\hermes\\|\\appdata\\local\\hermes|hermes-setup|hermes-no-console|\\uv\\python\\",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);

    // コンソール/ターミナルのウィンドウクラス名
    private static readonly string[] ConsoleWindowClassKeywords =
    {
        "ConsoleWindowClass",
        "CASCADIA_HOSTING_WINDOW_CLASS",
        "PseudoConsoleWindow",
        "VirtualConsoleClass"
    };

    public ProcessMonitorService()
    {
        string dataDir = JsonStore.DataDir;
        try { Directory.CreateDirectory(dataDir); } catch { }
        _baselineFilePath = Path.Combine(dataDir, "process_baseline.json");
        LoadBaseline();
        StartTransientSniperLoop();
    }

    public static bool IsConsoleOrShellProcess(string procName)
    {
        if (string.IsNullOrWhiteSpace(procName)) return false;
        string clean = procName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? procName[..^4]
            : procName;
        return ConsoleAndShellProcesses.Contains(clean);
    }

    /// <summary>
    /// 50ms (0.05秒) 周期でカーネルのプロセススナップショットを監視し、
    /// 0.1〜0.5秒で一瞬だけ現れて消えるターミナル（短命プロセス）のコマンドライン引数・親プロセス・生存時間を確実に捕捉する。
    /// </summary>
    private void StartTransientSniperLoop()
    {
        _sniperCts = new CancellationTokenSource();
        var token = _sniperCts.Token;

        Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    RunSniperTick();
                }
                catch
                {
                    // Ignore transient sniper errors
                }

                try
                {
                    int delayMs = SettingsManager.Current.ScanInterval switch
                    {
                        ScanIntervalMode.PowerSaving => 120,
                        ScanIntervalMode.Standard => 75,
                        _ => 55
                    };
                    await Task.Delay(delayMs, token);
                }
                catch (TaskCanceledException)
                {
                    break;
                }
            }
        }, token);
    }

    private void RunSniperTick()
    {
        var fastList = NativeSecurity.GetFastProcessSnapshot();
        if (fastList.Count == 0) return;

        DateTime now = DateTime.Now;
        var currentPidDict = new Dictionary<int, NativeSecurity.FastProcessEntry>(fastList.Count);
        foreach (var e in fastList)
        {
            currentPidDict[e.Pid] = e;
        }

        // 初回スナップショット時は現在稼働中のPIDを記録するのみ
        if (!_sniperInitialized)
        {
            foreach (var e in fastList)
            {
                string pName = Path.GetFileNameWithoutExtension(e.ExeFile);
                _sniperActivePids[e.Pid] = new SniperTrackedProcess
                {
                    Pid = e.Pid,
                    ParentPid = e.ParentPid,
                    ProcessName = pName,
                    DetectedAt = now,
                    IsConsoleOrShell = IsConsoleOrShellProcess(pName)
                };
            }
            _sniperInitialized = true;
            return;
        }

        var newlySpawnedThisTick = new List<SniperTrackedProcess>();

        // 1. 新規に出現したPIDを即座に検査（プロセスが0.1〜0.3秒で消える前にコマンドラインと親プロセスを抜き取る）
        foreach (var e in fastList)
        {
            if (_sniperActivePids.ContainsKey(e.Pid)) continue;

            string procName = Path.GetFileNameWithoutExtension(e.ExeFile);
            var identity = NativeSecurity.QueryProcessIdentity(e.Pid);
            string exePath = identity?.ImagePath ?? "";
            string cmdLine = identity?.CommandLine ?? "";
            int parentPid = (identity != null && identity.ParentPid > 0) ? identity.ParentPid : e.ParentPid;
            DateTime kernelCreated = (identity != null && identity.CreationTime > DateTime.MinValue) ? identity.CreationTime : now;

            // 親プロセスの名前とコマンドラインを解決
            string parentName = "";
            string parentCmd = "";
            if (parentPid > 0)
            {
                if (_sniperActivePids.TryGetValue(parentPid, out var parentTracked))
                {
                    parentName = parentTracked.ProcessName;
                    parentCmd = parentTracked.CommandLine;
                }
                else if (currentPidDict.TryGetValue(parentPid, out var parentFast))
                {
                    parentName = Path.GetFileNameWithoutExtension(parentFast.ExeFile);
                }

                if (string.IsNullOrEmpty(parentCmd))
                {
                    var parentId = NativeSecurity.QueryProcessIdentity(parentPid);
                    if (parentId != null)
                    {
                        if (string.IsNullOrEmpty(parentName) && !string.IsNullOrEmpty(parentId.ImagePath))
                            parentName = Path.GetFileNameWithoutExtension(parentId.ImagePath);
                        parentCmd = parentId.CommandLine;
                    }
                }
            }

            string parentDisplay = NativeSecurity.DescribeParentOrigin(parentPid, parentName, parentCmd);
            bool isConsole = IsConsoleOrShellProcess(procName);

            // 祖先チェーン（親→祖父→曾祖父…）を、プロセスが消える前のこの瞬間に取得して保存する
            int gpPid = 0;
            string gpName = "";
            string treeSummary = "";
            string treeDetail = "";
            if (parentPid > 0)
            {
                try
                {
                    var nameMap = new Dictionary<int, string>(currentPidDict.Count);
                    foreach (var kv in currentPidDict)
                        nameMap[kv.Key] = Path.GetFileNameWithoutExtension(kv.Value.ExeFile);

                    var chain = NativeSecurity.QueryAncestorChain(parentPid, kernelCreated, nameMap, 5);
                    if (chain.Count > 1)
                    {
                        gpPid = chain[1].Pid;
                        gpName = chain[1].Name;
                    }
                    (treeSummary, treeDetail) = NativeSecurity.FormatProcessTree(chain, procName, e.Pid, cmdLine, kernelCreated);
                    if (chain.Count > 0 && chain.Count > 1)
                        parentDisplay = $"{parentDisplay} ⇐ {gpName}({gpPid})";
                }
                catch { }
            }
            string key = BuildProcessKey(procName, exePath, cmdLine, parentPid, parentName, isConsole, isDynamicSpawn: true);

            var tracked = new SniperTrackedProcess
            {
                Pid = e.Pid,
                ParentPid = parentPid,
                ProcessName = procName,
                ExecutablePath = exePath,
                CommandLine = cmdLine,
                ParentName = parentName,
                ParentCommandLine = parentCmd,
                ParentDisplay = parentDisplay,
                GrandparentPid = gpPid,
                GrandparentName = gpName,
                TreeSummary = treeSummary,
                TreeDetail = treeDetail,
                ProcessKey = key,
                DetectedAt = now,
                KernelCreationTime = kernelCreated,
                IsConsoleOrShell = isConsole
            };

            // もし conhost.exe / OpenConsole.exe が起動した場合、その親プロセス（または同時起動したプロセス）もコンソール表示としてマーク
            if (procName.Equals("conhost", StringComparison.OrdinalIgnoreCase) ||
                procName.Equals("OpenConsole", StringComparison.OrdinalIgnoreCase))
            {
                tracked.HadVisibleConsoleWindow = true;
                if (parentPid > 0 && _sniperActivePids.TryGetValue(parentPid, out var parentProc))
                {
                    parentProc.HadVisibleConsoleWindow = true;
                    if (_processMap.TryGetValue(parentProc.ProcessKey, out var parentItem))
                    {
                        parentItem.HadVisibleConsoleWindow = true;
                        parentItem.IsTransientFlash = true;
                        EvaluateProcessAnomaly(parentItem);
                    }
                }
            }

            _sniperActivePids[e.Pid] = tracked;
            newlySpawnedThisTick.Add(tracked);

            // _processMap に即座に登録・更新
            RegisterOrUpdateFromSniper(tracked, now);
        }

        // 2. 起動から4秒以内の新しいプロセスがある場合は、可視コンソールウィンドウが出ていないか高速チェック
        bool hasRecentSpawns = newlySpawnedThisTick.Count > 0 ||
                               _sniperActivePids.Values.Any(x => (now - x.DetectedAt).TotalSeconds <= 4.0);
        if (hasRecentSpawns)
        {
            CheckVisibleConsoleWindows(now);
        }

        // 3. 終了したPIDを検出し、生存時間 (DurationMs) を計算して短命プロセス（0.3秒フラッシュ等）として記録
        foreach (var kv in _sniperActivePids)
        {
            int pid = kv.Key;
            if (currentPidDict.ContainsKey(pid)) continue;

            if (_sniperActivePids.TryRemove(pid, out var exited))
            {
                double durationMs = (now - exited.DetectedAt).TotalMilliseconds;
                if (exited.KernelCreationTime > DateTime.MinValue && exited.KernelCreationTime <= now)
                {
                    double kernelMs = (now - exited.KernelCreationTime).TotalMilliseconds;
                    if (kernelMs > 5 && kernelMs < 60000)
                        durationMs = kernelMs;
                }
                if (durationMs < 15) durationMs = 45; // 最小1ティック分補正

                // 生存時間が 3.5 秒以下で消えたプロセス、またはコンソール/シェル系で 10 秒以内に終了したものを「瞬間ターミナル/短命プロセス」として記録
                bool isShortLived = durationMs <= 3500 || (exited.IsConsoleOrShell && durationMs <= 12000) || exited.HadVisibleConsoleWindow;

                if (_processMap.TryGetValue(exited.ProcessKey, out var item))
                {
                    item.IsCurrentlyRunning = false;
                    item.LastDurationMs = Math.Round(durationMs, 0);

                    if (isShortLived && !item.IsSelfProcess)
                    {
                        bool wasAlreadyTransient = item.IsTransientFlash;
                        item.IsTransientFlash = true;
                        item.IsRareOrNew = true;
                        if (exited.HadVisibleConsoleWindow)
                        {
                            item.HadVisibleConsoleWindow = true;
                            if (!string.IsNullOrEmpty(exited.ConsoleWindowTitle))
                                item.ConsoleWindowTitle = exited.ConsoleWindowTitle;
                        }

                        // タスクスケジューラの直近実行タスクと非同期で照合（プロセスの起動時刻を基準に照合）
                        DateTime estimatedLaunch = item.LaunchTimestamps.LastOrDefault();
                        if (estimatedLaunch == default) estimatedLaunch = item.FirstSeenTime;
                        _ = Task.Run(() => TryCorrelateWithScheduledTask(item, estimatedLaunch));

                        RecalculatePeriodicity(item);
                        EvaluateProcessAnomaly(item);

                        if (!wasAlreadyTransient || item.TotalSeenCount >= 1)
                        {
                            try { OnTransientProcessCaptured?.Invoke(item); } catch { }
                        }
                    }
                }
            }
        }
    }

    private void CheckVisibleConsoleWindows(DateTime now)
    {
        try
        {
            var topWindows = NativeMethods.GetTopLevelWindows();
            foreach (var w in topWindows)
            {
                bool isConsoleClass = ConsoleWindowClassKeywords.Any(k =>
                    w.ClassName.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (_sniperActivePids.TryGetValue(w.ProcessId, out var tracked))
                {
                    if (isConsoleClass || tracked.IsConsoleOrShell || (now - tracked.DetectedAt).TotalSeconds <= 3.5)
                    {
                        tracked.HadVisibleConsoleWindow = true;
                        if (!string.IsNullOrWhiteSpace(w.Title))
                            tracked.ConsoleWindowTitle = w.Title;

                        if (_processMap.TryGetValue(tracked.ProcessKey, out var item))
                        {
                            item.HadVisibleConsoleWindow = true;
                            if (!string.IsNullOrWhiteSpace(w.Title))
                                item.ConsoleWindowTitle = w.Title;
                            if ((now - tracked.DetectedAt).TotalSeconds <= 4.0)
                                item.IsTransientFlash = true;
                            EvaluateProcessAnomaly(item);
                        }
                    }
                }
            }
        }
        catch { }
    }

    private static string BuildProcessKey(
        string procName,
        string exePath,
        string cmdLine,
        int parentPid,
        string parentName,
        bool isConsoleOrShell,
        bool isDynamicSpawn)
    {
        string baseKey = !string.IsNullOrWhiteSpace(exePath)
            ? exePath.ToLowerInvariant()
            : procName.ToLowerInvariant();

        // 新規スポーンしたコンソール/シェル系プロセス（cmd, powershell, conhost, schtasks 等）は
        // 親プロセスやコマンドライン引数が異なれば別エントリとして分離し、どのタスクが何を起動したか消えないようにする
        if (isDynamicSpawn && isConsoleOrShell)
        {
            string normalizedCmd = (cmdLine ?? "").Trim();
            // conhost の場合は "--headless" やフォント引数等のランダムIDを除き、親プロセス名でグルーピング
            if (procName.Equals("conhost", StringComparison.OrdinalIgnoreCase) ||
                procName.Equals("OpenConsole", StringComparison.OrdinalIgnoreCase))
            {
                string pTag = string.IsNullOrEmpty(parentName) ? "unknown" : parentName.ToLowerInvariant();
                return $"{baseKey}::host_for:{pTag}";
            }

            if (!string.IsNullOrEmpty(normalizedCmd))
            {
                string pTag = string.IsNullOrEmpty(parentName) ? "" : parentName.ToLowerInvariant();
                int cmdHash = normalizedCmd.ToLowerInvariant().GetHashCode();
                return $"{baseKey}::spawn:{pTag}:{cmdHash:X8}";
            }
        }

        return baseKey;
    }

    private void RegisterOrUpdateFromSniper(SniperTrackedProcess tracked, DateTime now)
    {
        var (isSigned, signer) = CheckSignature(tracked.ExecutablePath, tracked.ProcessName);
        bool isSelf = CheckIsSelfProcess(tracked.Pid, tracked.ProcessName, tracked.ExecutablePath);

        if (!_processMap.TryGetValue(tracked.ProcessKey, out var item))
        {
            item = new ProcessAnalysisItem
            {
                ProcessKey = tracked.ProcessKey,
                ProcessName = tracked.ProcessName,
                ExecutablePath = string.IsNullOrWhiteSpace(tracked.ExecutablePath)
                    ? Loc.T("(Short-lived exit or protected system area)", "(短命退出或系统保护区域)", "(Salida fugaz o área protegida del sistema)", "(短命終了またはシステム保護領域)")
                    : tracked.ExecutablePath,
                CommandLine = tracked.CommandLine,
                ParentPid = tracked.ParentPid,
                ParentProcessName = tracked.ParentName,
                ParentCommandLine = tracked.ParentCommandLine,
                ParentDisplay = tracked.ParentDisplay,
                GrandparentPid = tracked.GrandparentPid,
                GrandparentProcessName = tracked.GrandparentName,
                ProcessTreeSummary = tracked.TreeSummary,
                ProcessTreeDetail = tracked.TreeDetail,
                IsSigned = isSigned,
                SignerName = isSelf
                    ? Loc.T("Self Process (Local build / Unsigned)", "自身进程 (本地构建/未签名)", "Proceso propio (Compilación local/Sin firma)", "自己プロセス (ローカルビルド・未署名)")
                    : signer,
                IsSelfProcess = isSelf,
                FirstSeenTime = now,
                LastSeenTime = now,
                CurrentPid = tracked.Pid,
                IsCurrentlyRunning = true,
                TotalSeenCount = 1,
                IsRareOrNew = (!CoreWindowsProcesses.Contains(tracked.ProcessName) || tracked.IsConsoleOrShell) && !isSelf,
                IsTransientFlash = tracked.IsConsoleOrShell || tracked.HadVisibleConsoleWindow,
                HadVisibleConsoleWindow = tracked.HadVisibleConsoleWindow,
                IsUserTrusted = false
            };

            if (!string.IsNullOrWhiteSpace(tracked.CommandLine))
            {
                item.RecentCommandHistory.Add($"[{now:HH:mm:ss}] {tracked.CommandLine}");
            }

            item.LaunchTimestamps.Add(now);
            EvaluateProcessAnomaly(item);
            _processMap[tracked.ProcessKey] = item;

            if (tracked.IsConsoleOrShell)
            {
                _ = Task.Run(() => TryCorrelateWithScheduledTask(item, now));
            }
        }
        else
        {
            item.IsCurrentlyRunning = true;
            item.CurrentPid = tracked.Pid;
            item.LastSeenTime = now;
            if (tracked.ParentPid > 0)
            {
                item.ParentPid = tracked.ParentPid;
                item.ParentProcessName = tracked.ParentName;
                item.ParentCommandLine = tracked.ParentCommandLine;
                item.ParentDisplay = tracked.ParentDisplay;
                if (!string.IsNullOrEmpty(tracked.TreeSummary))
                {
                    item.GrandparentPid = tracked.GrandparentPid;
                    item.GrandparentProcessName = tracked.GrandparentName;
                    item.ProcessTreeSummary = tracked.TreeSummary;
                    item.ProcessTreeDetail = tracked.TreeDetail;
                }
            }
            if (!string.IsNullOrWhiteSpace(tracked.CommandLine))
            {
                item.CommandLine = tracked.CommandLine;
                if (item.RecentCommandHistory.Count == 0 || !item.RecentCommandHistory[^1].EndsWith(tracked.CommandLine, StringComparison.Ordinal))
                {
                    item.RecentCommandHistory.Add($"[{now:HH:mm:ss}] {tracked.CommandLine}");
                    if (item.RecentCommandHistory.Count > 10)
                        item.RecentCommandHistory.RemoveAt(0);
                }
            }
            if (tracked.HadVisibleConsoleWindow)
            {
                item.HadVisibleConsoleWindow = true;
            }

            var lastLaunch = item.LaunchTimestamps.LastOrDefault();
            if ((now - lastLaunch).TotalSeconds >= 1.2)
            {
                item.TotalSeenCount++;
                item.LaunchTimestamps.Add(now);
                if (item.LaunchTimestamps.Count > 25)
                    item.LaunchTimestamps.RemoveAt(0);

                RecalculatePeriodicity(item);
            }
            EvaluateProcessAnomaly(item);
        }
    }

    /// <summary>
    /// タスクスケジューラ (Schedule.Service) の全フォルダ（\Microsoft\Windows 含む）から、
    /// プロセス起動時刻の直近に実行されたタスクや、実行パスが一致するタスクを照合する。
    /// プロセスの親子関係およびプロセスの実際の起動時刻を厳格に照合し、誤紐付けを防ぐ。
    /// </summary>
    private void TryCorrelateWithScheduledTask(ProcessAnalysisItem item, DateTime launchTime)
    {
        try
        {
            var recentTasks = GetRecentlyExecutedScheduledTasks(withinMinutes: 30, useCacheIfFresh: true);
            if (recentTasks.Count == 0) return;

            string procName = item.ProcessName;
            string exePath = item.ExecutablePath;

            // プロセスの実効起動時刻（履歴があれば直近の起動タイムスタンプを優先）
            DateTime effectiveLaunchTime = launchTime;
            if (item.LaunchTimestamps.Count > 0)
            {
                var lastLaunch = item.LaunchTimestamps.Last();
                if (lastLaunch.Year >= 2020 && Math.Abs((lastLaunch - launchTime).TotalSeconds) > 2)
                    effectiveLaunchTime = lastLaunch;
            }
            if (effectiveLaunchTime.Year < 2020) effectiveLaunchTime = item.FirstSeenTime;

            // 親プロセスがタスクスケジューラ系 (Schedule サービス, taskhostw, schtasks) かを判定
            string pName = item.ParentProcessName.ToLowerInvariant();
            string pDisp = item.ParentDisplay.ToLowerInvariant();
            string pCmd = item.ParentCommandLine.ToLowerInvariant();
            string tree = item.ProcessTreeDetail.ToLowerInvariant();
            bool isParentTaskScheduler =
                pName == "taskhostw" || pName == "taskhost" || pName == "schtasks" ||
                (pName == "svchost" && (pCmd.Contains("schedule") || pDisp.Contains("schedule"))) ||
                pDisp.Contains("task scheduler") || pDisp.Contains("タスクスケジューラ") ||
                tree.Contains("svchost.exe -k netsvcs -p -s schedule") ||
                item.GrandparentProcessName.Equals("taskhostw", StringComparison.OrdinalIgnoreCase);

            // 1. 実行コマンド内の実行ファイル名またはパスが一致するタスクを照合
            var matchedTasksByCmd = recentTasks.Where(t =>
            {
                if (string.IsNullOrWhiteSpace(t.ActionCommand)) return false;
                var (taskExe, _) = PathHelper.ExtractExecutableAndArguments(t.ActionCommand);
                string taskExeName = Path.GetFileNameWithoutExtension(taskExe);
                if (string.IsNullOrEmpty(taskExeName)) return false;

                // プロセス名 (拡張子なし) の完全一致、または実行ファイルパスの完全一致
                bool exeMatch = taskExeName.Equals(procName, StringComparison.OrdinalIgnoreCase) ||
                               taskExeName.Equals(Path.GetFileNameWithoutExtension(procName), StringComparison.OrdinalIgnoreCase);

                if (!exeMatch && !string.IsNullOrEmpty(exePath) && !exePath.StartsWith("("))
                {
                    string itemExeName = Path.GetFileNameWithoutExtension(exePath);
                    exeMatch = taskExeName.Equals(itemExeName, StringComparison.OrdinalIgnoreCase) ||
                               string.Equals(PathHelper.CleanFilePath(taskExe), PathHelper.CleanFilePath(exePath), StringComparison.OrdinalIgnoreCase);
                }

                return exeMatch;
            }).ToList();

            var matchByCmd = matchedTasksByCmd
                .OrderBy(t => Math.Abs((t.LastRunTime - effectiveLaunchTime).TotalSeconds))
                .FirstOrDefault();

            if (matchByCmd != null)
            {
                double diffSec = Math.Abs((matchByCmd.LastRunTime - effectiveLaunchTime).TotalSeconds);
                // 実行コマンドが一致する場合でも、起動時刻から120秒以内のタスクに限定（数時間離れた古い履歴を誤紐付けしない）
                if (diffSec <= 120.0)
                {
                    TaskCorrelationStrength strength = diffSec <= 5.0 ? TaskCorrelationStrength.Strong
                                                     : diffSec <= 30.0 ? TaskCorrelationStrength.Likely
                                                     : TaskCorrelationStrength.Possible;
                    string strengthLabel = strength switch
                    {
                        TaskCorrelationStrength.Strong => Loc.T("Strong correlation (±5s)", "强相关 (±5秒)", "Correlación fuerte", "強い相関 (±5秒以内)"),
                        TaskCorrelationStrength.Likely => Loc.T("Likely correlation (±30s)", "高概率相关 (±30秒)", "Correlación probable", "有力な相関 (±30秒以内)"),
                        _ => Loc.T("Possible correlation (±2m)", "可能相关 (±2分钟)", "Correlación posible", "相関候補 (±2分以内)")
                    };

                    string lastRunLabel = Loc.T("LastRun", "上次运行", "Última ejec.", "最終実行");
                    item.MatchedScheduledTask = $"{matchByCmd.TaskPath} [{strengthLabel}] ({lastRunLabel}:{matchByCmd.LastRunTime:HH:mm:ss})";
                    item.TaskCorrelation = strength;
                    item.TaskCorrelationDeltaSeconds = diffSec;
                    EvaluateProcessAnomaly(item);
                    return;
                }
            }

            // 2. 親プロセスがタスクスケジューラ (Schedule / taskhostw / svchost) である場合に限り、起動時刻の近傍タスクを照合
            // 親がタスクスケジューラではない（例: explorer, chrome, ユーザー手動起動）場合は誤検知防止のため同時刻照合を行わない
            if (isParentTaskScheduler)
            {
                var matchByTime = recentTasks
                    .Where(t => Math.Abs((t.LastRunTime - effectiveLaunchTime).TotalSeconds) <= 60.0)
                    .OrderBy(t => Math.Abs((t.LastRunTime - effectiveLaunchTime).TotalSeconds))
                    .FirstOrDefault();

                if (matchByTime != null)
                {
                    double diffSec = Math.Abs((matchByTime.LastRunTime - effectiveLaunchTime).TotalSeconds);
                    TaskCorrelationStrength strength = diffSec <= 5.0 ? TaskCorrelationStrength.Strong
                                                     : diffSec <= 30.0 ? TaskCorrelationStrength.Likely
                                                     : TaskCorrelationStrength.Possible;
                    string strengthLabel = strength switch
                    {
                        TaskCorrelationStrength.Strong => Loc.T("Strong correlation (±5s)", "强相关 (±5秒)", "Correlación fuerte", "強い相関 (±5秒以内)"),
                        TaskCorrelationStrength.Likely => Loc.T("Likely correlation (±30s)", "高概率相关 (±30秒)", "Correlación probable", "有力な相関 (±30秒以内)"),
                        _ => Loc.T("Possible correlation (±1m)", "可能相关 (±1分钟)", "Correlación posible", "相関候補 (±1分以内)")
                    };

                    string sameTimeLabel = Loc.T("CoincidentRun", "同时刻运行", "Ejec. simultánea", "同時刻実行");
                    string cmdLabel = Loc.T("Cmd", "命令", "Cmd", "コマンド");
                    item.MatchedScheduledTask = $"{matchByTime.TaskPath} [{strengthLabel}] ({sameTimeLabel}:{matchByTime.LastRunTime:HH:mm:ss} / {cmdLabel}:{CommandLineAnalyzer.Shorten(matchByTime.ActionCommand, 60)})";
                    item.TaskCorrelation = strength;
                    item.TaskCorrelationDeltaSeconds = diffSec;
                    EvaluateProcessAnomaly(item);
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// タスクスケジューラの全フォルダ（\Microsoft\Windows 配下の標準タスクも含む）を走査し、
    /// 直近 withinMinutes 分以内に実行されたスケジュールタスク一覧を最新順で取得する。
    /// </summary>
    public List<RecentScheduledTaskInfo> GetRecentlyExecutedScheduledTasks(int withinMinutes = 60, bool useCacheIfFresh = false)
    {
        lock (_taskCacheLock)
        {
            if (useCacheIfFresh && (DateTime.Now - _lastTaskCacheUpdate).TotalSeconds < 8 && _cachedRecentTasks.Count > 0)
            {
                return _cachedRecentTasks.Where(t => (DateTime.Now - t.LastRunTime).TotalMinutes <= withinMinutes).ToList();
            }
        }

        var result = StaRunner.Run(() =>
        {
            var list = new List<RecentScheduledTaskInfo>();
            var t = Type.GetTypeFromProgID("Schedule.Service");
            if (t == null) return list;
            dynamic service = Activator.CreateInstance(t)!;
            service.Connect();
            dynamic root = service.GetFolder("\\");
            DateTime cutoff = DateTime.Now.AddMinutes(-Math.Max(withinMinutes, 60));
            EnumRecentTasksInFolder(root, list, cutoff, 0);
            return list.OrderByDescending(x => x.LastRunTime).ToList();
        }, new List<RecentScheduledTaskInfo>(), 8000);

        lock (_taskCacheLock)
        {
            _cachedRecentTasks = result;
            _lastTaskCacheUpdate = DateTime.Now;
        }

        return result.Where(t => (DateTime.Now - t.LastRunTime).TotalMinutes <= withinMinutes).ToList();
    }

    private static void EnumRecentTasksInFolder(dynamic folder, List<RecentScheduledTaskInfo> found, DateTime cutoff, int depth)
    {
        if (depth > 5) return;
        try
        {
            dynamic tasks = folder.GetTasks(0);
            int count = tasks.Count;
            for (int i = 1; i <= count; i++)
            {
                try
                {
                    dynamic task = tasks[i];
                    DateTime lastRun = DateTime.MinValue;
                    try { lastRun = (DateTime)task.LastRunTime; } catch { }

                    // 1999年/1899年などの未実行デフォルト値を除外し、cutoff 以降に実行されたタスクのみ抽出
                    if (lastRun.Year < 2020 || lastRun < cutoff || lastRun > DateTime.Now.AddMinutes(5))
                        continue;

                    DateTime nextRun = DateTime.MinValue;
                    try { nextRun = (DateTime)task.NextRunTime; } catch { }
                    int lastResult = 0;
                    try { lastResult = (int)task.LastTaskResult; } catch { }

                    string name = task.Name as string ?? "Task";
                    string path = task.Path as string ?? name;
                    string author = "";
                    var actionStrs = new List<string>();

                    try
                    {
                        dynamic def = task.Definition;
                        try { author = def.RegistrationInfo.Author as string ?? ""; } catch { }
                        dynamic actions = def.Actions;
                        int actCount = actions.Count;
                        for (int a = 1; a <= actCount; a++)
                        {
                            try
                            {
                                dynamic act = actions[a];
                                int actType = (int)act.Type;
                                if (actType == 0) // EXEC
                                {
                                    string exe = act.Path as string ?? "";
                                    string args = "";
                                    try { args = act.Arguments as string ?? ""; } catch { }
                                    actionStrs.Add(string.IsNullOrWhiteSpace(args) ? exe : $"{exe} {args}");
                                }
                                else if (actType == 5) // COM Handler
                                {
                                    string clsid = "";
                                    try { clsid = act.ClassId as string ?? ""; } catch { }
                                    actionStrs.Add($"COM Handler CLSID:{clsid}");
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }

                    string actionCmd = actionStrs.Count > 0
                        ? string.Join(" ; ", actionStrs)
                        : Loc.T("(COM / Internal Handler)", "(COM/内部处理程序)", "(Controlador COM/Interno)", "(COM/内部ハンドラ)");
                    found.Add(new RecentScheduledTaskInfo(path, name, lastRun, nextRun, lastResult, actionCmd, author));
                }
                catch { }
            }

            dynamic subFolders = folder.GetFolders(0);
            int subCount = subFolders.Count;
            for (int i = 1; i <= subCount; i++)
            {
                try { EnumRecentTasksInFolder(subFolders[i], found, cutoff, depth + 1); } catch { }
            }
        }
        catch { }
    }

    /// <summary>
    /// 直近に実行されたスケジュールタスクをスキャンし、ターミナルを出現させうるタスクをプロセス監視一覧へ取り込む。
    /// </summary>
    public int ImportRecentScheduledTasksToProcessList(int withinMinutes = 60)
    {
        var recentTasks = GetRecentlyExecutedScheduledTasks(withinMinutes, useCacheIfFresh: false);
        int imported = 0;

        foreach (var t in recentTasks)
        {
            string exePath = PathHelper.ExtractExecutablePath(t.ActionCommand);
            string exeName = !string.IsNullOrWhiteSpace(exePath)
                ? Path.GetFileNameWithoutExtension(exePath)
                : t.TaskName;

            bool isConsoleTask = IsConsoleOrShellProcess(exeName) ||
                                 t.ActionCommand.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                                 t.ActionCommand.Contains("cmd", StringComparison.OrdinalIgnoreCase) ||
                                 t.ActionCommand.Contains(".bat", StringComparison.OrdinalIgnoreCase) ||
                                 t.ActionCommand.Contains(".cmd", StringComparison.OrdinalIgnoreCase) ||
                                 t.ActionCommand.Contains(".vbs", StringComparison.OrdinalIgnoreCase) ||
                                 t.ActionCommand.Contains(".ps1", StringComparison.OrdinalIgnoreCase) ||
                                 !t.ActionCommand.StartsWith("(COM", StringComparison.OrdinalIgnoreCase);

            if (!isConsoleTask) continue;

            string key = $"sched_recent:{t.TaskPath.ToLowerInvariant()}";
            var (isSigned, signer) = CheckSignature(exePath, exeName);
            string nextLabel = Loc.T("Next", "下次计划", "Próx.", "次回予定");
            string lastLabel = Loc.T("LastRun", "上次运行", "Última ejec.", "最終実行");
            string taskLabel = Loc.T("Task", "任务", "Tarea", "タスク");
            string schedLabel = Loc.T("Task Scheduler", "任务计划程序", "Programador de tareas", "タスクスケジューラ");
            string nextRunStr = t.NextRunTime.Year >= 2025 ? $" / {nextLabel}:{t.NextRunTime:HH:mm:ss}" : "";

            var item = new ProcessAnalysisItem
            {
                ProcessKey = key,
                ProcessName = $"⏰ {exeName} [{taskLabel}:{t.TaskName}]",
                ExecutablePath = string.IsNullOrWhiteSpace(exePath) ? $"TaskScheduler: {t.TaskPath}" : exePath,
                CommandLine = t.ActionCommand,
                ParentProcessName = "Schedule (TaskScheduler)",
                ParentDisplay = $"⏰ {schedLabel} ({t.TaskPath})",
                MatchedScheduledTask = $"{t.TaskPath} ({lastLabel}:{t.LastRunTime:HH:mm:ss}{nextRunStr})",
                IsSigned = isSigned,
                SignerName = signer,
                FirstSeenTime = t.LastRunTime,
                LastSeenTime = t.LastRunTime,
                CurrentPid = 0,
                IsCurrentlyRunning = false,
                TotalSeenCount = 1,
                IsTransientFlash = true,
                IsRareOrNew = true,
                LastDurationMs = 300,
                LaunchTimestamps = new List<DateTime> { t.LastRunTime }
            };

            EvaluateProcessAnomaly(item);
            _processMap[key] = item;
            imported++;
        }

        return imported;
    }

    public List<ProcessAnalysisItem> ScanProcesses()
    {
        Process[] procs;
        try
        {
            procs = Process.GetProcesses();
        }
        catch
        {
            return GetOrderedProcessList();
        }

        var currentPids = new HashSet<int>();
        var activeKeysThisTick = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        DateTime now = DateTime.Now;

        // PID -> プロセス名辞書（親プロセス名解決用）
        var pidNameMap = new Dictionary<int, string>();
        try
        {
            foreach (var p in procs)
            {
                try { pidNameMap[p.Id] = p.ProcessName; } catch { }
            }

            foreach (var p in procs)
            {
            try
            {
                int pid = p.Id;
                if (pid == 0 || pid == 4) continue;

                currentPids.Add(pid);
                string procName = p.ProcessName;
                var identity = NativeSecurity.QueryProcessIdentity(pid);
                string exePath = !string.IsNullOrWhiteSpace(identity?.ImagePath)
                    ? identity!.ImagePath
                    : TryGetExecutablePath(p);
                string cmdLine = identity?.CommandLine ?? "";
                int parentPid = identity?.ParentPid ?? 0;
                pidNameMap.TryGetValue(parentPid, out string? parentName);
                string parentCmd = "";
                if (parentPid > 0 && (parentName ?? "").Equals("svchost", StringComparison.OrdinalIgnoreCase))
                {
                    parentCmd = NativeSecurity.QueryProcessIdentity(parentPid)?.CommandLine ?? "";
                }
                string parentDisplay = parentPid > 0
                    ? NativeSecurity.DescribeParentOrigin(parentPid, parentName ?? "", parentCmd)
                    : "—";

                bool isNewPidSpawn = !_previousActivePids.Contains(pid);
                bool isConsole = IsConsoleOrShellProcess(procName);
                string key = BuildProcessKey(
                    procName,
                    exePath,
                    cmdLine,
                    parentPid,
                    parentName ?? "",
                    isConsole,
                    isDynamicSpawn: _isInitialSnapshotDone && isNewPidSpawn);

                activeKeysThisTick[key] = pid;

                if (!_processMap.TryGetValue(key, out var item))
                {
                    var (isSigned, signer) = CheckSignature(exePath, procName);
                    bool isInitial = !_isInitialSnapshotDone;
                    bool isSelf = CheckIsSelfProcess(pid, procName, exePath);

                    item = new ProcessAnalysisItem
                    {
                        ProcessKey = key,
                        ProcessName = procName,
                        ExecutablePath = string.IsNullOrWhiteSpace(exePath)
                            ? Loc.T("(Protected system area or inaccessible)", "(系统保护区域或无法获取)", "(Área protegida del sistema o inaccesible)", "(システム保護領域または取得不可)")
                            : exePath,
                        CommandLine = cmdLine,
                        ParentPid = parentPid,
                        ParentProcessName = parentName ?? "",
                        ParentCommandLine = parentCmd,
                        ParentDisplay = parentDisplay,
                        IsSigned = isSigned,
                        SignerName = isSelf
                            ? Loc.T("Self Process (Local build / Unsigned)", "自身进程 (本地构建/未签名)", "Proceso propio (Compilación local/Sin firma)", "自己プロセス (ローカルビルド・未署名)")
                            : signer,
                        IsSelfProcess = isSelf,
                        FirstSeenTime = now,
                        LastSeenTime = now,
                        CurrentPid = pid,
                        IsCurrentlyRunning = true,
                        TotalSeenCount = 1,
                        // 初回スナップショット後に初めて登場したプロセスは「普段出てこない（初出）プロセス」としてマーク
                        IsRareOrNew = (!isInitial && !CoreWindowsProcesses.Contains(procName)) || isSelf,
                        IsUserTrusted = isInitial && (isSigned || CoreWindowsProcesses.Contains(procName)) && !isSelf && !isConsole
                    };

                    item.LaunchTimestamps.Add(now);
                    EvaluateProcessAnomaly(item);
                    _processMap[key] = item;
                }
                else
                {
                    item.IsCurrentlyRunning = true;
                    item.CurrentPid = pid;
                    item.LastSeenTime = now;
                    if (parentPid > 0 && item.ParentDisplay == "—")
                    {
                        item.ParentPid = parentPid;
                        item.ParentProcessName = parentName ?? "";
                        item.ParentDisplay = parentDisplay;
                    }
                    if (!string.IsNullOrWhiteSpace(cmdLine) && !string.Equals(item.CommandLine, cmdLine, StringComparison.Ordinal))
                    {
                        item.CommandLine = cmdLine;
                        EvaluateProcessAnomaly(item);
                    }
                    if (CheckIsSelfProcess(pid, procName, exePath) && !item.IsSelfProcess)
                    {
                        item.IsSelfProcess = true;
                        item.SignerName = Loc.T("Self Process (Local build / Unsigned)", "自身进程 (本地构建/未签名)", "Proceso propio (Compilación local/Sin firma)", "自己プロセス (ローカルビルド・未署名)");
                        EvaluateProcessAnomaly(item);
                    }

                    // 新しいPIDでプロセスが再起動・周期起動した場合
                    if (isNewPidSpawn && _isInitialSnapshotDone)
                    {
                        // 同一プロセスのワーカー連続起動（1.5秒未満のバースト）は1回の起動サイクルとしてまとめる
                        var lastLaunch = item.LaunchTimestamps.LastOrDefault();
                        if ((now - lastLaunch).TotalSeconds >= 1.5)
                        {
                            item.TotalSeenCount++;
                            item.LaunchTimestamps.Add(now);
                            if (item.LaunchTimestamps.Count > 25)
                                item.LaunchTimestamps.RemoveAt(0);

                            RecalculatePeriodicity(item);
                            EvaluateProcessAnomaly(item);
                        }
                    }
                }
            }
            catch
            {
                // Ignore individual process access error
            }
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

        // 終了したプロセスのステータス更新（50msスナイパー側でまだ生きているものは維持）
        foreach (var kv in _processMap)
        {
            if (!activeKeysThisTick.ContainsKey(kv.Key) && !_sniperActivePids.ContainsKey(kv.Value.CurrentPid))
            {
                kv.Value.IsCurrentlyRunning = false;
            }
        }

        _previousActivePids = currentPids;
        if (!_isInitialSnapshotDone)
        {
            _isInitialSnapshotDone = true;
            SaveBaselineSafe();
        }

        return GetOrderedProcessList();
    }

    private List<ProcessAnalysisItem> GetOrderedProcessList()
    {
        return _processMap.Values
            .OrderByDescending(x => x.IsSimulated)
            .ThenByDescending(x => x.RiskLevel)
            .ThenByDescending(x => x.IsTransientFlash && !x.IsUserTrusted)
            .ThenByDescending(x => x.IsPeriodic)
            .ThenByDescending(x => x.IsRareOrNew)
            .ThenByDescending(x => x.LastSeenTime)
            .ToList();
    }

    public static void RecalculatePeriodicity(ProcessAnalysisItem item)
    {
        var stamps = item.LaunchTimestamps;
        if (stamps.Count < 3)
        {
            item.IsPeriodic = false;
            return;
        }

        var intervals = new List<double>();
        for (int i = 1; i < stamps.Count; i++)
        {
            double sec = (stamps[i] - stamps[i - 1]).TotalSeconds;
            if (sec >= 1.5 && sec <= 86400) // 1.5秒〜24時間の範囲
                intervals.Add(sec);
        }

        if (intervals.Count < 2)
        {
            item.IsPeriodic = false;
            return;
        }

        // 直近最大10サイクルの間隔で周期性を評価
        var recentIntervals = intervals.TakeLast(10).ToList();
        double mean = recentIntervals.Average();
        double variance = recentIntervals.Sum(x => Math.Pow(x - mean, 2)) / recentIntervals.Count;
        double stdDev = Math.Sqrt(variance);
        double cv = mean > 0 ? stdDev / mean : 1.0;

        // 変動係数 CV <= 0.30 または標準偏差が5秒以内なら「一定周期で現れるプロセス」と判定
        if (cv <= 0.30 || stdDev <= 5.0)
        {
            item.IsPeriodic = true;
            item.AverageIntervalSeconds = Math.Round(mean, 1);
            item.IntervalStdDevSeconds = Math.Round(stdDev, 1);
        }
        else
        {
            item.IsPeriodic = false;
            item.AverageIntervalSeconds = Math.Round(mean, 1);
            item.IntervalStdDevSeconds = Math.Round(stdDev, 1);
        }
    }

    public static bool CheckIsSelfProcess(int pid, string procName, string exePath)
    {
        if (pid > 0 && pid == Environment.ProcessId)
            return true;
        if (!string.IsNullOrWhiteSpace(procName) &&
            procName.Equals("AnzenSecurityWatcher", StringComparison.OrdinalIgnoreCase))
            return true;
        if (!string.IsNullOrWhiteSpace(exePath))
        {
            if (!string.IsNullOrWhiteSpace(Environment.ProcessPath) &&
                exePath.Equals(Environment.ProcessPath, StringComparison.OrdinalIgnoreCase))
                return true;
            if (exePath.EndsWith("\\AnzenSecurityWatcher.exe", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public static void EvaluateProcessAnomaly(ProcessAnalysisItem item)
    {
        if (item.IsSelfProcess)
        {
            item.RiskLevel = item.IsUserTrusted ? RiskLevel.Safe : RiskLevel.Low;
            item.AnomalyReason = Loc.T(
                "🛡️ Self Process (Anzen Security Watcher) [Local build: unsigned & non-standard folder]",
                "🛡️ 生成此日志的自身监控程序 (Anzen Security Watcher) [本地构建：未签名且位于非标准目录]",
                "🛡️ Proceso propio (Anzen Security Watcher) [Compilación local: sin firma]",
                "🛡️ このログを生成した自分自身のプログラム (Anzen Security Watcher) です [ローカルビルドのため未署名・標準外フォルダ配置]");
            return;
        }

        if (item.IsUserTrusted)
        {
            item.RiskLevel = RiskLevel.Safe;
            item.Confidence = ConfidenceLevel.High;
            item.AnomalyReason = Loc.T(
                "User trusted (Registered in baseline)",
                "用户已信任 (已加入基线)",
                "Confiado por el usuario (En línea base)",
                "ユーザー承認済み (ベースライン登録済み)");
            return;
        }

        // ファイル現存性の動的チェック（非稼働プロセスの場合）
        if (!item.IsCurrentlyRunning && !string.IsNullOrWhiteSpace(item.ExecutablePath) &&
            !item.ExecutablePath.StartsWith("(") && !item.ExecutablePath.StartsWith("TaskScheduler:"))
        {
            try { item.IsFilePresent = File.Exists(item.ExecutablePath); } catch { item.IsFilePresent = false; }
        }

        // 過去の痕跡（実行ファイル削除済み・プロセス非稼働）の識別
        if (!item.IsCurrentlyRunning && !item.IsFilePresent)
        {
            string chainCheck = $"{item.CommandLine} {item.ParentCommandLine} {item.ProcessTreeDetail} {item.ProcessKey} {item.ExecutablePath}";
            if (AiAgentChainRegex.IsMatch(chainCheck))
            {
                item.StoryKey = "STORY:AI_AGENT_HERMES";
                item.StoryTitle = "Hermes Agent / uv-managed Python launcher chain (Historical)";
                item.RiskLevel = RiskLevel.Safe;
                item.Confidence = ConfidenceLevel.High;
                item.AnomalyReason = Loc.T(
                    "⚪ Historical Hermes setup/build trace (Executable deleted, process inactive. No active threat)",
                    "⚪ 历史 Hermes 安装/构建痕迹 (可执行文件已删除，无活跃进程，非当前威胁)",
                    "⚪ Historial de Hermes (Archivo eliminado, proceso inactivo. Sin amenaza)",
                    "⚪ 過去のHermesインストール/ビルド履歴 (ファイル削除済・プロセス非稼働・現在脅威なし)");
                return;
            }

            item.RiskLevel = RiskLevel.Low;
            item.Confidence = ConfidenceLevel.Medium;
            item.AnomalyReason = Loc.T(
                "⚪ Historical execution trace (Executable file deleted, process not running)",
                "⚪ 历史执行记录 (可执行文件已删除，无运行中进程)",
                "⚪ Registro de ejecución histórico (Archivo eliminado, proceso inactivo)",
                "⚪ 過去の実行履歴 (実行ファイルは既に削除済・非稼働)");
            return;
        }

        // 要件 #12: BadUSB 攻撃シーケンスの検出 (新規HIDキーボード接続直後 0〜15秒以内のシェル・コマンド起動)
        if (PrivacyHardwareMonitorService.IsRecentBadUsbSequence(item.ProcessName, item.DetectedAt, out var badUsbDev))
        {
            item.StoryKey = "STORY:BADUSB_ATTACK";
            item.StoryTitle = "BadUSB Keystroke Injection Attack Sequence";
            item.RiskLevel = RiskLevel.Critical;
            item.Confidence = ConfidenceLevel.High;
            item.AnomalyReason = Loc.T(
                $"🚨 BadUSB Attack Sequence: Process spawned within 15s after new USB HID keyboard connection ({badUsbDev})",
                $"🚨 BadUSB 攻击序列：新 USB HID 键盘接入后 15 秒内启动了命令行/脚本 ({badUsbDev})",
                $"🚨 Secuencia de ataque BadUSB: Proceso iniciado dentro de 15s de conectar nuevo USB HID ({badUsbDev})",
                $"🚨 BadUSB攻撃シーケンス検知: 新規USB HIDキーボード接続後15秒以内にシェル/スクリプトが起動 ({badUsbDev})");
            return;
        }

        // 要件 #6: Flash Terminal は単体でなく Process Tree で判定する (Office 更新等の正常活動を 1 イベントに統合)
        bool isOfficeUpdateChain =
            (item.ProcessTreeDetail.Contains("OfficeClickToRun", StringComparison.OrdinalIgnoreCase) ||
             item.ProcessTreeDetail.Contains("OfficeC2RClient", StringComparison.OrdinalIgnoreCase) ||
             item.ParentDisplay.Contains("Office", StringComparison.OrdinalIgnoreCase) ||
             item.MatchedScheduledTask.Contains("Office Automatic Updates", StringComparison.OrdinalIgnoreCase)) &&
            (item.ProcessName.Equals("schtasks", StringComparison.OrdinalIgnoreCase) ||
             item.ProcessName.Equals("conhost", StringComparison.OrdinalIgnoreCase) ||
             item.ProcessName.Contains("Office", StringComparison.OrdinalIgnoreCase));

        if (isOfficeUpdateChain)
        {
            item.StoryKey = "STORY:OFFICE_UPDATE";
            item.StoryTitle = "Microsoft Office Update Activity";
            item.RiskLevel = RiskLevel.Safe;
            item.Confidence = ConfidenceLevel.High;
            string durText = item.LastDurationMs > 0 ? $" (Duration: {item.LastDurationMs}ms)" : "";
            item.AnomalyReason = Loc.T(
                $"🟢 Microsoft Office Update Activity{durText}: Legitimate background update task under Office Click-to-Run tree",
                $"🟢 Microsoft Office 更新活动{durText}：Office 即点即用更新树下的正常后台子任务",
                $"🟢 Actividad de actualización de Office{durText}: Subtarea legítima bajo el árbol de Office Click-to-Run",
                $"🟢 Microsoft Office 更新アクティビティ{durText}: Office Click-to-Run ツリー配下の正常な更新サブタスク");
            return;
        }

        var reasons = new List<string>();
        var risk = RiskLevel.Safe;
        var confidence = ConfidenceLevel.Medium;

        string lowerPath = item.ExecutablePath.ToLowerInvariant();
        bool inSuspiciousFolder =
            lowerPath.Contains("\\appdata\\local\\temp\\") ||
            lowerPath.Contains("\\downloads\\") ||
            lowerPath.Contains("\\users\\public\\") ||
            lowerPath.Contains("\\appdata\\roaming\\");

        bool inStandardSystemFolder =
            lowerPath.StartsWith("c:\\windows\\") ||
            lowerPath.StartsWith("c:\\program files\\") ||
            lowerPath.StartsWith("c:\\program files (x86)\\");

        // 0. 瞬間ターミナル / 短命プロセス (0.3秒フラッシュ等) の判定
        if (item.IsTransientFlash)
        {
            // 要件 #7: スケジュールタスクと強い相関 (±5s) があり、正規タスクの場合は警告レベルを下げる
            if (item.TaskCorrelation == TaskCorrelationStrength.Strong && !inSuspiciousFolder)
            {
                risk = RiskLevel.Safe;
                confidence = ConfidenceLevel.High;
                reasons.Add(Loc.T(
                    "Strongly correlated with scheduled task (lowered to safe)",
                    "与计划任务强相关（降级为安全）",
                    "Fuertemente correlacionado con tarea programada (seguro)",
                    "スケジュールタスクと強い相関 (安全と判定)"));
            }
            else if (item.HadVisibleConsoleWindow)
            {
                if (risk < RiskLevel.Caution) risk = RiskLevel.Caution;
                string dur = item.LastDurationMs > 0
                    ? Loc.T($" (alive {item.LastDurationMs / 1000.0:F2}s)", $" (存活 {item.LastDurationMs / 1000.0:F2}秒)", $" (vivo {item.LastDurationMs / 1000.0:F2}s)", $" (生存 {item.LastDurationMs / 1000.0:F2}秒)")
                    : "";
                string winTitle = !string.IsNullOrEmpty(item.ConsoleWindowTitle)
                    ? Loc.T($" [Title: {item.ConsoleWindowTitle}]", $" [窗口标题: {item.ConsoleWindowTitle}]", $" [Título: {item.ConsoleWindowTitle}]", $" [窓タイトル: {item.ConsoleWindowTitle}]")
                    : "";
                reasons.Add(Loc.T(
                    $"💥 Flash terminal/console window appeared and vanished{dur}{winTitle}",
                    $"💥 屏幕上瞬间闪现终端/控制台窗口后消失{dur}{winTitle}",
                    $"💥 Ventana de terminal/consola apareció fugazmente{dur}{winTitle}",
                    $"💥 画面上に一瞬ターミナル/コンソール窓が出現して消滅{dur}{winTitle}"));
            }
            else
            {
                if (risk < RiskLevel.Informational) risk = RiskLevel.Informational;
                string dur = item.LastDurationMs > 0
                    ? Loc.T($" (alive {item.LastDurationMs / 1000.0:F2}s)", $" (存活 {item.LastDurationMs / 1000.0:F2}秒)", $" (vivo {item.LastDurationMs / 1000.0:F2}s)", $" (生存 {item.LastDurationMs / 1000.0:F2}秒)")
                    : "";
                reasons.Add(Loc.T(
                    $"⚡ Short-lived process/command executed briefly and exited{dur}",
                    $"⚡ 短命进程/命令短暂执行后退出{dur}",
                    $"⚡ Proceso/comando de corta duración ejecutado brevemente{dur}",
                    $"⚡ 短命プロセス/コマンドが一瞬だけ実行され終了{dur}"));
            }

            if (!string.IsNullOrEmpty(item.ParentDisplay) && item.ParentDisplay != "—")
            {
                reasons.Add(Loc.T(
                    $"Parent: {item.ParentDisplay}",
                    $"启动源(父进程): {item.ParentDisplay}",
                    $"Padre: {item.ParentDisplay}",
                    $"起動元(親): {item.ParentDisplay}"));
            }

            if (!string.IsNullOrEmpty(item.MatchedScheduledTask))
            {
                reasons.Add(Loc.T(
                    $"🎯 Matched Scheduled Task: {item.MatchedScheduledTask}",
                    $"🎯 关联计划任务: {item.MatchedScheduledTask}",
                    $"🎯 Tarea programada: {item.MatchedScheduledTask}",
                    $"🎯 該当スケジュールタスク: {item.MatchedScheduledTask}"));
            }
        }

        // 1. 周期的出現の判定
        if (item.IsPeriodic)
        {
            if (risk < RiskLevel.Caution) risk = RiskLevel.Caution;
            reasons.Add(Loc.T(
                $"⏱️ Repeatedly launched at ~{item.AverageIntervalSeconds:F1}s intervals (±{item.IntervalStdDevSeconds:F1}s, {item.TotalSeenCount} times)",
                $"⏱️ 按固定周期 ({item.AverageIntervalSeconds:F1}秒间隔 ±{item.IntervalStdDevSeconds:F1}秒) 重复出现 (共{item.TotalSeenCount}次)",
                $"⏱️ Aparición periódica cada ~{item.AverageIntervalSeconds:F1}s (±{item.IntervalStdDevSeconds:F1}s, {item.TotalSeenCount} veces)",
                $"⏱️ 一定周期 ({item.AverageIntervalSeconds:F1}秒間隔 ±{item.IntervalStdDevSeconds:F1}秒) で繰り返し出現 (計{item.TotalSeenCount}回)"));
            if (!item.IsSigned)
            {
                if (risk < RiskLevel.High) risk = RiskLevel.High;
                confidence = ConfidenceLevel.Medium;
                reasons.Add(Loc.T(
                    "Unsigned periodic process (Suspected beacon / suspicious task)",
                    "无数字签名的周期性进程 (疑似信标/可疑任务)",
                    "Proceso periódico sin firma digital (Sospecha de beacon/tarea)",
                    "デジタル署名なしの周期的プロセス (ビーコン/不審タスクの疑い)"));
            }
            else if (item.IsTransientFlash)
            {
                if (risk < RiskLevel.Caution) risk = RiskLevel.Caution;
                reasons.Add(Loc.T(
                    "Candidate cause of periodic flashing terminal / short-lived process",
                    "定期启动终端/短命进程的候选源头",
                    "Candidato causante de terminal fugaz periódica",
                    "定期的にターミナル/短命プロセスを起動している元凶候補"));
            }
        }

        // 2. 普段出てこない（初出・レア）プロセスの判定
        if (item.IsRareOrNew && !item.IsTransientFlash)
        {
            if (risk < RiskLevel.Informational) risk = RiskLevel.Informational;
            reasons.Add(Loc.T(
                $"Newly seen or rare process since monitoring started (Count: {item.TotalSeenCount})",
                $"监控开始后首次出现或罕见的进程 (出现次数:{item.TotalSeenCount}次)",
                $"Proceso nuevo o poco frecuente desde el inicio del monitoreo (Veces: {item.TotalSeenCount})",
                $"監視開始後に初出・出現頻度が低いプロセス (出現回数:{item.TotalSeenCount}回)"));
        }

        // 3. 実行パスとデジタル署名の複合判定 (要件 #2: 未署名単体で Medium/High にしない)
        bool isInstallerLike = item.ProcessName.Contains("setup", StringComparison.OrdinalIgnoreCase) ||
                               item.ProcessName.Contains("installer", StringComparison.OrdinalIgnoreCase) ||
                               item.ProcessName.Contains("update", StringComparison.OrdinalIgnoreCase) ||
                               item.ExecutablePath.Contains("setup", StringComparison.OrdinalIgnoreCase) ||
                               item.ExecutablePath.Contains("installer", StringComparison.OrdinalIgnoreCase);

        // 祖先チェーンにユーザー対話シェル (explorer) またはブラウザが含まれているか判定
        string treeAll = $"{item.ParentProcessName} {item.GrandparentProcessName} {item.ProcessTreeDetail}".ToLowerInvariant();
        bool isUserInteractiveLaunch = treeAll.Contains("explorer") ||
                                       treeAll.Contains("chrome") ||
                                       treeAll.Contains("msedge") ||
                                       treeAll.Contains("firefox") ||
                                       treeAll.Contains("brave") ||
                                       treeAll.Contains("opera");

        bool isBackgroundTaskLaunch = treeAll.Contains("svchost") ||
                                      treeAll.Contains("taskhost") ||
                                      treeAll.Contains("schtasks");

        bool isAutostartLaunch = treeAll.Contains("runonce") ||
                                 item.ParentProcessName.Equals("runonce", StringComparison.OrdinalIgnoreCase) ||
                                 item.ParentDisplay.Contains("RunOnce", StringComparison.OrdinalIgnoreCase) ||
                                 item.ParentDisplay.Contains("Run6432", StringComparison.OrdinalIgnoreCase);

        if (inSuspiciousFolder)
        {
            if (!item.IsSigned)
            {
                if (isInstallerLike && isUserInteractiveLaunch)
                {
                    // ユーザーがエクスプローラーやブラウザから起動したインストーラー/セットアップ
                    // 未署名でもHIGH誤検知にせず、注意 (Caution) に留めてStory化する
                    risk = RiskLevel.Caution;
                    confidence = ConfidenceLevel.High;
                    item.StoryKey = "STORY:USER_SETUP";
                    item.StoryTitle = "User-initiated Installer / Setup Execution";
                    reasons.Add(Loc.T(
                        "User-launched installer from Downloads/Temp (Parent: Explorer / Browser verified)",
                        "用户从 Downloads/Temp 运行的安装程序 (已通过 Explorer/浏览器 祖先链验证)",
                        "Instalador iniciado por el usuario desde Downloads/Temp (Verificado por Explorer/Navegador)",
                        "ユーザーがDownloads/Tempから実行したインストーラー (Explorer/ブラウザの祖先ツリー検証済)"));
                }
                else if (isAutostartLaunch)
                {
                    // runonce / Run6432 による 32ビット HKLM Run 自動起動経由
                    risk = RiskLevel.Caution;
                    confidence = ConfidenceLevel.Medium;
                    item.StoryKey = "STORY:AUTOSTART_RUNONCE";
                    item.StoryTitle = "Windows RunOnce / 32-bit Autostart (Run6432)";
                    reasons.Add(Loc.T(
                        "Spawned via Windows RunOnce / Run6432 autostart launcher (32-bit registry Run)",
                        "通过 Windows RunOnce / Run6432 自动启动启动器运行 (32位 Run 注册表)",
                        "Iniciado mediante lanzador RunOnce / Run6432 de Windows",
                        "Windows RunOnce / Run6432 自動起動ランチャー経由で実行 (32bit Runレジストリ)"));
                }
                else
                {
                    // Unsigned + Temp/AppData
                    risk = RiskLevel.High;
                    confidence = ConfidenceLevel.High;
                    reasons.Add(Loc.T(
                        "Unsigned executable running from user Temp/Downloads folder",
                        "从 Temp/Downloads 等用户目录运行未签名程序",
                        "Ejecutable sin firma ejecutándose desde carpeta Temp/Downloads",
                        "Temp/Downloads等のユーザー領域から未署名プログラムが実行"));
                }
            }
            else
            {
                if (risk < RiskLevel.Informational) risk = RiskLevel.Informational;
                reasons.Add(Loc.T(
                    "Executed from user folder (Temp/Downloads/AppData)",
                    "从用户目录 (Temp/Downloads/AppData) 运行",
                    "Ejecutado desde carpeta de usuario (Temp/Downloads/AppData)",
                    "ユーザー領域(Temp/Downloads/AppData)からの実行"));
            }
        }
        else if (isAutostartLaunch)
        {
            // runonce / Run6432 による標準フォルダ外または通常起動
            if (risk < RiskLevel.Informational) risk = RiskLevel.Informational;
            item.StoryKey = "STORY:AUTOSTART_RUNONCE";
            item.StoryTitle = "Windows RunOnce / 32-bit Autostart (Run6432)";
            reasons.Add(Loc.T(
                "Spawned via Windows RunOnce / Run6432 autostart launcher (32-bit registry Run)",
                "通过 Windows RunOnce / Run6432 自动启动启动器运行 (32位 Run 注册表)",
                "Iniciado mediante lanzador RunOnce / Run6432 de Windows",
                "Windows RunOnce / Run6432 自動起動ランチャー経由で実行 (32bit Runレジストリ)"));
        }
        else if (!item.IsSigned && !inStandardSystemFolder && !item.ExecutablePath.StartsWith("(") && !item.ExecutablePath.StartsWith("TaskScheduler:"))
        {
            // Unsigned + Program Files 外 + 新規出現 → Caution (Medium相当)
            if (risk < RiskLevel.Caution) risk = RiskLevel.Caution;
            confidence = ConfidenceLevel.Low;
            reasons.Add(Loc.T(
                "Unsigned executable launched from non-standard folder",
                "从非标准目录启动无数字签名的可执行文件",
                "Ejecutable sin firma iniciado desde carpeta no estándar",
                "標準外のフォルダからデジタル署名のない実行ファイルが起動"));
            item.IsRareOrNew = true;
        }

        // 4. コマンドライン引数の難読化・LOLBins 悪用解析 (#12)
        if (!string.IsNullOrWhiteSpace(item.CommandLine))
        {
            var cmdRes = CommandLineAnalyzer.Analyze(item.CommandLine, item.ProcessName, item.ParentProcessName);
            if (cmdRes.IsSuspicious)
            {
                item.HasSuspiciousCommandLine = true;
                if (cmdRes.Risk > risk) risk = cmdRes.Risk;
                reasons.Add(Loc.T(
                    $"Command line alert: {cmdRes.ReasonText}",
                    $"命令行检测: {cmdRes.ReasonText}",
                    $"Alerta de línea de comandos: {cmdRes.ReasonText}",
                    $"コマンドライン検知: {cmdRes.ReasonText}"));
            }
            else
            {
                item.HasSuspiciousCommandLine = false;
            }
        }

        // 5. AIエージェント/開発ツール系（Hermes / uv管理Python 等）の起動チェーン識別
        string chainText = $"{item.CommandLine} {item.ParentCommandLine} {item.ProcessTreeDetail}";
        if (AiAgentChainRegex.IsMatch(chainText))
        {
            item.StoryKey = "STORY:AI_AGENT_HERMES";
            item.StoryTitle = "Hermes Agent / uv-managed Python launcher chain";

            if (isUserInteractiveLaunch)
            {
                // ユーザー主導の起動であれば、未署名Temp起動等によるHIGHをCautionまたはInformationalへ引き下げて誤検知防止
                if (risk > RiskLevel.Caution) risk = RiskLevel.Caution;
                reasons.Add(Loc.T(
                    "🤖 Hermes / AI agent tool launched by user (Explorer / Browser / Terminal). Normal developer activity",
                    "🤖 用户通过 Explorer、浏览器或终端启动的 Hermes / AI 代理工具。属于正常操作行为",
                    "🤖 Herramienta Hermes / agente IA iniciada por el usuario (Explorer / Navegador / Terminal).",
                    "🤖 ユーザーによって起動された Hermes / AIエージェント開発ツール (Explorer/ブラウザ/ターミナル由来)。正常な操作アクティビティです"));
            }
            else if (isBackgroundTaskLaunch)
            {
                // スケジュールタスクやバックグラウンドサービスからの起動（アンインストール後の残存挙動候補）
                if (risk < RiskLevel.Caution) risk = RiskLevel.Caution;
                reasons.Add(Loc.T(
                    "⚠️ Hermes residue / background launch detected via Scheduled Task or svchost. Verify post-uninstall leftovers",
                    "⚠️ 检测到通过计划任务或 svchost 启动的 Hermes 后台残存进程。请排查卸载残留",
                    "⚠️ Actividad de Hermes en segundo plano detectada vía tareas programadas. Verifique residuos post-desinstalación.",
                    "⚠️ スケジュールタスクまたはsvchost経由のHermesバックグラウンド起動を検知。アンインストール後の残存タスク・常駐設定の確認が必要です"));
            }
            else
            {
                reasons.Add(Loc.T(
                    "🤖 AI agent tool chain (Hermes / uv Python launcher). Check who started the parent shell in the process tree",
                    "🤖 AI 代理工具链 (Hermes / uv Python 启动器)。请在进程树中确认启动父 Shell 的源头",
                    "🤖 Cadena de herramientas de agente IA (Hermes / uv). Revise el árbol de procesos para ver quién inició el shell",
                    "🤖 AIエージェント系ツールの起動チェーン (Hermes / uv管理Python)。プロセスツリーで親シェルの起動元を確認してください"));
            }
        }

        // 6. 個人導入ツール（Wox, AutoHotkey 等）およびリモート管理ツール（TeamViewer 等）の社内規程・シャドーIT留意判定
        string lowerProc = item.ProcessName.ToLowerInvariant();
        bool isRemoteAdminTool =
            lowerProc.Contains("teamviewer") || lowerProc.Contains("anydesk") ||
            lowerProc.Contains("screenconnect") || lowerProc.Contains("rustdesk") ||
            lowerProc.Contains("ultraviewer") || lowerProc.Contains("logmein");

        bool isPersonalUtilityTool =
            lowerProc.Contains("wox") || lowerProc.Contains("powertoys") ||
            lowerProc.Contains("everything") || lowerProc.Contains("autohotkey") ||
            lowerProc.Contains("keypirinha") || lowerProc.Contains("flow.launcher");

        if (isRemoteAdminTool)
        {
            if (risk < RiskLevel.Caution) risk = RiskLevel.Caution;
            reasons.Add(Loc.T(
                "⚠️ Remote management tool detected (If using a corporate PC, verify internal security policy / IT approval)",
                "⚠️ 检测到远程控制管理工具 (如系公司电脑，请确认是否符合企业安全规程或已向IT部门报备)",
                "⚠️ Herramienta de acceso remoto detectada (En PC corporativo, verifique directivas internas de TI)",
                "⚠️ リモート管理ツールを検知 (社用PCでご利用の場合、社内情報セキュリティ規程・情シス部門の利用許可をご確認ください)"));
        }
        else if (isPersonalUtilityTool)
        {
            if (risk < RiskLevel.Informational) risk = RiskLevel.Informational;
            reasons.Add(Loc.T(
                "💡 Personal utility / productivity launcher (If using a corporate PC, check IT department policies)",
                "💡 个人效能/快捷启动工具 (如系公司电脑，请确认是否符合信息安全规程)",
                "💡 Herramienta de productividad personal (En PC corporativo, consulte directivas internas)",
                "💡 個人導入ユーティリティ/ランチャー (社用PCの場合は社内規程・利用許可をご確認ください)"));
        }

        // 現在進行中の脅威と過去履歴の分離:
        // プロセスが稼働しておらず、かつ過去の履歴（24時間以上前）の場合は、
        // 過去ログとして扱い、現在進行中の Critical / High 警戒アラートにはしない（最大 Caution）
        if (!item.IsCurrentlyRunning && item.IsHistoricalOnly && risk > RiskLevel.Caution)
        {
            risk = RiskLevel.Caution;
            reasons.Add(Loc.T(
                "Historical record (Process not currently active)",
                "历史记录 (当前进程未运行)",
                "Registro histórico (El proceso no está activo actualmente)",
                "過去の履歴レコード (現在プロセスは非稼働)"));
        }

        if (reasons.Count == 0)
        {
            item.RiskLevel = RiskLevel.Safe;
            item.Confidence = ConfidenceLevel.High;
            item.AnomalyReason = Loc.T(
                "Normal system / application process",
                "正常的系统/应用程序进程",
                "Proceso normal del sistema / aplicación",
                "通常のシステム/アプリケーションプロセス");
        }
        else
        {
            item.RiskLevel = risk;
            item.Confidence = confidence;
            item.AnomalyReason = string.Join(" / ", reasons);
        }
    }

    public void MarkAsTrusted(ProcessAnalysisItem item)
    {
        item.IsUserTrusted = true;
        item.IsRareOrNew = false;
        EvaluateProcessAnomaly(item);
        SaveBaselineSafe();
    }

    /// <summary>
    /// 動作確認用：0.3秒の瞬間ターミナル（フラッシュコンソール）、周期的プロセス、未知プロセスのサンプル検知エントリを注入する
    /// </summary>
    public void InjectSimulatedAnomalies()
    {
        DateTime now = DateTime.Now;

        var flashTerminalSample = new ProcessAnalysisItem
        {
            ProcessKey = "sim:transient_flash_powershell.exe",
            ProcessName = Loc.T(
                "powershell [SIMULATION: 0.3s Flash Terminal]",
                "powershell [模拟测试: 0.3秒瞬时终端]",
                "powershell [SIMULACIÓN: Terminal Fugaz 0.3s]",
                "powershell [テスト模擬: 0.3秒瞬間ターミナル]"),
            ExecutablePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine = @"powershell.exe -ExecutionPolicy Bypass -File ""C:\ProgramData\VendorUpdater\check_update_tick.ps1"" --silent-check",
            ParentPid = 1480,
            ParentProcessName = "svchost",
            ParentDisplay = Loc.T(
                "⏰ Task Scheduler (svchost/Schedule, PID:1480)",
                "⏰ 任务计划程序 (svchost/Schedule, PID:1480)",
                "⏰ Programador de tareas (svchost/Schedule, PID:1480)",
                "⏰ タスクスケジューラ (svchost/Schedule, PID:1480)"),
            MatchedScheduledTask = Loc.T(
                @"\VendorUpdater\PeriodicBackgroundCheck (LastRun:" + now.ToString("HH:mm:ss") + " / 5m cycle)",
                @"\VendorUpdater\PeriodicBackgroundCheck (上次运行:" + now.ToString("HH:mm:ss") + " / 5分钟周期)",
                @"\VendorUpdater\PeriodicBackgroundCheck (Última ejec.:" + now.ToString("HH:mm:ss") + " / ciclo 5m)",
                @"\VendorUpdater\PeriodicBackgroundCheck (最終実行:" + now.ToString("HH:mm:ss") + " / 5分周期)"),
            ConsoleWindowTitle = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            IsSigned = true,
            SignerName = "Microsoft Windows",
            IsSimulated = true,
            FirstSeenTime = now.AddMinutes(-15),
            LastSeenTime = now,
            CurrentPid = 88320,
            IsCurrentlyRunning = false,
            TotalSeenCount = 4,
            IsRareOrNew = true,
            IsTransientFlash = true,
            HadVisibleConsoleWindow = true,
            LastDurationMs = 280,
            IsUserTrusted = false,
            LaunchTimestamps = new List<DateTime>
            {
                now.AddSeconds(-900),
                now.AddSeconds(-600),
                now.AddSeconds(-300),
                now
            }
        };
        RecalculatePeriodicity(flashTerminalSample);
        EvaluateProcessAnomaly(flashTerminalSample);
        _processMap[flashTerminalSample.ProcessKey] = flashTerminalSample;

        var periodicSample = new ProcessAnalysisItem
        {
            ProcessKey = "sim:periodic_beacon_updater.exe",
            ProcessName = Loc.T(
                "updater_beacon_task [SIMULATION]",
                "updater_beacon_task [模拟测试]",
                "updater_beacon_task [SIMULACIÓN]",
                "updater_beacon_task [テスト模擬]"),
            ExecutablePath = @"C:\Users\Public\Tasks\updater_beacon_task.exe",
            CommandLine = @"C:\Users\Public\Tasks\updater_beacon_task.exe --heartbeat",
            ParentPid = 4120,
            ParentProcessName = "explorer",
            ParentDisplay = Loc.T(
                "🖥️ Explorer / User Launch (explorer, PID:4120)",
                "🖥️ 资源管理器/用户启动 (explorer, PID:4120)",
                "🖥️ Explorador / Usuario (explorer, PID:4120)",
                "🖥️ エクスプローラー/ユーザー起動 (explorer, PID:4120)"),
            IsSigned = false,
            SignerName = Loc.T("Unsigned", "未签名", "Sin firma", "署名なし"),
            IsSimulated = true,
            FirstSeenTime = now.AddMinutes(-3),
            LastSeenTime = now,
            CurrentPid = 99412,
            IsCurrentlyRunning = true,
            TotalSeenCount = 5,
            IsRareOrNew = true,
            IsUserTrusted = false,
            LaunchTimestamps = new List<DateTime>
            {
                now.AddSeconds(-180),
                now.AddSeconds(-135),
                now.AddSeconds(-90),
                now.AddSeconds(-45),
                now
            }
        };
        RecalculatePeriodicity(periodicSample);
        EvaluateProcessAnomaly(periodicSample);
        _processMap[periodicSample.ProcessKey] = periodicSample;

        var rareSample = new ProcessAnalysisItem
        {
            ProcessKey = "sim:unknown_temp_helper.exe",
            ProcessName = Loc.T(
                "sys_diag_helper [SIMULATION]",
                "sys_diag_helper [模拟测试]",
                "sys_diag_helper [SIMULACIÓN]",
                "sys_diag_helper [テスト模擬]"),
            ExecutablePath = @"C:\Users\User\AppData\Local\Temp\sys_diag_helper.exe",
            CommandLine = @"C:\Users\User\AppData\Local\Temp\sys_diag_helper.exe /collect",
            ParentPid = 6200,
            ParentProcessName = "cmd",
            ParentDisplay = "cmd (PID:6200)",
            IsSigned = false,
            SignerName = Loc.T("Unsigned", "未签名", "Sin firma", "署名なし"),
            IsSimulated = true,
            FirstSeenTime = now.AddSeconds(-15),
            LastSeenTime = now,
            CurrentPid = 99488,
            IsCurrentlyRunning = true,
            TotalSeenCount = 1,
            IsRareOrNew = true,
            IsUserTrusted = false,
            LaunchTimestamps = new List<DateTime> { now }
        };
        EvaluateProcessAnomaly(rareSample);
        _processMap[rareSample.ProcessKey] = rareSample;
    }

    public void RemoveSimulatedAnomalies()
    {
        var simKeys = _processMap
            .Where(kv => kv.Key.StartsWith("sim:", StringComparison.OrdinalIgnoreCase) || kv.Value.IsSimulated)
            .Select(kv => kv.Key)
            .ToList();
        foreach (var k in simKeys)
        {
            _processMap.TryRemove(k, out _);
        }
    }

    private static string TryGetExecutablePath(Process p)
    {
        try
        {
            return p.MainModule?.FileName ?? "";
        }
        catch
        {
            return "";
        }
    }

    private (bool IsSigned, string Signer) CheckSignature(string filePath, string procName)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            if (CoreWindowsProcesses.Contains(procName) || IsConsoleOrShellProcess(procName))
                return (true, Loc.T("Microsoft Windows (OS Standard / Protected)", "Microsoft Windows (OS 标准/受保护进程)", "Microsoft Windows (Estándar / Protegido)", "Microsoft Windows (OS標準/保護プロセス)"));
            return (true, Loc.T("OS Protected Process", "OS 受保护进程", "Proceso protegido del SO", "OS保護プロセス (権限外)"));
        }

        var ext = SignatureHelper.CheckExtended(filePath);
        return (ext.IsSigned, ext.Signer);
    }

    private void LoadBaseline()
    {
        try
        {
            if (!File.Exists(_baselineFilePath)) return;
            string json = File.ReadAllText(_baselineFilePath);
            var records = JsonSerializer.Deserialize<List<ProcessBaselineRecord>>(json);
            if (records == null) return;

            foreach (var r in records)
            {
                if (r.ProcessKey.StartsWith("sim:", StringComparison.OrdinalIgnoreCase) ||
                    r.ProcessName.Contains("テスト模擬", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                bool isSelf = CheckIsSelfProcess(0, r.ProcessName, r.ExecutablePath);
                bool fileExists = true;
                if (!string.IsNullOrWhiteSpace(r.ExecutablePath) &&
                    !r.ExecutablePath.StartsWith("(") &&
                    !r.ExecutablePath.StartsWith("TaskScheduler:"))
                {
                    try { fileExists = File.Exists(r.ExecutablePath); } catch { fileExists = false; }
                }

                var item = new ProcessAnalysisItem
                {
                    ProcessKey = r.ProcessKey,
                    ProcessName = r.ProcessName,
                    ExecutablePath = r.ExecutablePath,
                    CommandLine = r.CommandLine ?? "",
                    ParentDisplay = string.IsNullOrWhiteSpace(r.ParentDisplay) ? "—" : r.ParentDisplay,
                    GrandparentPid = r.GrandparentPid,
                    GrandparentProcessName = r.GrandparentProcessName ?? "",
                    ProcessTreeSummary = r.ProcessTreeSummary ?? "",
                    ProcessTreeDetail = r.ProcessTreeDetail ?? "",
                    IsSigned = r.IsSigned,
                    SignerName = isSelf
                        ? Loc.T("Self Process (Local build / Unsigned)", "自身进程 (本地构建/未签名)", "Proceso propio (Compilación local/Sin firma)", "自己プロセス (ローカルビルド・未署名)")
                        : r.SignerName,
                    IsSelfProcess = isSelf,
                    IsRareOrNew = isSelf || r.IsTransientFlash,
                    IsTransientFlash = r.IsTransientFlash,
                    HadVisibleConsoleWindow = r.HadVisibleConsoleWindow,
                    LastDurationMs = r.LastDurationMs,
                    MatchedScheduledTask = r.MatchedScheduledTask ?? "",
                    FirstSeenTime = r.FirstSeenTime,
                    LastSeenTime = r.LastSeenTime,
                    TotalSeenCount = r.TotalSeenCount,
                    IsUserTrusted = r.IsUserTrusted,
                    IsCurrentlyRunning = false,
                    IsFilePresent = fileExists,
                    LaunchTimestamps = r.RecentLaunchTimestamps ?? new List<DateTime>()
                };
                RecalculatePeriodicity(item);
                EvaluateProcessAnomaly(item);
                _processMap[item.ProcessKey] = item;
            }
        }
        catch
        {
            // Ignore corrupt baseline
        }
    }

    public void SaveBaselineSafe()
    {
        try
        {
            var records = _processMap.Values
                .Where(x => !x.ProcessKey.StartsWith("sim:") && !x.IsSimulated)
                .Select(x => new ProcessBaselineRecord
                {
                    ProcessKey = x.ProcessKey,
                    ProcessName = x.ProcessName,
                    ExecutablePath = x.ExecutablePath,
                    CommandLine = x.CommandLine,
                    ParentDisplay = x.ParentDisplay,
                    GrandparentPid = x.GrandparentPid,
                    GrandparentProcessName = x.GrandparentProcessName,
                    ProcessTreeSummary = x.ProcessTreeSummary,
                    ProcessTreeDetail = x.ProcessTreeDetail,
                    IsSigned = x.IsSigned,
                    SignerName = x.SignerName,
                    FirstSeenTime = x.FirstSeenTime,
                    LastSeenTime = x.LastSeenTime,
                    TotalSeenCount = x.TotalSeenCount,
                    IsUserTrusted = x.IsUserTrusted,
                    IsTransientFlash = x.IsTransientFlash,
                    HadVisibleConsoleWindow = x.HadVisibleConsoleWindow,
                    LastDurationMs = x.LastDurationMs,
                    MatchedScheduledTask = x.MatchedScheduledTask,
                    RecentLaunchTimestamps = x.LaunchTimestamps.TakeLast(15).ToList()
                })
                .ToList();

            string json = JsonSerializer.Serialize(records, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_baselineFilePath, json);
        }
        catch
        {
            // Ignore write errors
        }
    }

    public void Dispose()
    {
        try
        {
            _sniperCts?.Cancel();
            _sniperCts?.Dispose();
        }
        catch { }
    }
}
