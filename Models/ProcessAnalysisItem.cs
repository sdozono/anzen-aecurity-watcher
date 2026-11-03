using System.ComponentModel;
using System.Runtime.CompilerServices;
using AnzenSecurityWatcher.Services;

namespace AnzenSecurityWatcher.Models;

public enum TaskCorrelationStrength
{
    None = 0,
    Weak = 1,
    Possible = 2, // ±2 min
    Likely = 3,   // ±30 sec
    Strong = 4    // ±5 sec
}

public class ProcessAnalysisItem : INotifyPropertyChanged
{
    private bool _isCurrentlyRunning;
    private int _currentPid;
    private int _totalSeenCount;
    private DateTime _lastSeenTime = DateTime.Now;
    private bool _isPeriodic;
    private double _averageIntervalSeconds;
    private double _intervalStdDevSeconds;
    private bool _isRareOrNew;
    private bool _isTransientFlash;
    private bool _hadVisibleConsoleWindow;
    private double _lastDurationMs;
    private string _parentDisplay = "—";
    private string _matchedScheduledTask = "";
    private bool _isUserTrusted;
    private RiskLevel _riskLevel = RiskLevel.Safe;
    private ConfidenceLevel _confidence = ConfidenceLevel.High;
    private string _anomalyReason = "Normal process";

    public string ProcessKey { get; set; } = ""; // 小文字化したExecutablePathまたはProcessName(+短命シェル識別キー)
    public string ProcessName { get; set; } = "";
    public string ExecutablePath { get; set; } = "";
    public string CommandLine { get; set; } = "";
    public int ParentPid { get; set; }
    public string ParentProcessName { get; set; } = "";
    public string ParentCommandLine { get; set; } = "";
    public int GrandparentPid { get; set; }
    public string GrandparentProcessName { get; set; } = "";
    public string ProcessTreeSummary { get; set; } = "";
    /// <summary>祖先チェーン各世代のコマンドライン付き詳細（複数行）</summary>
    public string ProcessTreeDetail { get; set; } = "";
    public bool IsTrustedActivityChain { get; set; }
    public string TrustedActivityName { get; set; } = "";
    public TaskCorrelationStrength TaskCorrelation { get; set; } = TaskCorrelationStrength.None;
    public double TaskCorrelationDeltaSeconds { get; set; }
    public bool IsNewlyInstalledBinary { get; set; }
    public bool HasSuspiciousCommandLine { get; set; }
    public bool IsSigned { get; set; }
    public SignatureStatus SignatureStatus { get; set; } = SignatureStatus.Unknown;
    public string SignerName { get; set; } = "Unknown";
    public string Sha256 { get; set; } = "";
    public bool IsSelfProcess { get; set; }
    public bool IsSimulated { get; set; }
    public DateTime FirstSeenTime { get; set; } = DateTime.Now;
    public DateTime DetectedAt => LastSeenTime;
    public string ConsoleWindowTitle { get; set; } = "";
    public List<string> RecentCommandHistory { get; set; } = new();
    public string StoryKey { get; set; } = "";
    public string StoryTitle { get; set; } = "";

    public string ParentDisplay
    {
        get => _parentDisplay;
        set { _parentDisplay = value; OnPropertyChanged(); }
    }

    public string MatchedScheduledTask
    {
        get => _matchedScheduledTask;
        set { _matchedScheduledTask = value; OnPropertyChanged(); }
    }

    /// <summary>
    /// 0.05秒〜3秒程度で一瞬だけ起動して消えたプロセス（またはコンソール/ターミナルの一瞬の表示）か
    /// </summary>
    public bool IsTransientFlash
    {
        get => _isTransientFlash;
        set
        {
            _isTransientFlash = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(RunningStatusText));
            OnPropertyChanged(nameof(PeriodicitySummary));
        }
    }

    /// <summary>
    /// 実際に画面上に可視状態のコンソール/ターミナルウィンドウが一瞬表示されたか
    /// </summary>
    public bool HadVisibleConsoleWindow
    {
        get => _hadVisibleConsoleWindow;
        set
        {
            _hadVisibleConsoleWindow = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(RunningStatusText));
        }
    }

    /// <summary>
    /// 直近の起動〜終了までの生存時間（ミリ秒）
    /// </summary>
    public double LastDurationMs
    {
        get => _lastDurationMs;
        set
        {
            _lastDurationMs = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(RunningStatusText));
            OnPropertyChanged(nameof(DurationText));
        }
    }

    public string DurationText => LastDurationMs > 0
        ? (LastDurationMs < 1000
            ? Loc.T($"{LastDurationMs:F0}ms ({LastDurationMs / 1000.0:F2}s)", $"{LastDurationMs:F0}ms ({LastDurationMs / 1000.0:F2}秒)", $"{LastDurationMs:F0}ms ({LastDurationMs / 1000.0:F2}s)", $"{LastDurationMs:F0}ms ({LastDurationMs / 1000.0:F2}秒)")
            : Loc.T($"{LastDurationMs / 1000.0:F2}s", $"{LastDurationMs / 1000.0:F2}秒", $"{LastDurationMs / 1000.0:F2}s", $"{LastDurationMs / 1000.0:F2}秒"))
        : "—";

    public bool IsCurrentlyRunning
    {
        get => _isCurrentlyRunning;
        set { _isCurrentlyRunning = value; OnPropertyChanged(); OnPropertyChanged(nameof(RunningStatusText)); OnPropertyChanged(nameof(IsHistoricalOnly)); }
    }

    private bool _isFilePresent = true;
    public bool IsFilePresent
    {
        get => _isFilePresent;
        set { _isFilePresent = value; OnPropertyChanged(); OnPropertyChanged(nameof(RunningStatusText)); OnPropertyChanged(nameof(IsHistoricalOnly)); }
    }

    /// <summary>
    /// 現在稼働しておらず、かつ実行ファイルが既に削除されているか、または24時間以上前の過去の実行履歴であるか
    /// </summary>
    public bool IsHistoricalOnly => !IsCurrentlyRunning && (!IsFilePresent || (DateTime.Now - LastSeenTime).TotalHours >= 24);

    public int CurrentPid
    {
        get => _currentPid;
        set { _currentPid = value; OnPropertyChanged(); }
    }

    public string RunningStatusText
    {
        get
        {
            if (IsCurrentlyRunning)
                return Loc.T($"🟢 Running (PID:{CurrentPid})", $"🟢 运行中 (PID:{CurrentPid})", $"🟢 Activo (PID:{CurrentPid})", $"🟢 稼働中 (PID:{CurrentPid})");
            if (!IsFilePresent)
                return Loc.T("⚪ Exited (File Removed)", "⚪ 已退出 (文件已删除)", "⚪ Terminado (Archivo Eliminado)", "⚪ 終了 (ファイル削除済・残存なし)");
            if (HadVisibleConsoleWindow && LastDurationMs > 0)
                return Loc.T($"💥 Flash Win ({LastDurationMs / 1000.0:F2}s)", $"💥 瞬时窗口 ({LastDurationMs / 1000.0:F2}秒消失)", $"💥 Ventana fugaz ({LastDurationMs / 1000.0:F2}s)", $"💥 瞬間窓 ({LastDurationMs / 1000.0:F2}秒で消滅)");
            if (IsTransientFlash && LastDurationMs > 0)
                return Loc.T($"⚡ Short-lived ({LastDurationMs / 1000.0:F2}s)", $"⚡ 短命结束 ({LastDurationMs / 1000.0:F2}秒)", $"⚡ Fugaz ({LastDurationMs / 1000.0:F2}s)", $"⚡ 短命終了 ({LastDurationMs / 1000.0:F2}秒)");
            if (IsTransientFlash)
                return Loc.T("⚡ Flash Terminal / Short-lived", "⚡ 瞬时终端/短命", "⚡ Terminal fugaz / corto", "⚡ 瞬間ターミナル/短命");
            return Loc.T("⚪ Exited (History)", "⚪ 已退出 (保留历史)", "⚪ Terminado (Historial)", "⚪ 終了 (履歴保持)");
        }
    }

    public int TotalSeenCount
    {
        get => _totalSeenCount;
        set { _totalSeenCount = value; OnPropertyChanged(); }
    }

    public DateTime LastSeenTime
    {
        get => _lastSeenTime;
        set { _lastSeenTime = value; OnPropertyChanged(); OnPropertyChanged(nameof(LastSeenText)); }
    }

    public bool IsPeriodic
    {
        get => _isPeriodic;
        set { _isPeriodic = value; OnPropertyChanged(); OnPropertyChanged(nameof(PeriodicitySummary)); }
    }

    public double AverageIntervalSeconds
    {
        get => _averageIntervalSeconds;
        set { _averageIntervalSeconds = value; OnPropertyChanged(); OnPropertyChanged(nameof(PeriodicitySummary)); }
    }

    public double IntervalStdDevSeconds
    {
        get => _intervalStdDevSeconds;
        set { _intervalStdDevSeconds = value; OnPropertyChanged(); OnPropertyChanged(nameof(PeriodicitySummary)); }
    }

    public string PeriodicitySummary
    {
        get
        {
            if (IsPeriodic)
            {
                string dur = IsTransientFlash && LastDurationMs > 0
                    ? Loc.T($" [alive {LastDurationMs / 1000.0:F2}s]", $" [存活{LastDurationMs / 1000.0:F2}秒]", $" [vivo {LastDurationMs / 1000.0:F2}s]", $" [生存{LastDurationMs / 1000.0:F2}秒]")
                    : "";
                return Loc.T(
                    $"⏱️ Every ~{AverageIntervalSeconds:F1}s (±{IntervalStdDevSeconds:F1}s){dur}",
                    $"⏱️ 约 {AverageIntervalSeconds:F1} 秒周期 (±{IntervalStdDevSeconds:F1}秒){dur}",
                    $"⏱️ Cada ~{AverageIntervalSeconds:F1}s (±{IntervalStdDevSeconds:F1}s){dur}",
                    $"⏱️ 約 {AverageIntervalSeconds:F1} 秒周期 (±{IntervalStdDevSeconds:F1}秒){dur}");
            }
            if (IsTransientFlash && LaunchTimestamps.Count >= 2)
            {
                double lastGap = (LaunchTimestamps[^1] - LaunchTimestamps[^2]).TotalSeconds;
                if (lastGap >= 1.0 && lastGap <= 86400)
                    return Loc.T(
                        $"⚡ Flash ({lastGap:F0}s after prev / alive {LastDurationMs / 1000.0:F2}s)",
                        $"⚡ 瞬时启动 (距上次 {lastGap:F0}秒 / 存活{LastDurationMs / 1000.0:F2}秒)",
                        $"⚡ Fugaz (hace {lastGap:F0}s / vivo {LastDurationMs / 1000.0:F2}s)",
                        $"⚡ 瞬間起動 (前回から {lastGap:F0}秒後 / 生存{LastDurationMs / 1000.0:F2}秒)");
            }
            if (IsTransientFlash && LastDurationMs > 0)
            {
                return Loc.T(
                    $"⚡ Flash (alive {LastDurationMs / 1000.0:F2}s / {LastSeenTime:HH:mm:ss})",
                    $"⚡ 瞬时启动 (存活 {LastDurationMs / 1000.0:F2}秒 / {LastSeenTime:HH:mm:ss})",
                    $"⚡ Fugaz (vivo {LastDurationMs / 1000.0:F2}s / {LastSeenTime:HH:mm:ss})",
                    $"⚡ 瞬間起動 (生存 {LastDurationMs / 1000.0:F2}秒 / {LastSeenTime:HH:mm:ss})");
            }
            return Loc.T("— (Non-periodic)", "— (非周期)", "— (No periódico)", "— (非周期)");
        }
    }

    public bool IsRareOrNew
    {
        get => _isRareOrNew;
        set { _isRareOrNew = value; OnPropertyChanged(); }
    }

    public bool IsUserTrusted
    {
        get => _isUserTrusted;
        set { _isUserTrusted = value; OnPropertyChanged(); OnPropertyChanged(nameof(TrustBadge)); }
    }

    public string TrustBadge => IsSelfProcess
        ? Loc.T("🛡️ Self Process (This Monitor)", "🛡️ 自身进程 (本监控工具·未签名)", "🛡️ Proceso propio (Este monitor)", "🛡️ 自己プロセス (本監視ツール・未署名)")
        : (IsUserTrusted
            ? Loc.T("✅ Trusted", "✅ 已信任", "✅ Confiable", "✅ 承認済み")
            : (IsSigned || SignatureStatus == SignatureStatus.Signed
                ? Loc.T($"🔏 Signed ({SignerName})", $"🔏 已签名 ({SignerName})", $"🔏 Firmado ({SignerName})", $"🔏 署名あり ({SignerName})")
                : SignatureStatus == SignatureStatus.Unknown
                    ? Loc.T($"⚪ Unknown ({SignerName})", $"⚪ 未知 ({SignerName})", $"⚪ Desconocido ({SignerName})", $"⚪ 未解決/不明 ({SignerName})")
                    : Loc.T("⚠️ Unsigned", "⚠️ 未签名", "⚠️ Sin firma", "⚠️ 署名なし (Unsigned)")));

    /// <summary>
    /// Microsoft 署名（Microsoft Corporation / Microsoft Windows 等）を持つプロセスか
    /// </summary>
    public bool IsMicrosoftSigned =>
        IsSigned &&
        !IsSelfProcess &&
        !string.IsNullOrWhiteSpace(SignerName) &&
        (SignerName.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase) ||
         SignerName.Contains("Microsoft Windows", StringComparison.OrdinalIgnoreCase) ||
         SignerName.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase));

    public RiskLevel RiskLevel
    {
        get => _riskLevel;
        set { _riskLevel = value; OnPropertyChanged(); OnPropertyChanged(nameof(RiskBadge)); }
    }

    public ConfidenceLevel Confidence
    {
        get => _confidence;
        set { _confidence = value; OnPropertyChanged(); OnPropertyChanged(nameof(ConfidenceLabel)); OnPropertyChanged(nameof(RiskBadge)); }
    }

    public string ConfidenceLabel => Confidence switch
    {
        ConfidenceLevel.High => "High",
        ConfidenceLevel.Medium => "Med",
        _ => "Low"
    };

    public string RiskBadge => RiskLevel switch
    {
        RiskLevel.Critical => $"{Loc.T("🚨 Critical", "🚨 紧急", "🚨 Crítico", "🚨 緊急")} ({ConfidenceLabel})",
        RiskLevel.High => $"{Loc.T("⚠️ High", "⚠️ 警惕", "⚠️ Alto", "⚠️ 要警戒")} ({ConfidenceLabel})",
        RiskLevel.Medium => $"{Loc.T("⚡ Caution", "⚡ 注意", "⚡ Precaución", "⚡ 注意")} ({ConfidenceLabel})",
        RiskLevel.Low => Loc.T("ℹ️ Info", "ℹ️ 信息", "ℹ️ Info", "ℹ️ 情報"),
        _ => Loc.T("✅ Safe", "✅ 正常", "✅ Seguro", "✅ 正常")
    };

    public string AnomalyReason
    {
        get => _anomalyReason;
        set { _anomalyReason = value; OnPropertyChanged(); }
    }

    public List<DateTime> LaunchTimestamps { get; set; } = new();

    public string FirstSeenText => FirstSeenTime.ToString("yyyy-MM-dd HH:mm:ss");
    public string LastSeenText => LastSeenTime.ToString("HH:mm:ss");

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class ProcessBaselineRecord
{
    public string ProcessKey { get; set; } = "";
    public string ProcessName { get; set; } = "";
    public string ExecutablePath { get; set; } = "";
    public string CommandLine { get; set; } = "";
    public string ParentDisplay { get; set; } = "—";
    public bool IsSigned { get; set; }
    public string SignerName { get; set; } = "";
    public DateTime FirstSeenTime { get; set; }
    public DateTime LastSeenTime { get; set; }
    public int TotalSeenCount { get; set; }
    public bool IsUserTrusted { get; set; }
    public bool IsTransientFlash { get; set; }
    public bool HadVisibleConsoleWindow { get; set; }
    public double LastDurationMs { get; set; }
    public string MatchedScheduledTask { get; set; } = "";
    public int GrandparentPid { get; set; }
    public string GrandparentProcessName { get; set; } = "";
    public string ProcessTreeSummary { get; set; } = "";
    public string ProcessTreeDetail { get; set; } = "";
    public List<DateTime> RecentLaunchTimestamps { get; set; } = new();
}
