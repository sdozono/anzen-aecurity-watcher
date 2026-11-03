using System.ComponentModel;
using System.Runtime.CompilerServices;
using AnzenSecurityWatcher.Services;

namespace AnzenSecurityWatcher.Models;

public enum LogCategory
{
    SecurityStory,
    Network,
    ScreenShare,
    ProcessAnomaly,
    SystemSecurity
}

public class SecurityLogEntry : INotifyPropertyChanged
{
    private bool _isSelected = true;
    private int _occurrenceCount = 1;
    private DateTime _lastTimestamp = DateTime.Now;
    private RiskLevel _severity = RiskLevel.Medium;
    private ConfidenceLevel _confidence = ConfidenceLevel.High;
    private bool _isHistorical;

    public string LogKey { get; set; } = "";
    public string StoryKey { get; set; } = "";
    public bool IsStorySummary { get; set; }
    public bool IsHistorical
    {
        get => _isHistorical;
        set { _isHistorical = value; OnPropertyChanged(); OnPropertyChanged(nameof(SeverityLabel)); OnPropertyChanged(nameof(IsHistoricalRecord)); }
    }

    public bool IsHistoricalRecord => _isHistorical ||
                                      Title.Contains("過去履歴") ||
                                      Title.Contains("Historical Trace") ||
                                      Title.Contains("历史痕迹") ||
                                      Title.Contains("Historial");
    public DateTime Timestamp { get; set; } = DateTime.Now;

    public DateTime LastTimestamp
    {
        get => _lastTimestamp;
        set { _lastTimestamp = value; OnPropertyChanged(); OnPropertyChanged(nameof(TimestampText)); }
    }

    public int OccurrenceCount
    {
        get => _occurrenceCount;
        set { _occurrenceCount = value; OnPropertyChanged(); }
    }

    public LogCategory Category { get; set; }

    public RiskLevel Severity
    {
        get => _severity;
        set { _severity = value; OnPropertyChanged(); OnPropertyChanged(nameof(SeverityLabel)); }
    }

    public ConfidenceLevel Confidence
    {
        get => _confidence;
        set { _confidence = value; OnPropertyChanged(); OnPropertyChanged(nameof(ConfidenceLabel)); OnPropertyChanged(nameof(SeverityLabel)); }
    }

    public string ConfidenceLabel => Confidence switch
    {
        ConfidenceLevel.High => "HIGH",
        ConfidenceLevel.Medium => "MEDIUM",
        _ => "LOW"
    };

    public string Title { get; set; } = "";
    public string Summary { get; set; } = "";
    public string TechnicalDetails { get; set; } = "";
    public string RelatedProcess { get; set; } = "";
    public string RelatedEndpoint { get; set; } = "";
    public string RecommendedAction { get; set; } = "";
    /// <summary>Parent PID → Grandparent PID → Great-grandparent PID (各CommandLine・StartTime付き祖先系譜)</summary>
    public string ProcessLineage { get; set; } = "";

    public bool IsSelected
    {
        get => _isSelected;
        set { _isSelected = value; OnPropertyChanged(); }
    }

    public string TimestampText => LastTimestamp.ToString("HH:mm:ss");

    public string CategoryLabel => Category switch
    {
        LogCategory.SecurityStory => Loc.T("📖 Security Story", "📖 关联安全故事 (Story)", "📖 Historia de Seguridad", "📖 統合セキュリティストーリー"),
        LogCategory.Network => Loc.T("🌐 Network & Country Traffic", "🌐 可疑通信与国家监控", "🌐 Red y Tráfico por País", "🌐 不審通信・国別監視"),
        LogCategory.ScreenShare => Loc.T("🖥️ Screen Share & Remote Access", "🖥️ 屏幕共享与远程控制", "🖥️ Pantalla Compartida y Remoto", "🖥️ 画面共有・遠隔操作"),
        LogCategory.ProcessAnomaly => Loc.T("⚙️ Unknown / Periodic Process", "⚙️ 未知/周期进程", "⚙️ Proceso Desconocido/Periódico", "⚙️ 未知/周期プロセス"),
        _ => Loc.T("🛡️ System Security", "🛡️ 系统安全", "🛡️ Seguridad del Sistema", "🛡️ システム")
    };

    public string SeverityLabel
    {
        get
        {
            string baseLabel = Severity switch
            {
                RiskLevel.Critical => $"{Loc.T("🚨 CRITICAL", "🚨 紧急 (CRITICAL)", "🚨 CRÍTICO (CRITICAL)", "🚨 緊急 (CRITICAL)")} [Conf:{ConfidenceLabel}]",
                RiskLevel.High => $"{Loc.T("⚠️ HIGH", "⚠️ 高 (HIGH)", "⚠️ ALTO (HIGH)", "⚠️ 高 (HIGH)")} [Conf:{ConfidenceLabel}]",
                RiskLevel.Medium => $"{Loc.T("⚡ CAUTION", "⚡ 注意 (CAUTION)", "⚡ PRECAUCIÓN (CAUTION)", "⚡ 注意 (CAUTION)")} [Conf:{ConfidenceLabel}]",
                RiskLevel.Low => $"{Loc.T("ℹ️ INFORMATIONAL", "ℹ️ 信息 (INFO)", "ℹ️ INFORMATIVO (INFO)", "ℹ️ 情報 (INFORMATIONAL)")} [Conf:{ConfidenceLabel}]",
                _ => $"{Loc.T("🟢 SAFE", "🟢 正常 (SAFE)", "🟢 SEGURO (SAFE)", "🟢 安全 (SAFE)")} [Conf:{ConfidenceLabel}]"
            };
            if (IsHistorical)
            {
                return $"{baseLabel} {Loc.T("[Historical / Inactive]", "[历史记录/非活跃]", "[Historial / Inactivo]", "[過去履歴/非稼働]")}";
            }
            return baseLabel;
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
