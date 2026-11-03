using System.ComponentModel;
using System.Runtime.CompilerServices;
using AnzenSecurityWatcher.Services;

namespace AnzenSecurityWatcher.Models;

public enum RiskLevel
{
    Safe = 0,
    Low = 1,
    Informational = 1,
    Medium = 2,
    Caution = 2,
    High = 3,
    Critical = 4
}

/// <summary>
/// 判定の確信度 (Severity と分離して評価する Confidence 軸)
/// </summary>
public enum ConfidenceLevel
{
    Low = 0,
    Medium = 1,
    High = 2
}

/// <summary>
/// デジタル署名の検証状態 (Unsigned と Unknown/未解決 を明確に分離)
/// </summary>
public enum SignatureStatus
{
    Signed = 0,
    Unsigned = 1,
    Unknown = 2
}

/// <summary>
/// ベースラインとの意味的差分 (Semantic Diff) 種別
/// </summary>
public enum BaselineChangeType
{
    None = 0,
    NewlyAdded,
    PathChanged,
    HashChanged,
    SignerChanged,
    StartTypeChanged,
    ServiceDllChanged,
    ArgumentsChanged,
    TaskActionChanged,
    CertificateAdded
}

public class NetworkConnectionItem : INotifyPropertyChanged
{
    private string _countryCode = "...";
    private string _countryName = "Resolving...";
    private string _countryFlag = "🌐";
    private string _organization = "";
    private string _city = "";
    private RiskLevel _riskLevel = RiskLevel.Safe;
    private ConfidenceLevel _confidence = ConfidenceLevel.High;
    private string _riskReason = "Normal";
    private string _state = "";

    public string ConnectionKey => $"{Protocol}:{LocalAddress}:{LocalPort}->{RemoteAddress}:{RemotePort}:{ProcessId}";
    public string Protocol { get; set; } = "TCP";
    public string LocalAddress { get; set; } = "";
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public bool IsWildcardEndpoint { get; set; }
    public bool IsKnownCdn { get; set; }
    public string ProcessSigner { get; set; } = "";
    public SignatureStatus ProcessSignatureStatus { get; set; } = SignatureStatus.Unknown;

    public string State
    {
        get => _state;
        set { _state = value; OnPropertyChanged(); }
    }

    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string ProcessPath { get; set; } = "";
    public DateTime FirstSeen { get; set; } = DateTime.Now;
    public DateTime LastSeen { get; set; } = DateTime.Now;

    public string CountryCode
    {
        get => _countryCode;
        set { _countryCode = value; OnPropertyChanged(); OnPropertyChanged(nameof(CountryDisplay)); }
    }

    public string CountryName
    {
        get => _countryName;
        set { _countryName = value; OnPropertyChanged(); OnPropertyChanged(nameof(CountryDisplay)); }
    }

    public string CountryFlag
    {
        get => _countryFlag;
        set { _countryFlag = value; OnPropertyChanged(); OnPropertyChanged(nameof(CountryDisplay)); }
    }

    public string CountryDisplay => IsWildcardEndpoint
        ? Loc.T("📡 Local Bind / Unspecified (*)", "📡 本地绑定 / 未指定地址 (*)", "📡 Enlace local / No especificado (*)", "📡 ローカル待受 / 未指定アドレス (*)")
        : $"{CountryFlag} {GeoIpService.GetLocalizedCountryName(CountryCode, CountryName)} ({CountryCode})";

    public string Organization
    {
        get => _organization;
        set { _organization = value; OnPropertyChanged(); }
    }

    public string City
    {
        get => _city;
        set { _city = value; OnPropertyChanged(); }
    }

    public RiskLevel RiskLevel
    {
        get => _riskLevel;
        set
        {
            _riskLevel = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(RiskLabel));
        }
    }

    public ConfidenceLevel Confidence
    {
        get => _confidence;
        set
        {
            _confidence = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(ConfidenceLabel));
            OnPropertyChanged(nameof(RiskLabel));
        }
    }

    public string ConfidenceLabel => Confidence switch
    {
        ConfidenceLevel.High => "High",
        ConfidenceLevel.Medium => "Medium",
        _ => "Low"
    };

    public string RiskReason
    {
        get => _riskReason;
        set { _riskReason = value; OnPropertyChanged(); }
    }

    public string RiskLabel => RiskLevel switch
    {
        RiskLevel.Critical => Loc.T("🚨 Critical", "🚨 紧急", "🚨 Crítico", "🚨 緊急"),
        RiskLevel.High => Loc.T("⚠️ High", "⚠️ 高风险", "⚠️ Alto", "⚠️ 高リスク"),
        RiskLevel.Medium => Loc.T("⚡ Caution", "⚡ 注意", "⚡ Precaución", "⚡ 注意(Caution)"),
        RiskLevel.Low => Loc.T("ℹ️ Info", "ℹ️ 信息", "ℹ️ Info", "ℹ️ 情報(Info)"),
        _ => Loc.T("✅ Safe", "✅ 正常", "✅ Seguro", "✅ 安全(Safe)")
    };

    public string LocalEndpoint => LocalAddress.Contains(':') ? $"[{LocalAddress}]:{LocalPort}" : $"{LocalAddress}:{LocalPort}";
    public string RemoteEndpoint => (Protocol == "UDP" && RemotePort == 0) || IsWildcardEndpoint
        ? $"{Protocol} {(LocalAddress.Contains(':') ? $"[{LocalAddress}]" : LocalAddress)}:{LocalPort} (Local Bind)"
        : (RemoteAddress.Contains(':') ? $"[{RemoteAddress}]:{RemotePort}" : $"{RemoteAddress}:{RemotePort}");
    public string FirstSeenText => FirstSeen.ToString("HH:mm:ss");

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class CountryTrafficSummary : INotifyPropertyChanged
{
    private int _connectionCount;
    private int _processCount;
    private bool _hasWarning;

    public string CountryCode { get; set; } = "";
    public string CountryName { get; set; } = "";
    public string CountryFlag { get; set; } = "🌐";
    public string DisplayTitle => $"{CountryFlag} {GeoIpService.GetLocalizedCountryName(CountryCode, CountryName)} ({CountryCode})";

    public int ConnectionCount
    {
        get => _connectionCount;
        set
        {
            _connectionCount = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(ConnectionCountText));
        }
    }

    public int ProcessCount
    {
        get => _processCount;
        set
        {
            _processCount = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(ProcessCountText));
        }
    }

    public string ConnectionCountText => Loc.T(
        $"{ConnectionCount} conn",
        $"{ConnectionCount}个连接",
        $"{ConnectionCount} conex.",
        $"{ConnectionCount}件");

    public string ProcessCountText => Loc.T(
        $" ({ProcessCount} proc)",
        $" ({ProcessCount}个进程)",
        $" ({ProcessCount} proc.)",
        $" ({ProcessCount}プロセス)");

    public bool HasWarning
    {
        get => _hasWarning;
        set { _hasWarning = value; OnPropertyChanged(); }
    }

    public string SampleProcesses { get; set; } = "";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
