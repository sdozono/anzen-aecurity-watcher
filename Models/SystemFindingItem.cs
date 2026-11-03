using System.ComponentModel;
using System.Runtime.CompilerServices;
using AnzenSecurityWatcher.Services;

namespace AnzenSecurityWatcher.Models;

/// <summary>
/// システム防御エンジンが検知するイベントの分類
/// </summary>
public enum FindingCategory
{
    Autostart,        // 自動起動・永続化
    WmiSubscription,  // WMI イベントサブスクリプション (ファイルレス永続化)
    CommandLine,      // 不審なコマンドライン
    CameraMic,        // カメラ・マイク・画面キャプチャ使用
    Keylogger,        // キーロガー / グローバルフック兆候
    Clipboard,        // クリップボード監視・改ざん
    UsbDevice,        // USB デバイス接続
    RootCertificate,  // ルート証明書ストア
    Account,          // ログオン失敗・アカウント作成 (イベントログ)
    AdminGroup,       // ローカル管理者グループ・ユーザー変更
    DllSideload,      // DLL サイドローディング
    SecurityConfig    // セキュリティ設定診断
}

/// <summary>
/// 検知アイテムのライフサイクル状態
/// </summary>
public enum FindingState
{
    New,        // 監視開始後に新たに出現（ベースラインに無い）
    Existing,   // 起動時点から存在（ベースライン）
    Active,     // 現在進行形で発生中（カメラ使用中など）
    Resolved    // 解消済み（削除・切断・使用終了）
}

public class SystemFindingItem : INotifyPropertyChanged
{
    private RiskLevel _severity = RiskLevel.Low;
    private ConfidenceLevel _confidence = ConfidenceLevel.High;
    private FindingState _state = FindingState.Existing;
    private string _title = "";
    private string _detail = "";
    private DateTime _lastSeen = DateTime.Now;
    private bool _isAcknowledged;

    /// <summary>重複排除・承認管理に使う一意キー</summary>
    public string Key { get; set; } = "";
    public FindingCategory Category { get; set; }
    public string Target { get; set; } = "";          // 対象（パス・プロセス名・デバイス名など）
    public string TechnicalDetails { get; set; } = ""; // AI 相談用の詳細
    public string RecommendedAction { get; set; } = "";
    public string OpenLocationPath { get; set; } = ""; // 「場所を開く」で開くファイル/フォルダ
    public int ProcessId { get; set; }
    public DateTime FirstSeen { get; set; } = DateTime.Now;
    public bool IsSimulated { get; set; }
    public string StoryKey { get; set; } = "";
    public string StoryTitle { get; set; } = "";

    public RiskLevel Severity
    {
        get => _severity;
        set { _severity = value; OnPropertyChanged(); OnPropertyChanged(nameof(SeverityBadge)); OnPropertyChanged(nameof(EffectiveSeverity)); }
    }

    public ConfidenceLevel Confidence
    {
        get => _confidence;
        set { _confidence = value; OnPropertyChanged(); OnPropertyChanged(nameof(ConfidenceBadge)); OnPropertyChanged(nameof(SeverityBadge)); }
    }

    public string ConfidenceBadge => Confidence switch
    {
        ConfidenceLevel.High => Loc.T("Conf:High", "置信:高", "Conf:Alta", "確信:高"),
        ConfidenceLevel.Medium => Loc.T("Conf:Med", "置信:中", "Conf:Media", "確信:中"),
        _ => Loc.T("Conf:Low", "置信:低", "Conf:Baja", "確信:低")
    };

    public FindingState State
    {
        get => _state;
        set { _state = value; OnPropertyChanged(); OnPropertyChanged(nameof(StateBadge)); }
    }

    public string Title
    {
        get => _title;
        set { _title = value; OnPropertyChanged(); }
    }

    public string Detail
    {
        get => _detail;
        set { _detail = value; OnPropertyChanged(); }
    }

    public DateTime LastSeen
    {
        get => _lastSeen;
        set { _lastSeen = value; OnPropertyChanged(); OnPropertyChanged(nameof(LastSeenText)); }
    }

    /// <summary>ユーザーが「承認（問題なし）」とマークしたか</summary>
    public bool IsAcknowledged
    {
        get => _isAcknowledged;
        set { _isAcknowledged = value; OnPropertyChanged(); OnPropertyChanged(nameof(SeverityBadge)); OnPropertyChanged(nameof(EffectiveSeverity)); }
    }

    /// <summary>承認済みの場合は Safe 扱いにした実効リスク</summary>
    public RiskLevel EffectiveSeverity => IsAcknowledged ? RiskLevel.Safe : Severity;

    public string SeverityBadge => IsAcknowledged
        ? Loc.T("✅ Acked", "✅ 已确认", "✅ Aceptado", "✅ 承認済")
        : Severity switch
        {
            RiskLevel.Critical => $"{Loc.T("🚨 Critical", "🚨 紧急", "🚨 Crítico", "🚨 緊急")} ({ConfidenceBadge})",
            RiskLevel.High => $"{Loc.T("⚠️ High", "⚠️ 警惕", "⚠️ Alto", "⚠️ 要警戒")} ({ConfidenceBadge})",
            RiskLevel.Medium => $"{Loc.T("⚡ Caution", "⚡ 注意", "⚡ Precaución", "⚡ 注意")} ({ConfidenceBadge})",
            RiskLevel.Low => Loc.T("ℹ️ Info", "ℹ️ 信息", "ℹ️ Info", "ℹ️ 情報"),
            _ => Loc.T("✅ Safe", "✅ 正常", "✅ Seguro", "✅ 正常")
        };

    public string StateBadge => State switch
    {
        FindingState.New => Loc.T("🆕 New", "🆕 新增", "🆕 Nuevo", "🆕 新規"),
        FindingState.Active => Loc.T("🔴 Active", "🔴 发生中", "🔴 Activo", "🔴 発生中"),
        FindingState.Resolved => Loc.T("⚪ Resolved", "⚪ 已消除", "⚪ Resuelto", "⚪ 解消"),
        _ => Loc.T("📌 Existing", "📌 既有", "📌 Existente", "📌 既存")
    };

    public string CategoryLabel => GetCategoryLabel(Category);

    public static string GetCategoryLabel(FindingCategory category) => category switch
    {
        FindingCategory.Autostart => Loc.T("🚀 Autostart", "🚀 开机自启", "🚀 Autoinicio", "🚀 自動起動"),
        FindingCategory.WmiSubscription => Loc.T("👻 WMI Persistence", "👻 WMI持久化", "👻 Persistencia WMI", "👻 WMI永続化"),
        FindingCategory.CommandLine => Loc.T("⌨️ Command Line", "⌨️ 命令行", "⌨️ Línea de Comandos", "⌨️ コマンドライン"),
        FindingCategory.CameraMic => Loc.T("📷 Camera / Mic", "📷 摄像头/麦克风", "📷 Cámara / Mic", "📷 カメラ/マイク"),
        FindingCategory.Keylogger => Loc.T("🎹 Keyhook Monitor", "🎹 按键监控", "🎹 Monitoreo de Teclas", "🎹 キー入力監視"),
        FindingCategory.Clipboard => Loc.T("📋 Clipboard", "📋 剪贴板", "📋 Portapapeles", "📋 クリップボード"),
        FindingCategory.UsbDevice => Loc.T("🔌 USB Device", "🔌 USB设备", "🔌 Dispositivo USB", "🔌 USBデバイス"),
        FindingCategory.RootCertificate => Loc.T("📜 Root Certificate", "📜 根证书", "📜 Certificado Raíz", "📜 ルート証明書"),
        FindingCategory.Account => Loc.T("🔐 Logon / Account", "🔐 登录/账户", "🔐 Inicio / Cuenta", "🔐 ログオン/アカウント"),
        FindingCategory.AdminGroup => Loc.T("👑 Admin Group", "👑 管理员组", "👑 Grupo Admin", "👑 管理者グループ"),
        FindingCategory.DllSideload => Loc.T("🧩 DLL Sideload", "🧩 DLL侧加载", "🧩 DLL Sideload", "🧩 DLLサイドロード"),
        FindingCategory.SecurityConfig => Loc.T("🛡️ Security Config", "🛡️ 安全配置", "🛡️ Config. Seguridad", "🛡️ セキュリティ設定"),
        _ => Loc.T("Other", "其他", "Otro", "その他")
    };

    public string FirstSeenText => FirstSeen.ToString("MM/dd HH:mm:ss");
    public string LastSeenText => LastSeen.ToString("HH:mm:ss");

    public void RefreshLocalization()
    {
        OnPropertyChanged(nameof(SeverityBadge));
        OnPropertyChanged(nameof(StateBadge));
        OnPropertyChanged(nameof(CategoryLabel));
        OnPropertyChanged(nameof(Title));
        OnPropertyChanged(nameof(Detail));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>
/// 各監視エンジンが 1 回のスキャンで返す検知結果（キー単位で集約される前の生データ）
/// </summary>
public record FindingReport(
    string Key,
    FindingCategory Category,
    RiskLevel Severity,
    FindingState State,
    string Title,
    string Detail,
    string Target,
    string TechnicalDetails,
    string RecommendedAction,
    string OpenLocationPath = "",
    int ProcessId = 0,
    bool IsSimulated = false,
    ConfidenceLevel Confidence = ConfidenceLevel.High,
    string StoryKey = "",
    string StoryTitle = "");
