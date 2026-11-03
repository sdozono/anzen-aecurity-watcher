using System.ComponentModel;
using System.Runtime.CompilerServices;
using AnzenSecurityWatcher.Services;

namespace AnzenSecurityWatcher.Models;

public enum ScreenShareCategory
{
    WindowsRdp,
    RemoteDesktopTool,
    MeetingScreenShare
}

public enum ScreenShareStatus
{
    Inactive = 0,
    InstalledOnly = 1,          // 🟢 Installed (インストールのみ・プロセス未稼働)
    ServiceRunning = 2,         // 🟢 Service running (TeamViewer_Service等の常駐サービスのみ・セッション未確立)
    StandbyService = 3,         // ⚪ Listening/Standby (GUIや待受ポートが起動しているがセッション未確立)
    ListeningStandby = 3,
    OutboundControlChannel = 4, // 🟠 Outbound control channel established (外部制御サーバーと通信確立中だが画面転送ヘルパー未起動)
    ActiveStreaming = 5         // 🔴 Active remote-control session (画面共有中またはリモート操作セッション確立中！)
}

public class ScreenShareDetectionItem : INotifyPropertyChanged
{
    private ScreenShareStatus _status = ScreenShareStatus.Inactive;
    private RiskLevel _severity = RiskLevel.Safe;
    private ConfidenceLevel _confidence = ConfidenceLevel.High;
    private string _evidence = "";
    private string _remoteEndpoints = "";
    private DateTime _lastDetected = DateTime.Now;

    public string DetectionKey { get; set; } = "";
    public ScreenShareCategory Category { get; set; }
    public string ToolName { get; set; } = "";
    public string ProcessName { get; set; } = "";
    public int ProcessId { get; set; }
    public DateTime FirstDetected { get; set; } = DateTime.Now;
    public bool IsSimulated { get; set; }

    public RiskLevel Severity
    {
        get => _severity;
        set { _severity = value; OnPropertyChanged(); }
    }

    public ConfidenceLevel Confidence
    {
        get => _confidence;
        set { _confidence = value; OnPropertyChanged(); }
    }

    public DateTime LastDetected
    {
        get => _lastDetected;
        set { _lastDetected = value; OnPropertyChanged(); OnPropertyChanged(nameof(LastDetectedText)); }
    }

    public ScreenShareStatus Status
    {
        get => _status;
        set
        {
            _status = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(StatusBadge));
            OnPropertyChanged(nameof(IsActiveStreaming));
        }
    }

    public bool IsActiveStreaming => Status == ScreenShareStatus.ActiveStreaming;

    public string CategoryLabel => Category switch
    {
        ScreenShareCategory.WindowsRdp => Loc.T(
            "🖥️ Windows RDP (Remote Desktop)",
            "🖥️ Windows RDP (远程桌面)",
            "🖥️ Windows RDP (Escritorio remoto)",
            "🖥️ Windows RDP (リモートデスクトップ)"),
        ScreenShareCategory.RemoteDesktopTool => Loc.T(
            "🔑 Remote Access Tool (AnyDesk/TV/VNC)",
            "🔑 远程控制工具 (AnyDesk/TV/VNC等)",
            "🔑 Herramienta de Control Remoto (AnyDesk/TV/VNC)",
            "🔑 遠隔操作ツール (AnyDesk/TV/VNC等)"),
        ScreenShareCategory.MeetingScreenShare => Loc.T(
            "📹 Meeting Screen Share (Teams/Zoom)",
            "📹 视频会议屏幕共享 (Teams/Zoom等)",
            "📹 Pantalla Compartida en Reunión (Teams/Zoom)",
            "📹 Web会議 画面共有 (Teams/Zoom等)"),
        _ => Loc.T("Other", "其他", "Otro", "その他")
    };

    public string StatusBadge => Status switch
    {
        ScreenShareStatus.ActiveStreaming => Loc.T(
            "🔴 Active remote-control / screen share session",
            "🔴 活动远程控制 / 屏幕共享会话 (ACTIVE)",
            "🔴 Sesión activa de control remoto / pantalla",
            "🔴 アクティブな遠隔操作・画面共有セッション"),
        ScreenShareStatus.OutboundControlChannel => Loc.T(
            "🟠 Outbound control channel established",
            "🟠 已建立外部控制通道连接",
            "🟠 Canal de control saliente establecido",
            "🟠 外部制御チャネル接続中 (セッション未開始)"),
        ScreenShareStatus.StandbyService => Loc.T(
            "⚪ Listening / Standby",
            "⚪ 监听 / 待机中",
            "⚪ Escuchando / En espera",
            "⚪ 待受・スタンバイ中"),
        ScreenShareStatus.ServiceRunning => Loc.T(
            "🟢 Service running (No remote session)",
            "🟢 后台服务运行中 (无远程连接)",
            "🟢 Servicio en ejecución (Sin sesión remota)",
            "🟢 サービス稼働のみ (リモート接続なし)"),
        ScreenShareStatus.InstalledOnly => Loc.T(
            "🟢 Installed (Not running)",
            "🟢 已安装 (未运行)",
            "🟢 Instalado (No en ejecución)",
            "🟢 インストール済み (未起動)"),
        _ => Loc.T("✅ Inactive", "✅ 已停止", "✅ Inactivo", "✅ 停止中")
    };

    public string Evidence
    {
        get => _evidence;
        set { _evidence = value; OnPropertyChanged(); }
    }

    public string RemoteEndpoints
    {
        get => _remoteEndpoints;
        set { _remoteEndpoints = value; OnPropertyChanged(); }
    }

    public string FirstDetectedText => FirstDetected.ToString("HH:mm:ss");
    public string LastDetectedText => LastDetected.ToString("HH:mm:ss");

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
