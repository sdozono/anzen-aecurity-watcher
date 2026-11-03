using System.Media;
using System.Windows;
using AnzenSecurityWatcher.Models;
using AnzenSecurityWatcher.Services;

namespace AnzenSecurityWatcher;

public partial class AlertPopupWindow : Window
{
    public event Action? OnInspectRequested;
    private ScreenShareDetectionItem? _lastItem;

    public AlertPopupWindow()
    {
        InitializeComponent();
        Loaded += AlertPopupWindow_Loaded;
        LocalizationManager.OnLanguageChanged += _ =>
        {
            if (_lastItem != null)
            {
                Dispatcher.BeginInvoke(() => RefreshText(_lastItem));
            }
        };
    }

    private void AlertPopupWindow_Loaded(object sender, RoutedEventArgs e)
    {
        PositionBottomRight();
    }

    public void PositionBottomRight()
    {
        var workArea = SystemParameters.WorkArea;
        Left = workArea.Right - Width - 16;
        Top = workArea.Bottom - Height - 16;
    }

    public void UpdateAlertContent(ScreenShareDetectionItem item)
    {
        _lastItem = item;
        RefreshText(item);
        PositionBottomRight();
        try
        {
            SystemSounds.Exclamation.Play();
        }
        catch { }
    }

    private void RefreshText(ScreenShareDetectionItem item)
    {
        ToolTitleText.Text = Loc.T(
            $"⚠️ Screen share / remote access detected via {item.ToolName}!",
            $"⚠️ 检测到通过 {item.ToolName} 进行的屏幕共享/远程连接！",
            $"⚠️ ¡Se detectó pantalla compartida / acceso remoto por {item.ToolName}!",
            $"⚠️ {item.ToolName} による画面共有・遠隔接続を検知！");
        EvidenceText.Text = Loc.T(
            $"Evidence: {item.Evidence}",
            $"依据: {item.Evidence}",
            $"Evidencia: {item.Evidence}",
            $"証跡: {item.Evidence}");
        EndpointText.Text = Loc.T(
            $"Remote: {item.RemoteEndpoints}",
            $"通信目标: {item.RemoteEndpoints}",
            $"Destino: {item.RemoteEndpoints}",
            $"通信先: {item.RemoteEndpoints}");
    }

    private void InspectButton_Click(object sender, RoutedEventArgs e)
    {
        OnInspectRequested?.Invoke();
        Hide();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Hide();
    }
}
