using System.Windows;
using AnzenSecurityWatcher.Services;

namespace AnzenSecurityWatcher;

public partial class SettingsWindow : Window
{
    private readonly MainWindow _mainWindow;
    private bool _isInitializing = true;

    public SettingsWindow(MainWindow mainWindow)
    {
        InitializeComponent();
        _mainWindow = mainWindow;
        Owner = mainWindow;

        // 現在の表示言語を選択状態に反映
        switch (LocalizationManager.CurrentLanguage)
        {
            case AppLanguage.Chinese:
                LangZhRadio.IsChecked = true;
                break;
            case AppLanguage.Spanish:
                LangEsRadio.IsChecked = true;
                break;
            case AppLanguage.Japanese:
                LangJaRadio.IsChecked = true;
                break;
            default:
                LangEnRadio.IsChecked = true;
                break;
        }

        // 現在のテーマモードを選択状態に反映
        switch (ThemeManager.CurrentMode)
        {
            case AppThemeMode.Light:
                ThemeLightRadio.IsChecked = true;
                break;
            case AppThemeMode.Dark:
                ThemeDarkRadio.IsChecked = true;
                break;
            default:
                ThemeSystemRadio.IsChecked = true;
                break;
        }

        // 現在のスキャン間隔を選択状態に反映
        switch (SettingsManager.Current.ScanInterval)
        {
            case ScanIntervalMode.PowerSaving:
                ScanIntervalPowerSavingRadio.IsChecked = true;
                break;
            case ScanIntervalMode.Standard:
                ScanIntervalStandardRadio.IsChecked = true;
                break;
            default:
                ScanIntervalFastRadio.IsChecked = true;
                break;
        }

        // 現在のオプション状態を反映
        IncludeLoopbackCheck.IsChecked = _mainWindow.IncludeLoopbackOption;
        IncludeListenCheck.IsChecked = _mainWindow.IncludeListenOption;
        IncludeUdpCheck.IsChecked = _mainWindow.IncludeUdpOption;
        EnableDllSideloadCheck.IsChecked = _mainWindow.EnableDllSideloadCheckOption;
        MaskPersonalInfoCheck.IsChecked = _mainWindow.MaskPersonalInfoOption;
        DisableOnlineGeoIpCheck.IsChecked = _mainWindow.DisableOnlineGeoIpOption;

        _isInitializing = false;
    }

    private void LanguageRadio_Checked(object sender, RoutedEventArgs e)
    {
        if (_isInitializing) return;

        if (LangZhRadio.IsChecked == true)
            _mainWindow.SetLanguage(AppLanguage.Chinese);
        else if (LangEsRadio.IsChecked == true)
            _mainWindow.SetLanguage(AppLanguage.Spanish);
        else if (LangJaRadio.IsChecked == true)
            _mainWindow.SetLanguage(AppLanguage.Japanese);
        else
            _mainWindow.SetLanguage(AppLanguage.English);
    }

    private void ThemeRadio_Checked(object sender, RoutedEventArgs e)
    {
        if (_isInitializing) return;

        if (ThemeLightRadio.IsChecked == true)
            _mainWindow.SetThemeMode(AppThemeMode.Light);
        else if (ThemeDarkRadio.IsChecked == true)
            _mainWindow.SetThemeMode(AppThemeMode.Dark);
        else
            _mainWindow.SetThemeMode(AppThemeMode.System);
    }

    private void ScanIntervalRadio_Checked(object sender, RoutedEventArgs e)
    {
        if (_isInitializing) return;

        if (ScanIntervalPowerSavingRadio.IsChecked == true)
            _mainWindow.SetScanInterval(ScanIntervalMode.PowerSaving);
        else if (ScanIntervalStandardRadio.IsChecked == true)
            _mainWindow.SetScanInterval(ScanIntervalMode.Standard);
        else
            _mainWindow.SetScanInterval(ScanIntervalMode.Fast);
    }

    private async void OptionsCheck_Clicked(object sender, RoutedEventArgs e)
    {
        if (_isInitializing) return;

        await _mainWindow.UpdateScanAndPromptOptionsAsync(
            IncludeLoopbackCheck.IsChecked == true,
            IncludeListenCheck.IsChecked == true,
            IncludeUdpCheck.IsChecked == true,
            MaskPersonalInfoCheck.IsChecked == true,
            EnableDllSideloadCheck.IsChecked == true,
            DisableOnlineGeoIpCheck.IsChecked == true);
    }

    private async void SimAllButton_Click(object sender, RoutedEventArgs e)
    {
        await _mainWindow.TriggerDemoSimulationAllAsync();
        TestActionStatusText.Text = Loc.T(
            "✅ Triggered all simulations (Check bottom-right popup, top banner, and process list. *Excluded from AI consultation logs).",
            "✅ 已触发全部模拟测试（请查看右下角弹窗、顶部横幅及进程列表。※不会混入 AI 咨询日志）。",
            "✅ Se activaron todas las simulaciones (Verifique la alerta emergente, el banner superior y la lista de procesos. *Excluido de los registros de IA).",
            "✅ 一括テストを発報しました（画面右下ポップアップ・上部バナー・プロセス一覧をご確認ください。※AI相談ログには混入しません）。");
    }

    private async void SimAnyDeskButton_Click(object sender, RoutedEventArgs e)
    {
        await _mainWindow.TriggerSimAnyDeskAsync();
        TestActionStatusText.Text = Loc.T(
            "✅ Triggered AnyDesk screen leak simulation.",
            "✅ 已触发 AnyDesk 屏幕外泄模拟测试。",
            "✅ Se activó la prueba de simulación de AnyDesk.",
            "✅ AnyDesk 画面流出テストを発報しました。");
    }

    private async void SimZoomButton_Click(object sender, RoutedEventArgs e)
    {
        await _mainWindow.TriggerSimZoomShareAsync();
        TestActionStatusText.Text = Loc.T(
            "✅ Triggered Zoom screen share simulation.",
            "✅ 已触发 Zoom 屏幕共享模拟测试。",
            "✅ Se activó la prueba de pantalla compartida de Zoom.",
            "✅ Zoom 画面共有テストを発報しました。");
    }

    private async void SimRdpButton_Click(object sender, RoutedEventArgs e)
    {
        await _mainWindow.TriggerSimRdpAsync();
        TestActionStatusText.Text = Loc.T(
            "✅ Triggered Windows RDP connection simulation.",
            "✅ 已触发 Windows RDP 连接模拟测试。",
            "✅ Se activó la prueba de conexión Windows RDP.",
            "✅ Windows RDP 接続テストを発報しました。");
    }

    private async void SimProcessButton_Click(object sender, RoutedEventArgs e)
    {
        await _mainWindow.TriggerSimProcessesAsync();
        TestActionStatusText.Text = Loc.T(
            "✅ Injected simulated data for 0.3s flash terminal (280ms, Task Scheduler) + periodic process (45s cycle) + unknown unsigned process.",
            "✅ 已注入 0.3 秒瞬时终端（280ms·计划任务启动）+ 周期进程（45秒周期）+ 未知未签名进程的模拟测试数据。",
            "✅ Se inyectaron datos simulados de terminal fugaz de 0.3s (280ms) + proceso periódico (ciclo de 45s) + proceso desconocido sin firmar.",
            "✅ 0.3秒で消える瞬間ターミナル (280ms・タスクスケジューラ起動) ＋ 周期プロセス (45秒周期) ＋ 未知未署名プロセスのテストデータを注入しました。");
    }

    private async void SimDefenseButton_Click(object sender, RoutedEventArgs e)
    {
        await _mainWindow.TriggerSimSystemDefenseAsync();
        TestActionStatusText.Text = Loc.T(
            "✅ Injected System Defense simulations (obfuscated command, autostart, webcam spy, DLL sideload, keylogger, BadUSB, root cert, admin added).",
            "✅ 已向系统防御选项卡注入混淆命令、自启动、摄像头偷拍、DLL侧加载、键盘记录、BadUSB、根证书及管理员添加的模拟数据。",
            "✅ Se inyectaron simulaciones en Defensa del Sistema (comando ofuscado, autoinicio, cámara, DLL sideload, keylogger, BadUSB, certificado raíz, admin).",
            "✅ システム防御タブに難読化コマンド・自動起動・カメラ盗撮・DLLサイドロード・キーロガー・BadUSB・ルート証明書・管理者追加のテストデータを注入しました。");
    }

    private async void ClearSimButton_Click(object sender, RoutedEventArgs e)
    {
        await _mainWindow.ClearAllSimulationsAsync();
        TestActionStatusText.Text = Loc.T(
            "🧹 Cleared all simulated alerts and test data.",
            "🧹 已清除所有模拟警报与测试数据。",
            "🧹 Se limpiaron todas las alertas y datos de simulación.",
            "🧹 すべてのテスト警報・テストデータを解除しました。");
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
