using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Navigation;
using AnzenSecurityWatcher.Services;
using Clipboard = System.Windows.Clipboard;
using MessageBox = System.Windows.MessageBox;

namespace AnzenSecurityWatcher;

public partial class AboutWindow : Window
{
    private readonly string _versionString;
    private readonly string _frameworkString;
    private readonly string _osString;
    private readonly string _archString;
    private readonly bool _isAdmin;

    public AboutWindow()
    {
        InitializeComponent();

        // 1. バージョン情報の取得
        var asm = Assembly.GetExecutingAssembly();
        var version = asm.GetName().Version;
        string fullVersion;

        if (version != null)
        {
            fullVersion = version.ToString();
            _versionString = (version.Revision > 0)
                ? $"{version.Major}.{version.Minor}.{version.Build}.{version.Revision}"
                : $"{version.Major}.{version.Minor}.{version.Build}";
        }
        else
        {
            _versionString = "1.0.0";
            fullVersion = "1.0.0.0";
        }

        // InformationalVersion 属性（セマンティックバージョン）があれば反映
        try
        {
            var infoVerAttr = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>();
            if (infoVerAttr?.InformationalVersion is { Length: > 0 } rawInfo)
            {
                int plusIdx = rawInfo.IndexOf('+');
                string cleanInfo = plusIdx >= 0 ? rawInfo[..plusIdx] : rawInfo;
                if (!string.IsNullOrWhiteSpace(cleanInfo))
                {
                    _versionString = cleanInfo;
                }
            }
        }
        catch { }

        VersionBadgeText.Text = $"v{_versionString}";
        FullVersionText.Text = fullVersion;

        // アイコンの確実な読み込みフォールバック
        LoadAppIconSafely();

        // 2. ランタイム & OS 情報の取得
        _frameworkString = RuntimeInformation.FrameworkDescription;
        _osString = RuntimeInformation.OSDescription;
        _archString = $"{RuntimeInformation.ProcessArchitecture} ({(Environment.Is64BitProcess ? "64-bit" : "32-bit")})";

        DotNetRuntimeText.Text = _frameworkString;
        OsDescriptionText.Text = _osString;
        ArchitectureText.Text = _archString;

        // 3. 管理者権限の判定
        _isAdmin = CheckIsAdministrator();
        UpdatePrivilegeText();

        // 言語変更イベントに追従
        LocalizationManager.OnLanguageChanged += OnLanguageChanged;
        Closed += (_, _) => LocalizationManager.OnLanguageChanged -= OnLanguageChanged;
    }

    private void OnLanguageChanged(AppLanguage _)
    {
        Dispatcher.Invoke(UpdatePrivilegeText);
    }

    private void UpdatePrivilegeText()
    {
        string adminText = LocalizationManager.GetString("Loc_About_PrivilegeAdmin", "Administrator (Elevated)");
        string userText = LocalizationManager.GetString("Loc_About_PrivilegeUser", "Standard User");
        PrivilegeLevelText.Text = _isAdmin ? $"🛡️ {adminText}" : $"👤 {userText}";
    }

    private static bool CheckIsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private void GitHubHyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
            e.Handled = true;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to open link:\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void CopyInfoButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== Anzen Security Watcher Environment Info ===");
            sb.AppendLine($"App Version     : v{_versionString} ({FullVersionText.Text})");
            sb.AppendLine($".NET Runtime    : {_frameworkString}");
            sb.AppendLine($"Operating System: {_osString}");
            sb.AppendLine($"Architecture    : {_archString}");
            sb.AppendLine($"Privilege       : {(_isAdmin ? "Administrator (Elevated)" : "Standard User")}");
            sb.AppendLine($"Current Language: {LocalizationManager.CurrentLanguage}");
            sb.AppendLine($"Current Theme   : {ThemeManager.CurrentMode}");
            sb.AppendLine($"Repository      : https://github.com/sdozono/Anzen-Security-Watcher");
            sb.AppendLine("================================================");

            Clipboard.SetText(sb.ToString());
            MessageBox.Show(
                LocalizationManager.GetString("Loc_About_Copied", "System information copied to clipboard!"),
                LocalizationManager.GetString("Loc_About_Title", "About Anzen Security Watcher"),
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Clipboard copy failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void LoadAppIconSafely()
    {
        try
        {
            // pack URI で既に読み込めているか確認
            if (AppIconImage.Source != null) return;

            // ローカルファイル Assets/app.ico からの読み込み
            string localIco = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "app.ico");
            if (System.IO.File.Exists(localIco))
            {
                var uri = new Uri(localIco, UriKind.Absolute);
                AppIconImage.Source = new System.Windows.Media.Imaging.BitmapImage(uri);
                Icon = AppIconImage.Source;
            }
        }
        catch
        {
            // フォールバックの 🛡️ 絵文字が表示されるため例外は無視
        }
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
