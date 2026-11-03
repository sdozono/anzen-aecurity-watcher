using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Controls;
using AnzenSecurityWatcher.Models;
using AnzenSecurityWatcher.Services;
using Clipboard = System.Windows.Clipboard;
using MessageBox = System.Windows.MessageBox;

namespace AnzenSecurityWatcher;

public partial class IpLookupWindow : Window
{
    private static readonly (string Name, string UrlFormat)[] AllServiceDefinitions =
    {
        ("AbuseIPDB", "https://www.abuseipdb.com/check/{0}"),
        ("GreyNoise", "https://viz.greynoise.io/ip/{0}"),
        ("VirusTotal Public API", "https://www.virustotal.com/gui/ip-address/{0}"),
        ("LevelBlue OTX", "https://otx.alienvault.com/indicator/ip/{0}"),
        ("Spamhaus", "https://check.spamhaus.org/query/ip/{0}"),
        ("Cisco Talos Reputation Center", "https://talosintelligence.com/reputation_center/lookup?search={0}"),
        ("Censys", "https://search.censys.io/hosts/{0}")
    };

    public IpLookupWindow(NetworkConnectionItem item)
        : this(item?.RemoteAddress ?? "", item)
    {
    }

    public IpLookupWindow(string targetIp, NetworkConnectionItem? item = null)
    {
        InitializeComponent();

        // ポート番号などの付随文字列を除去して純粋なIPを抽出
        string cleanIp = CleanIpAddress(targetIp);
        TargetIpTextBox.Text = cleanIp;

        if (item != null)
        {
            ConnectionInfoPanel.Visibility = Visibility.Visible;
            CountryInfoText.Text = string.IsNullOrWhiteSpace(item.CountryDisplay) ? "🌐 Unknown" : item.CountryDisplay;
            OrgInfoText.Text = string.IsNullOrWhiteSpace(item.Organization) ? "🏢 Org: -" : $"🏢 {item.Organization}";
            ProcessInfoText.Text = string.IsNullOrWhiteSpace(item.ProcessName) ? "⚙️ Process: -" : $"⚙️ {item.ProcessName} (PID:{item.ProcessId})";
            PortInfoText.Text = $"🔌 {item.Protocol} {item.RemotePort}";
        }

        UpdateWarningVisibility();
    }

    private static string CleanIpAddress(string? rawIp)
    {
        if (string.IsNullOrWhiteSpace(rawIp)) return "";
        string trimmed = rawIp.Trim();

        // "192.168.1.1:8080" のようなコロン＋ポート表記への対応
        if (trimmed.Contains(':') && !trimmed.Contains("::") && IPAddress.TryParse(trimmed.Split(':')[0], out var ipv4))
        {
            return ipv4.ToString();
        }

        // "[fe80::1]:8080" のようなIPv6ブラケット表記への対応
        if (trimmed.StartsWith('[') && trimmed.Contains(']'))
        {
            int closeBracket = trimmed.IndexOf(']');
            return trimmed.Substring(1, closeBracket - 1);
        }

        return trimmed;
    }

    private void TargetIpTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        UpdateWarningVisibility();
    }

    private void UpdateWarningVisibility()
    {
        if (PrivateIpWarningBorder == null) return;

        string ip = TargetIpTextBox.Text.Trim();
        bool isPrivate = IsPrivateOrLocalAddress(ip);
        PrivateIpWarningBorder.Visibility = isPrivate ? Visibility.Visible : Visibility.Collapsed;
    }

    public static bool IsPrivateOrLocalAddress(string ipStr)
    {
        if (string.IsNullOrWhiteSpace(ipStr) || ipStr == "*" || ipStr == "0.0.0.0")
            return true;

        if (!IPAddress.TryParse(ipStr, out var ip))
            return false;

        if (IPAddress.IsLoopback(ip))
            return true;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] bytes = ip.GetAddressBytes();
            // 10.0.0.0/8
            if (bytes[0] == 10) return true;
            // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            // 169.254.0.0/16 (Link Local / APIPA)
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            // 0.0.0.0 or 255.255.255.255
            if (bytes[0] == 0 || (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255)) return true;
        }
        else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return true;
            byte[] bytes = ip.GetAddressBytes();
            // Unique Local Address (fc00::/7)
            if ((bytes[0] & 0xFE) == 0xFC) return true;
        }

        return false;
    }

    private void CopyIpButton_Click(object sender, RoutedEventArgs e)
    {
        string ip = TargetIpTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(ip)) return;

        try
        {
            Clipboard.SetText(ip);
            SetStatusMessage(Loc.T(
                $"📋 Copied: {ip}",
                $"📋 已复制: {ip}",
                $"📋 Copiado: {ip}",
                $"📋 IPをコピーしました: {ip}"));
        }
        catch (Exception ex)
        {
            SetStatusMessage($"❌ Error: {ex.Message}");
        }
    }

    private void OpenServiceUrl(string serviceName, string urlFormat)
    {
        string ip = TargetIpTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(ip) || ip == "*")
        {
            MessageBox.Show(
                this,
                Loc.T("Please enter a valid IP address.", "请输入有效的 IP 地址。", "Por favor, introduzca una dirección IP válida.", "有効なIPアドレスを入力してください。"),
                "Notice", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        string escaped = Uri.EscapeDataString(ip);
        string url = string.Format(urlFormat, escaped);
        LaunchBrowser(url, serviceName);
    }

    private void LaunchBrowser(string url, string serviceName)
    {
        if (string.IsNullOrWhiteSpace(url)) return;

        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            SetStatusMessage(Loc.T(
                $"🌐 Opened {serviceName} in browser",
                $"🌐 已在浏览器中打开 {serviceName}",
                $"🌐 Abierto {serviceName} en el navegador",
                $"🌐 ブラウザで {serviceName} を開きました"));
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                this,
                Loc.T($"Failed to launch browser:\n{ex.Message}",
                      $"无法打开浏览器:\n{ex.Message}",
                      $"Error al abrir el navegador:\n{ex.Message}",
                      $"ブラウザを起動できませんでした:\n{ex.Message}"),
                "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // 1. AbuseIPDB
    private void AbuseIpDbButton_Click(object sender, RoutedEventArgs e)
        => OpenServiceUrl("AbuseIPDB", "https://www.abuseipdb.com/check/{0}");

    // 2. GreyNoise
    private void GreyNoiseButton_Click(object sender, RoutedEventArgs e)
        => OpenServiceUrl("GreyNoise", "https://viz.greynoise.io/ip/{0}");

    // 3. VirusTotal Public API
    private void VirusTotalButton_Click(object sender, RoutedEventArgs e)
        => OpenServiceUrl("VirusTotal", "https://www.virustotal.com/gui/ip-address/{0}");

    // 4. LevelBlue OTX
    private void LevelBlueOtxButton_Click(object sender, RoutedEventArgs e)
        => OpenServiceUrl("LevelBlue OTX", "https://otx.alienvault.com/indicator/ip/{0}");

    // 5. Spamhaus
    private void SpamhausButton_Click(object sender, RoutedEventArgs e)
        => OpenServiceUrl("Spamhaus", "https://check.spamhaus.org/query/ip/{0}");

    // 6. Cisco Talos Reputation Center
    private void CiscoTalosButton_Click(object sender, RoutedEventArgs e)
        => OpenServiceUrl("Cisco Talos", "https://talosintelligence.com/reputation_center/lookup?search={0}");

    // 7. Censys
    private void CensysButton_Click(object sender, RoutedEventArgs e)
        => OpenServiceUrl("Censys", "https://search.censys.io/hosts/{0}");

    // 一括オープン
    private void OpenAllServicesButton_Click(object sender, RoutedEventArgs e)
    {
        string ip = TargetIpTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(ip) || ip == "*")
        {
            MessageBox.Show(
                this,
                Loc.T("Please enter a valid IP address.", "请输入有效的 IP 地址。", "Por favor, introduzca una dirección IP válida.", "有効なIPアドレスを入力してください。"),
                "Notice", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var result = MessageBox.Show(
            this,
            Loc.T("Open all 7 threat intelligence services in your default browser at once?",
                  "确定要在默认浏览器中一次性打开全部 7 个威胁情报服务页面吗？",
                  "¿Abrir los 7 servicios de inteligencia de amenazas simultáneamente en el navegador predeterminado?",
                  "7つの脅威インテリジェンスサービスの検索ページをデフォルトブラウザで一斉に開きますか？"),
            "Open All Services",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes) return;

        string escaped = Uri.EscapeDataString(ip);
        int opened = 0;
        foreach (var svc in AllServiceDefinitions)
        {
            try
            {
                string url = string.Format(svc.UrlFormat, escaped);
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
                opened++;
            }
            catch { }
        }

        SetStatusMessage(Loc.T(
            $"🚀 Opened {opened} services in browser",
            $"🚀 已在浏览器中打开 {opened} 个服务页面",
            $"🚀 Se abrieron {opened} servicios en el navegador",
            $"🚀 {opened}件のサービスページをブラウザで開きました"));
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void SetStatusMessage(string msg)
    {
        StatusMessageText.Text = msg;
    }
}
