using System.IO;
using System.Text;
using System.Windows;
using AnzenSecurityWatcher.Services;

namespace AnzenSecurityWatcher;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        if (e.Args.Any(a => a.Equals("--self-test", StringComparison.OrdinalIgnoreCase)))
        {
            RunHeadlessSelfTest();
            Shutdown(0);
            Environment.Exit(0);
            return;
        }

        // 保存されたユーザー設定を読み込み、テーマと表示言語を適用
        SettingsManager.Load();
        ThemeManager.ApplyTheme(SettingsManager.Current.ThemeMode);
        LocalizationManager.ApplyLanguage(SettingsManager.Current.Language);
        base.OnStartup(e);
    }

    private static void RunHeadlessSelfTest()
    {
        var sb = new StringBuilder();
        var geo = new GeoIpService();
        var net = new NetworkMonitorService(geo);
        var conns = net.ScanActiveConnections(false, false, true);
        int tcp = conns.Count(c => c.Protocol == "TCP");
        int udp = conns.Count(c => c.Protocol == "UDP");
        int ipv6Tcp = conns.Count(c => c.Protocol == "TCP" && (c.RemoteAddress.Contains(':') || c.LocalAddress.Contains(':')));
        int ipv6Udp = conns.Count(c => c.Protocol == "UDP" && c.LocalAddress.Contains(':'));
        sb.AppendLine($"[1] NetworkMonitorService: Total={conns.Count} (TCP={tcp} [IPv6={ipv6Tcp}], UDP={udp} [IPv6={ipv6Udp}])");

        var cmdRes = CommandLineAnalyzer.Analyze(
            "powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
            "powershell",
            "WINWORD");
        sb.AppendLine($"[2] CommandLineAnalyzer: Risk={cmdRes.Risk}, Decoded='{cmdRes.DecodedPayload}', Reasons='{cmdRes.ReasonText}'");

        var procSvc = new ProcessMonitorService();
        var procs = procSvc.ScanProcesses();
        sb.AppendLine($"[3] ProcessMonitorService: Total={procs.Count}, WithCommandLine={procs.Count(p => !string.IsNullOrEmpty(p.CommandLine))}");

        var defSvc = new SystemDefenseService();
        var (findings, posture) = defSvc.ScanAll(true);
        sb.AppendLine($"[4] SecurityPostureService: Score={posture.Score}/100 (Grade={posture.Grade} - {posture.GradeComment})");
        foreach (var c in posture.Checks)
            sb.AppendLine($"    - {c.ResultBadge} [{c.WeightText}] {c.Name}: {c.StatusText}");

        sb.AppendLine($"[5] SystemDefenseService Findings: Total={findings.Count}");
        foreach (var grp in findings.GroupBy(f => f.Category))
            sb.AppendLine($"    - {grp.Key}: {grp.Count()} 件");

        // [6] SettingsManager 保存・読み込みテスト
        var origLang = SettingsManager.Current.Language;
        SettingsManager.Current.Language = AppLanguage.Japanese;
        SettingsManager.Save();
        SettingsManager.Load();
        bool settingsOk = SettingsManager.Current.Language == AppLanguage.Japanese;
        SettingsManager.Current.Language = origLang;
        SettingsManager.Save();
        sb.AppendLine($"[6] SettingsManager: PersistenceTest={(settingsOk ? "OK" : "FAILED")}");

        // [7] トークン伏せ字化・ストアアプリ署名・RunOnce・タスク紐付け精度テスト
        string testCmd = @"mytool.exe --token secret12345 --password ""mypassword99"" -apikey AKIA1234567890ABCDEF bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThis";
        string maskedCmd = CommandLineAnalyzer.MaskSensitiveArguments(testCmd);
        bool maskOk = !maskedCmd.Contains("secret12345") && !maskedCmd.Contains("mypassword99") && !maskedCmd.Contains("ABCDEF") && maskedCmd.Contains("***");
        sb.AppendLine($"[7] SensitiveTokenMasking: {(maskOk ? "PASS" : "FAILED")} (Masked='{maskedCmd}')");

        string winAppPath = @"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.18.3181.0_x64__8wekyb3d8bbwe\wt.exe";
        bool isWinAppsLoc = PathHelper.IsWindowsAppsLocation(winAppPath);
        var appxSig = AppxPackageSignatureHelper.CheckAppxSignature(winAppPath);
        sb.AppendLine($"[8] AppxPackageSignatureCheck: {(isWinAppsLoc && appxSig.IsSigned ? "PASS" : "FAILED")} (Signer='{appxSig.Signer}', Reason='{appxSig.Reason}')");

        string runonceParent = NativeSecurity.DescribeParentOrigin(1234, "runonce.exe", "runonce.exe Run6432");
        bool runonceOk = runonceParent.Contains("32-bit") || runonceParent.Contains("32位") || runonceParent.Contains("32bit");
        sb.AppendLine($"[9] RunOnceParentOriginCheck: {(runonceOk ? "PASS" : "FAILED")} (Display='{runonceParent}')");

        string reportPath = Path.Combine(JsonStore.DataDir, "selftest_report.txt");
        Directory.CreateDirectory(JsonStore.DataDir);
        File.WriteAllText(reportPath, sb.ToString(), Encoding.UTF8);
    }
}
