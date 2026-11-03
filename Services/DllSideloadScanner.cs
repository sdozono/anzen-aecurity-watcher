using System.Diagnostics;
using System.IO;
using AnzenSecurityWatcher.Models;

namespace AnzenSecurityWatcher.Services;

/// <summary>
/// DLL サイドローディング検知スキャナ
/// 「デジタル署名付きの正規 EXE と同じフォルダに、デジタル署名のない DLL が置かれている（または読み込まれている）」
/// という APT / マルウェアの代表的な永続化・防衛回避手法（DLL Side-Loading / DLL Hijacking）を検知する。
/// </summary>
public class DllSideloadScanner
{
    private readonly List<FindingReport> _cachedReports = new();
    private DateTime _lastFullScan = DateTime.MinValue;
    private AppLanguage _lastLang = AppLanguage.English;

    public List<FindingReport> Scan(bool forceRefresh = false)
    {
        // I/O 負荷を抑えるため 30 秒周期で更新（ただし言語切替や強制更新時は即時再構築）
        if (!forceRefresh &&
            _lastLang == LocalizationManager.CurrentLanguage &&
            (DateTime.Now - _lastFullScan).TotalSeconds < 30 &&
            _cachedReports.Count > 0)
        {
            return _cachedReports.ToList();
        }

        _lastFullScan = DateTime.Now;
        _lastLang = LocalizationManager.CurrentLanguage;
        var reports = new List<FindingReport>();
        var scannedPairs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        Process[] procs;
        try { procs = Process.GetProcesses(); }
        catch { return reports; }

        try
        {
            foreach (var p in procs)
            {
                try
                {
                    int pid = p.Id;
                    if (pid <= 4) continue;

                    string exePath = NativeSecurity.QueryProcessImagePath(pid);
                    if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath)) continue;

                    // Windows 標準フォルダ (C:\Windows\...) および Program Files 配下（管理者権限保護領域）は除外し、
                    // 実際の DLL サイドローディング攻撃が発生するユーザー書き込み可能領域・非標準フォルダを対象とする
                    if (PathHelper.IsWindowsLocation(exePath) || PathHelper.IsProgramFilesLocation(exePath))
                        continue;

                    // 自己プロセスは除外
                    if (ProcessMonitorService.CheckIsSelfProcess(pid, p.ProcessName, exePath)) continue;

                    var (exeSigned, exeSigner) = SignatureHelper.Check(exePath);
                    // DLL サイドローディングの本質は「署名付きの信頼された EXE が未署名 DLL をロードする」こと
                    if (!exeSigned) continue;

                    string? dir = Path.GetDirectoryName(exePath);
                    if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;

                    bool inUserWritable = PathHelper.IsUserWritableLocation(dir);

                    // 1. まず同一ディレクトリ内の未署名 DLL を検査 (最大 35 ファイルまで高速チェック)
                    string[] dllFiles;
                    try
                    {
                        dllFiles = Directory.GetFiles(dir, "*.dll", SearchOption.TopDirectoryOnly);
                    }
                    catch { continue; }

                    foreach (var dll in dllFiles.Take(35))
                    {
                        var (dllSigned, _) = SignatureHelper.Check(dll);
                        if (dllSigned) continue;

                        string pairKey = $"{exePath.ToLowerInvariant()}|{dll.ToLowerInvariant()}";
                        if (!scannedPairs.Add(pairKey)) continue;

                        // ユーザー書き込み可能フォルダ (AppData / Temp / Downloads / Public) での署名EXE + 未署名DLL は極めて危険
                        var risk = PathHelper.IsHighRiskTempLocation(dir) ? RiskLevel.Critical
                                 : inUserWritable ? RiskLevel.High
                                 : RiskLevel.Medium;

                        string dllName = Path.GetFileName(dll);
                        string title = Loc.T(
                            $"🧩 [DLL Sideloading] {p.ProcessName} + Unsigned {dllName}",
                            $"🧩 [DLL 侧加载隐患] {p.ProcessName} + 未签名 {dllName}",
                            $"🧩 [DLL Sideloading] {p.ProcessName} + {dllName} sin firmar",
                            $"🧩 [DLLサイドロード懸念] {p.ProcessName} + 未署名 {dllName}");

                        string detail = Loc.T(
                            $"Unsigned DLL ({dllName}) placed in the same folder as signed EXE ({exeSigner}) — {dir}",
                            $"未签名 DLL ({dllName}) 与已签名 EXE ({exeSigner}) 位于同一文件夹中 — {dir}",
                            $"DLL sin firmar ({dllName}) ubicada en la misma carpeta que EXE firmado ({exeSigner}) — {dir}",
                            $"署名付きEXE ({exeSigner}) と同一フォルダに未署名DLL ({dllName}) が配置されています — {dir}");

                        string folderKind = inUserWritable
                            ? Loc.T("User-writable folder (High risk)", "用户可写目录 (高风险)", "Carpeta escribible por el usuario (Alto riesgo)", "ユーザー書き込み可能領域 (高リスク)")
                            : Loc.T("Application folder", "应用程序文件夹", "Carpeta de aplicación", "アプリケーションフォルダ");

                        string tech = Loc.T(
                            $"Host Process: {p.ProcessName} (PID: {pid})\nHost EXE Path: {exePath}\nHost EXE Signature: Signed ({exeSigner})\nUnsigned DLL Path: {dll}\nFolder Type: {folderKind}\nReason: Matches the 'DLL Sideloading' pattern where an unsigned DLL is placed in the same directory as a legitimate signed executable.",
                            $"宿主进程: {p.ProcessName} (PID: {pid})\n宿主 EXE 路径: {exePath}\n宿主 EXE 签名: 有 ({exeSigner})\n未签名 DLL 路径: {dll}\n所在目录类型: {folderKind}\n判定原因: 符合将未签名同名 DLL 放置在正规已签名可执行文件同一目录中以诱导加载的“DLL 侧加载”模式。",
                            $"Proceso host: {p.ProcessName} (PID: {pid})\nRuta EXE host: {exePath}\nFirma EXE host: Firmado ({exeSigner})\nRuta DLL sin firmar: {dll}\nTipo de carpeta: {folderKind}\nMotivo: Coincide con el patrón de 'DLL Sideloading' donde se coloca una DLL sin firmar junto a un ejecutable firmado legítimo.",
                            $"ホストプロセス: {p.ProcessName} (PID: {pid})\nホストEXEパス: {exePath}\nホストEXE署名: あり ({exeSigner})\n未署名DLLパス: {dll}\n配置フォルダ種別: {folderKind}\n検知理由: 正規の署名付き実行ファイルと同じフォルダにデジタル署名のない同名DLLを配置して読み込ませる『DLLサイドローディング』のパターンに一致しました。");

                        string recAction = Loc.T(
                            "Unless this is a custom plugin under development, an unsigned DLL in a legitimate software folder may indicate a DLL sideloading attack. Verify the DLL's hash and creation timestamp.",
                            "除非是正在开发的自定义插件，否则在正规软件目录中混入未签名 DLL 可能意味着 DLL 侧加载攻击。请检查该 DLL 的哈希值与创建时间。",
                            "A menos que sea un plugin propio en desarrollo, una DLL sin firmar en la carpeta de un software legítimo puede indicar un ataque de DLL sideloading. Verifique el hash y la fecha de creación de la DLL.",
                            "開発中の独自プラグイン等でない限り、正規ソフトのフォルダに未署名DLLが混入している場合はDLLサイドローディング攻撃の疑いがあります。DLLのハッシュ値や作成日時を確認してください。");

                        reports.Add(new FindingReport(
                            Key: $"SIDELOAD:{pairKey}",
                            Category: FindingCategory.DllSideload,
                            Severity: risk,
                            State: FindingState.Active,
                            Title: title,
                            Detail: detail,
                            Target: dll,
                            TechnicalDetails: tech,
                            RecommendedAction: recAction,
                            OpenLocationPath: dll,
                            ProcessId: pid));
                    }
                }
                catch { }
                finally
                {
                    try { p.Dispose(); } catch { }
                }
            }
        }
        finally
        {
            foreach (var p in procs)
            {
                try { p.Dispose(); } catch { }
            }
        }

        _cachedReports.Clear();
        _cachedReports.AddRange(reports);
        return reports;
    }
}
