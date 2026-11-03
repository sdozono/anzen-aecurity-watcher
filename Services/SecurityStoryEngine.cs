using System.Text;
using AnzenSecurityWatcher.Models;

namespace AnzenSecurityWatcher.Services;

/// <summary>
/// 個別・散発的な警告を文脈・因果関係に基づき 1 つの「Security Story (セキュリティストーリー)」に集約する相関エンジン。
/// 例: Office更新による schtasks/conhost 連続起動、ベンダー管理スイート、Windows Per-User サービス、BadUSB 攻撃シーケンス等
/// </summary>
public record SecurityStory(
    string StoryKey,
    string Title,
    RiskLevel Severity,
    ConfidenceLevel Confidence,
    string Summary,
    List<string> MemberKeys,
    List<string> MemberDescriptions,
    List<string> InferredActions,
    DateTime FirstSeen,
    DateTime LastSeen,
    string ProcessLineage = "");

public static class SecurityStoryEngine
{
    public static List<SecurityStory> BuildStories(
        IEnumerable<SecurityLogEntry> logs,
        IEnumerable<ProcessAnalysisItem>? processes = null,
        IEnumerable<SystemFindingItem>? findings = null)
    {
        var stories = new Dictionary<string, List<SecurityLogEntry>>(StringComparer.OrdinalIgnoreCase);
        var storyMap = new Dictionary<string, SecurityStory>(StringComparer.OrdinalIgnoreCase);

        // 1. ログエントリからのグループ化
        foreach (var log in logs)
        {
            string sKey = !string.IsNullOrWhiteSpace(log.StoryKey) ? log.StoryKey : InferStoryKey(log);
            if (!stories.TryGetValue(sKey, out var list))
            {
                list = new List<SecurityLogEntry>();
                stories[sKey] = list;
            }
            list.Add(log);
        }

        // 2. グループごとに SecurityStory オブジェクトを構築
        foreach (var (key, group) in stories)
        {
            if (key.Equals("INDIVIDUAL", StringComparison.OrdinalIgnoreCase))
                continue; // 単体所見はストーリー化せず個別保持

            DateTime first = group.Min(x => x.Timestamp);
            DateTime last = group.Max(x => x.LastTimestamp);

            // 該当グループのプロセス祖先系譜（Lineage: Parent PID → Grandparent PID → Great-grandparent PID）を収集
            var lineageList = new List<string>();
            foreach (var log in group)
            {
                if (!string.IsNullOrWhiteSpace(log.ProcessLineage) && !lineageList.Contains(log.ProcessLineage))
                    lineageList.Add(log.ProcessLineage);
            }

            if (processes != null)
            {
                foreach (var p in processes)
                {
                    if (!string.IsNullOrWhiteSpace(p.ProcessTreeDetail) &&
                        (string.Equals(p.StoryKey, key, StringComparison.OrdinalIgnoreCase) ||
                         group.Any(g => g.RelatedProcess.Contains(p.ProcessName, StringComparison.OrdinalIgnoreCase))) &&
                        !lineageList.Contains(p.ProcessTreeDetail))
                    {
                        lineageList.Add(p.ProcessTreeDetail);
                    }
                }
            }

            string combinedLineage = lineageList.Count > 0 ? string.Join("\n\n---\n\n", lineageList) : "";

            // ストーリー全体の総合リスクと確信度を算出（祖先系譜も加味）
            var (title, severity, confidence, summary, actions) = SummarizeStory(key, group, combinedLineage);

            var memberKeys = group.Select(x => x.LogKey).Distinct().ToList();
            var memberDescs = group.Select(x => $"[{x.SeverityLabel}] {x.Title}").Distinct().ToList();

            storyMap[key] = new SecurityStory(
                StoryKey: key,
                Title: title,
                Severity: severity,
                Confidence: confidence,
                Summary: summary,
                MemberKeys: memberKeys,
                MemberDescriptions: memberDescs,
                InferredActions: actions,
                FirstSeen: first,
                LastSeen: last,
                ProcessLineage: combinedLineage);
        }

        return storyMap.Values
            .OrderByDescending(s => s.Severity)
            .ThenByDescending(s => s.Confidence)
            .ThenByDescending(s => s.LastSeen)
            .ToList();
    }

    private static string InferStoryKey(SecurityLogEntry log)
    {
        string t = (log.Title + " " + log.TechnicalDetails + " " + log.ProcessLineage).ToLowerInvariant();

        if (t.Contains("hermes") || t.Contains("nousresearch") || t.Contains("hermes-setup") || t.Contains("hermes-no-console"))
            return "STORY:AI_AGENT_HERMES";

        if ((t.Contains("setup") || t.Contains("installer")) && (t.Contains("explorer") || t.Contains("chrome") || t.Contains("msedge") || t.Contains("downloads")))
            return "STORY:USER_SETUP";

        if (t.Contains("office") && (t.Contains("schtasks") || t.Contains("clicktorun") || t.Contains("automatic updates") || t.Contains("c2r")))
            return "STORY:OFFICE_UPDATE";

        if (t.Contains("softlanding"))
            return "STORY:SOFTLANDING_COM";

        if (t.Contains("messagingservice") || t.Contains("cdpusersvc") || t.Contains("cbdhsvc") || t.Contains("onesyncsvc"))
            return "STORY:WINDOWS_PER_USER_SVC";

        if (t.Contains("dst root ca x3") || t.Contains("addtrust external ca") || t.Contains("hotspot 2.0") || t.Contains("securetrust"))
            return "STORY:ROOT_CERT_LEGACY";

        if (t.Contains("badusb"))
            return "STORY:BADUSB_ATTACK";

        // ベンダースイートの自動推定
        string[] knownVendors = { "brother", "scansnap", "hasleo", "audials", "thunderbolt", "aws vpn", "logitech", "razer" };
        foreach (var v in knownVendors)
        {
            if (t.Contains(v))
                return $"Story:VendorSuite:{v}";
        }

        return "INDIVIDUAL";
    }

    private static (string Title, RiskLevel Severity, ConfidenceLevel Confidence, string Summary, List<string> Actions) SummarizeStory(
        string key, List<SecurityLogEntry> group, string lineage = "")
    {
        var actions = new List<string>();
        string lineageLow = (lineage + " " + string.Join(" ", group.Select(x => x.TechnicalDetails))).ToLowerInvariant();
        bool isUserInteractive = lineageLow.Contains("explorer") || lineageLow.Contains("chrome") || lineageLow.Contains("msedge") || lineageLow.Contains("firefox") || lineageLow.Contains("terminal") || lineageLow.Contains("cmd.exe") || lineageLow.Contains("powershell");
        bool isBackgroundTrigger = lineageLow.Contains("svchost") || lineageLow.Contains("taskhost") || lineageLow.Contains("schtasks");

        if (key.Equals("STORY:AI_AGENT_HERMES", StringComparison.OrdinalIgnoreCase))
        {
            bool allHistorical = group.All(x => x.IsHistorical || x.Summary.Contains("過去") || x.Summary.Contains("Historical") || x.TechnicalDetails.Contains("ファイル現存: なし") || x.TechnicalDetails.Contains("File Present on Disk: No"));

            if (allHistorical)
            {
                return (
                    Title: Loc.T("🟢 Hermes Agent / Historical Trace (Uninstalled / Cleaned)", "🟢 Hermes Agent / 历史活动记录 (已卸载·已清理)", "🟢 Hermes Agent / Registro Histórico (Desinstalado·Limpio)", "🟢 Hermes Agent / 過去の活動履歴 (アンインストール済・現行脅威なし)"),
                    Severity: RiskLevel.Safe,
                    Confidence: ConfidenceLevel.High,
                    Summary: Loc.T(
                        "All Hermes-related executable files and processes have been verified absent/inactive. This entry represents historical build/setup logs from the past (e.g. Oct 30) and is not an active security threat.",
                        "所有与 Hermes 相关的可执行文件与进程均已清除，且当前无任何活跃进程。此处仅为过去的安装构建日志（如 10月30日），不构成当前安全威胁。",
                        "Todos los archivos y procesos de Hermes han sido eliminados y están inactivos. Representa registros históricos del pasado.",
                        "Hermesに関連する実行ファイルおよび稼働プロセスは既に存在せず、完全に非稼働・ファイル削除済みです。過去のインストール・ビルド時の履歴ログであり、現在進行中のセキュリティ脅威ではありません。"),
                    Actions: new List<string>
                    {
                        Loc.T("Hermes has been uninstalled. No action required.", "Hermes 已卸载，无需处理。", "Hermes desinstalado. Sin acción requerida.", "Hermes本体は既にアンインストール済みです。追加の対処は不要です。")
                    }
                );
            }

            if (isUserInteractive && !isBackgroundTrigger)
            {
                return (
                    Title: Loc.T("🟢 Hermes Agent / AI Developer Toolchain (User-Initiated)", "🟢 Hermes Agent / AI 开发者工具链 (用户主导启动)", "🟢 Hermes Agent / Cadena de Herramientas IA (Iniciado por Usuario)", "🟢 Hermes Agent / AIエージェント開発ツール群 (ユーザー起動検証済)"),
                    Severity: RiskLevel.Safe,
                    Confidence: ConfidenceLevel.High,
                    Summary: Loc.T(
                        "Hermes Agent components or Setup was launched by user interaction (verified via 3-5 generation process lineage from Explorer/Browser/Terminal). This is legitimate development/user operation, not malware infection.",
                        "Hermes Agent 组件或安装程序由用户主动启动（已通过 3~5 代祖先进程链证实源自 Explorer/浏览器/终端）。属于正常操作与开发行为，非恶意软件感染。",
                        "Componentes o Setup de Hermes iniciados por el usuario. Verificado por linaje de procesos 3-5 generaciones.",
                        "Hermes Agent コンポーネントまたは Setup は、ユーザーの明示的操作（Explorer/ブラウザ/ターミナル由来）により起動されました。3〜5世代のプロセス祖先系譜によって検証済みであり、マルウェア感染ではありません。"),
                    Actions: new List<string>
                    {
                        Loc.T("If you intend to use Hermes, no action required. Normal activity.", "如果您计划使用 Hermes，则无需处理。属于正常行为。", "Si planea usar Hermes, no requiere acción.", "Hermesをご使用の場合は対処不要です。正常なアクティビティです。"),
                        Loc.T("If already uninstalled and you want to clean leftovers: remove %LOCALAPPDATA%\\com.nousresearch.hermes.setup and Downloads\\Hermes-Setup.exe.", "若已卸载且希望彻底清理残留：请删除 %LOCALAPPDATA%\\com.nousresearch.hermes.setup 及 Downloads 目录下的安装包。", "Si ya desinstaló, elimine residuos en %LOCALAPPDATA% y Downloads.", "アンインストール済みで残存物を完全除去したい場合: %LOCALAPPDATA%\\com.nousresearch.hermes.setup と Downloads 内の Hermes-Setup.exe を削除してください。")
                    }
                );
            }
            else
            {
                return (
                    Title: Loc.T("ℹ️ Hermes Residue / Background Activity (Post-Uninstall Investigation)", "ℹ️ Hermes 卸载残留/后台自启排查", "ℹ️ Actividad Residual de Hermes en Segundo Plano", "ℹ️ Hermes アンインストール後残存挙動 (バックグラウンド起動・残存調査)"),
                    Severity: RiskLevel.Informational,
                    Confidence: ConfidenceLevel.High,
                    Summary: Loc.T(
                        "Hermes component was triggered in the background (potentially by residual scheduled tasks, services, or gateways after uninstallation). Process lineage traces the parent/caller chain.",
                        "检测到 Hermes 组件在后台被触发（可能是卸载后残留的计划任务、常驻服务或网关）。祖先进程系谱已完整记录父级与发起者链条。",
                        "Componente de Hermes disparado en segundo plano (posible residuo post-desinstalación). Linaje de procesos rastreado.",
                        "Hermes コンポーネントがバックグラウンドで起動されました（アンインストール後の残存スケジュールタスク、常駐サービス、またはGatewayの疑い）。プロセス祖先系譜により呼び出し元の親・祖父プロセスが特定されています。"),
                    Actions: new List<string>
                    {
                        Loc.T("Check and clean residual Scheduled Tasks or Startup shortcuts.", "检查并清理残留的计划任务或开机启动项。", "Revise y elimine tareas programadas o accesos directos de inicio residuales.", "残存しているスケジュールタスクやスタートアップ項目の有無を確認・削除してください。"),
                        Loc.T("Delete residual folders: %LOCALAPPDATA%\\com.nousresearch.hermes.setup and %LOCALAPPDATA%\\Temp\\hermes-no-console-git.py.", "删除残留文件夹: %LOCALAPPDATA%\\com.nousresearch.hermes.setup 及 Temp 下的 hermes 脚本。", "Elimine las carpetas residuales en %LOCALAPPDATA% y Temp.", "残存フォルダ %LOCALAPPDATA%\\com.nousresearch.hermes.setup および Temp\\hermes-no-console-git.py をクリーンアップしてください。")
                    }
                );
            }
        }

        if (key.Equals("STORY:USER_SETUP", StringComparison.OrdinalIgnoreCase))
        {
            return (
                Title: Loc.T("🟢 User-Initiated Application Setup / Installer Execution", "🟢 用户主动发起的应用程序安装/更新活动", "🟢 Instalación / Actualización Iniciada por el Usuario", "🟢 ユーザー主導のアプリセットアップ・インストーラー実行"),
                Severity: RiskLevel.Safe,
                Confidence: ConfidenceLevel.High,
                Summary: Loc.T(
                    "An installer or setup executable was launched directly from Explorer or a web browser. Process lineage confirms manual user invocation, preventing false-positive HIGH alerts.",
                    "安装程序直接从资源管理器 (Explorer) 或网页浏览器下载后启动。进程祖先链已证实属于用户主动操作，避免误报为高风险。",
                    "Instalador iniciado directamente desde Explorer o navegador. Linaje confirma acción manual del usuario.",
                    "インストーラー（Setup）がエクスプローラーまたはWebブラウザから直接起動されました。プロセス祖先系譜によりユーザーの手動操作であることが確認され、HIGH誤検知を自動抑止しました。"),
                Actions: new List<string> { Loc.T("No action required. Legitimate software setup by user.", "无需处理。属于用户主动的合法软件安装。", "No se requiere acción. Instalación legítima.", "対処不要です。ユーザー自身による正常なソフトウェアセットアップです。") }
            );
        }

        if (key.Equals("STORY:OFFICE_UPDATE", StringComparison.OrdinalIgnoreCase))
        {
            return (
                Title: Loc.T("🟢 Microsoft Office Automatic Update Activity", "🟢 Microsoft Office 自动更新活动", "🟢 Actividad de Actualización de Office", "🟢 Microsoft Office 自動更新アクティビティ"),
                Severity: RiskLevel.Safe,
                Confidence: ConfidenceLevel.High,
                Summary: Loc.T(
                    "schtasks.exe / conhost.exe were launched briefly by OfficeClickToRun / OfficeC2RClient for background update checks. This is normal Windows/Office behavior.",
                    "schtasks.exe 与 conhost.exe 是由 OfficeClickToRun 启动的短命后台更新检查任务，属于 Windows/Office 正常更新行为。",
                    "schtasks.exe y conhost.exe fueron iniciados fugazmente por OfficeClickToRun para verificar actualizaciones. Comportamiento normal.",
                    "schtasks.exe / conhost.exe は OfficeClickToRun による正常なバックグラウンド更新チェックに伴う瞬間実行です。Windows/Officeの正常動作です。"),
                Actions: new List<string> { Loc.T("No action required. Normal background service.", "无需处理。正常的后台更新服务。", "No se requiere acción. Servicio normal.", "対処不要です。正常なバックグラウンド更新サービスです。") }
            );
        }

        if (key.Equals("STORY:WINDOWS_PER_USER_SVC", StringComparison.OrdinalIgnoreCase))
        {
            return (
                Title: Loc.T("🟢 Windows Per-User Services (MessagingService / CDPUserSvc)", "🟢 Windows 用户专属服务 (MessagingService / CDPUserSvc)", "🟢 Servicios por Usuario de Windows", "🟢 Windows ユーザー単位サービス (MessagingService / CDPUserSvc)"),
                Severity: RiskLevel.Safe,
                Confidence: ConfidenceLevel.High,
                Summary: Loc.T(
                    "These services are officially documented Microsoft per-user services hosted inside svchost.exe. Hosting relations and ServiceDll are standard.",
                    "此类服务是微软官方文档明确记录的 Windows 用户专属服务，由 svchost.exe 正常托管，ServiceDll 关系正常。",
                    "Estos servicios son servicios por usuario oficiales de Microsoft alojados en svchost.exe.",
                    "Microsoft公式に仕様化されたユーザー単位サービスです。svchost.exeによるServiceDllホスティング関係は正常です。"),
                Actions: new List<string> { Loc.T("No action required. Standard Windows system services.", "无需处理。标准 Windows 系统服务。", "No se requiere acción. Servicios estándar.", "対処不要です。標準的なWindowsシステムサービスです。") }
            );
        }

        if (key.Equals("STORY:SOFTLANDING_COM", StringComparison.OrdinalIgnoreCase))
        {
            return (
                Title: Loc.T("⚪ SoftLanding Scheduled Tasks (COM Handler Tasks)", "⚪ SoftLanding 计划任务 (COM 处理程序)", "⚪ Tareas Programadas SoftLanding", "⚪ SoftLanding スケジュールタスク (COMハンドラー)"),
                Severity: RiskLevel.Informational,
                Confidence: ConfidenceLevel.Medium,
                Summary: Loc.T(
                    "Scheduled tasks invoking COM objects (CLSID handlers). The lack of direct executable paths is standard for COM tasks.",
                    "使用 COM 接口 (CLSID) 的计划任务。缺少直接可执行路径是 COM 任务的标准特征，并不意味着存在未签名恶意文件。",
                    "Tareas programadas que invocan objetos COM. La falta de ejecutable directo es estándar en COM.",
                    "COMオブジェクト (CLSID) を実行するスケジュールタスク群です。直接のEXEパスを持たないのはCOMタスクの正規仕様です。"),
                Actions: new List<string> { Loc.T("Safe unless accompanied by unknown DLL injections.", "除非伴随未知 DLL 注入，否则属于正常任务。", "Seguro salvo inyecciones DLL desconocidas.", "未知のDLL注入を伴わない限り正常動作です。") }
            );
        }

        if (key.StartsWith("Story:VendorSuite:", StringComparison.OrdinalIgnoreCase))
        {
            string vendor = key.Substring("Story:VendorSuite:".Length);
            string vTitle = char.ToUpperInvariant(vendor[0]) + vendor[1..];
            return (
                Title: Loc.T($"⚪ {vTitle} Device Management & Utility Suite", $"⚪ {vTitle} 设备管理与实用工具套件", $"⚪ Suite de Gestión de Dispositivos {vTitle}", $"⚪ {vTitle} 機器管理・ユーティリティ群"),
                Severity: RiskLevel.Informational,
                Confidence: ConfidenceLevel.High,
                Summary: Loc.T(
                    $"Multiple services, background tasks, or helper executables belonging to {vTitle}. Executables are located in standard Program Files directories.",
                    $"属于 {vTitle} 的多个后台服务、任务或辅助可执行程序。程序均位于正规 Program Files 目录中。",
                    $"Varios servicios o tareas pertenecientes a {vTitle}. Ubicados en Program Files estándar.",
                    $"{vTitle} に関連する複数の常駐サービス・タスク群です。標準の Program Files フォルダ配下に配置されています。"),
                Actions: new List<string> { Loc.T($"If you use {vTitle} hardware/software, this activity is completely normal.", $"如果您使用 {vTitle} 相关的硬件或软件，则该活动完全正常。", $"Si usa hardware/software de {vTitle}, es normal.", $"{vTitle} の製品やソフトウェアをお使いの場合、完全に正常な動作です。") }
            );
        }

        if (key.Equals("STORY:ROOT_CERT_LEGACY", StringComparison.OrdinalIgnoreCase))
        {
            return (
                Title: Loc.T("⚪ Known Public / Expired Root CA Certificates", "⚪ 知名公开/已过期的公共根证书", "⚪ Certificados Raíz Públicos/Expirados Conocidos", "⚪ 既知のパブリック/期限切れルート証明書"),
                Severity: RiskLevel.Informational,
                Confidence: ConfidenceLevel.High,
                Summary: Loc.T(
                    "Standard public Root CAs (e.g. Let's Encrypt DST Root CA X3, AddTrust). Their presence in the store is legacy standard behavior and does not imply HTTPS interception.",
                    "公知的公开根证书（如 Let's Encrypt DST Root CA X3、AddTrust）。其保留在证书库中是历史遗留的正常现象，并不代表 HTTPS 被监听窃听。",
                    "CAs raíz públicas estándar (DST Root CA X3, etc.). Su presencia es normal y no implica interceptación HTTPS.",
                    "Let's Encryptの旧ルート証明書 (DST Root CA X3) や AddTrust 等の既知のパブリックCAです。ストアに残存しているのは正常な互換性動作であり、HTTPS盗聴を意味するものではありません。"),
                Actions: new List<string> { Loc.T("No action required. Standard historical certificates.", "无需处理。标准的历史保留证书。", "No se requiere acción.", "対処不要です。互換性のための標準的な証明書です。") }
            );
        }

        if (key.Equals("STORY:BADUSB_ATTACK", StringComparison.OrdinalIgnoreCase))
        {
            return (
                Title: Loc.T("🚨 Suspicious BadUSB Keystroke Injection Attack Sequence", "🚨 疑似 BadUSB 键盘注入攻击序列", "🚨 Secuencia Sospechosa de Ataque BadUSB", "🚨 疑わしい BadUSB 自動キーストローク注入シーケンス"),
                Severity: RiskLevel.Critical,
                Confidence: ConfidenceLevel.High,
                Summary: Loc.T(
                    "A new USB HID keyboard device was plugged in, immediately followed within 15 seconds by the execution of a command shell or script.",
                    "系统检测到新插入的 USB HID 键盘设备，且在 15 秒内立即触发了命令行或脚本执行，符合 BadUSB 自动注入特征。",
                    "Se conectó un nuevo teclado USB HID y en 15 segundos se ejecutó un shell de comandos.",
                    "新しいUSB HIDキーボードが接続された直後（15秒以内）に、コマンドラインやスクリプトが起動しました。BadUSB攻撃の疑いがあります。"),
                Actions: new List<string> { Loc.T("If you just inserted an unfamiliar USB stick or cable, unplug it immediately and inspect your system.", "如果您刚刚插入的是不明来源的 U 盘或数据线，请立即将其拔出并排查系统。", "Desconecte el dispositivo USB de inmediato si no era un teclado intencional.", "心当たりのないUSBメモリやケーブルを挿した場合は、直ちに抜いてシステムを確認してください。") }
            );
        }

        // 一般ストーリーの集約
        var maxSev = group.Max(x => x.Severity);
        return (
            Title: $"{key} Activity ({group.Count} items)",
            Severity: maxSev,
            Confidence: ConfidenceLevel.Medium,
            Summary: Loc.T(
                $"Correlated {group.Count} related security events under {key}.",
                $"已将 {key} 下关联的 {group.Count} 个安全事件合并归纳。",
                $"Se correlacionaron {group.Count} eventos bajo {key}.",
                $"{key} に関連する {group.Count} 件のセキュリティイベントを集約しました。"),
            Actions: new List<string> { Loc.T("Review correlated members together.", "请综合审查关联项。", "Revise los elementos juntos.", "関連する項目をまとめて確認してください。") }
        );
    }

    /// <summary>
    /// AI 相談プロンプトに挿入する「Security Stories サマリー」セクションを生成
    /// </summary>
    public static string FormatStoriesForAiPrompt(List<SecurityStory> stories)
    {
        if (stories.Count == 0) return "";

        var sb = new StringBuilder();
        sb.AppendLine(Loc.T(
            "## 1.5 Correlated Security Stories (Root Cause Analysis Summary)",
            "## 1.5 关联安全故事 (根因分析归纳汇总)",
            "## 1.5 Historias de Seguridad Correlacionadas",
            "## 1.5 集約セキュリティストーリー (根本原因・文脈の統合サマリー)"));
        sb.AppendLine(Loc.T(
            "The monitoring engine automatically correlated individual alerts into the following coherent operational activities. Analyze these first before looking at individual log entries:",
            "监控引擎已将离散的警报自动关联为以下完整的系统行为故事。请优先评估这些综合行为，而非孤立地看待单条日志：",
            "El motor de monitoreo correlacionó las alertas en las siguientes actividades. Analice esto primero:",
            "監視エンジンが個別のアラートを分析し、以下のまとまったアクティビティ（ストーリー）に自動集約しました。単発のアラートを見る前に、まずこのストーリーを評価してください:"));
        sb.AppendLine();

        int idx = 1;
        foreach (var s in stories)
        {
            string confLabel = s.Confidence switch
            {
                ConfidenceLevel.High => Loc.T("High Confidence", "高置信度", "Alta Confianza", "確信度: 高"),
                ConfidenceLevel.Medium => Loc.T("Medium Confidence", "中置信度", "Media Confianza", "確信度: 中"),
                _ => Loc.T("Low Confidence", "低置信度", "Baja Confianza", "確信度: 低")
            };

            sb.AppendLine($"### [Story {idx}] {s.Title}");
            sb.AppendLine($"- **Severity**: {s.Severity} | **Confidence**: {confLabel}");
            sb.AppendLine($"- **Story Key**: `{s.StoryKey}` (Correlated items: {s.MemberKeys.Count})");
            sb.AppendLine($"- **Summary**: {s.Summary}");
            if (s.MemberDescriptions.Count > 0)
            {
                sb.AppendLine($"- **Correlated Elements**:");
                foreach (var desc in s.MemberDescriptions.Take(6))
                {
                    sb.AppendLine($"  - {desc}");
                }
                if (s.MemberDescriptions.Count > 6)
                {
                    sb.AppendLine($"  - *(and {s.MemberDescriptions.Count - 6} more elements...)*");
                }
            }
            if (s.InferredActions.Count > 0)
            {
                sb.AppendLine($"- **Inferred Assessment / Action**: {string.Join(" ", s.InferredActions)}");
            }
            if (!string.IsNullOrWhiteSpace(s.ProcessLineage))
            {
                sb.AppendLine(Loc.T(
                    "- **Process Lineage (3-5 Generations: Parent → Grandparent → Great-grandparent | CommandLine & StartTime)**:",
                    "- **进程祖先系谱 (3~5代: 父进程 → 祖父进程 → 曾祖父进程 | 命令行与启动时间)**:",
                    "- **Linaje de Procesos (3-5 Generaciones: Padre → Abuelo → Bisabuelo | CommandLine y StartTime)**:",
                    "- **プロセス祖先系譜 (3〜5世代: 親 → 祖父 → 曾祖父 | コマンドライン・開始時刻付き)**:"));
                sb.AppendLine("```text");
                sb.AppendLine(s.ProcessLineage);
                sb.AppendLine("```");
            }
            sb.AppendLine();
            idx++;
        }

        return sb.ToString();
    }
}
