using System.Collections.Concurrent;
using System.IO;
using Microsoft.Win32;
using AnzenSecurityWatcher.Models;

namespace AnzenSecurityWatcher.Services;

/// <summary>
/// #1 自動起動・永続化エントリ監視 (改善版)
/// - Windows サービスの ImagePath / ServiceDll / SvchostGroup / StartType / ServiceAccount を分離記録・評価
/// - Windows 標準 Per-User サービス (MessagingService, CDPUserSvc, cbdhsvc, WpnUserService 等) の認識
/// - COM Scheduled Task の CLSID -> HKCR\CLSID\{GUID}\InprocServer32/LocalServer32 実体解決と署名・SHA256検証
/// - 未署名単体での過剰警告を廃止し、配置場所・新規性・コマンド内容との複合スコアリングへ移行
/// - パス正規化と意味的差分 (PATH_CHANGED, SERVICE_DLL_CHANGED, ARGUMENTS_CHANGED 等) によるベースライン比較
/// </summary>
public class AutostartMonitorService
{
    private const string BaselineFile = "autostart_baseline.json";
    private const string SchemaVersionKey = "__SCHEMA_V3_SEMANTIC_SVC__";

    // Microsoft が文書化している Windows 標準 Per-User サービス名プレフィックス
    private static readonly HashSet<string> StandardPerUserServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "MessagingService", "CDPUserSvc", "cbdhsvc", "WpnUserService", "OneSyncSvc",
        "PimIndexMaintenanceSvc", "UserDataSvc", "UnistackSvcGroup", "BcastDVRUserService",
        "BluetoothUserService", "CaptureService", "ConsentUxUserSvc", "CredentialEnrollmentManagerUserSvc",
        "DeviceAssociationBrokerSvc", "DevicePickerUserSvc", "DevicesFlowUserSvc", "NPSMSvc",
        "PenService", "PrintWorkflowUserSvc", "UdkUserSvc", " AarSvc", "AarSvc"
    };

    private Dictionary<string, string> _baseline = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _latestBaselineValues = new(StringComparer.OrdinalIgnoreCase);
    private bool _baselineLoaded;

    private record ServiceMetadata(
        string ServiceName,
        string NormalizedName,
        string ImagePath,
        string ServiceDll,
        string SvchostGroup,
        int ServiceType,
        int StartType,
        string ServiceAccount,
        bool IsPerUserService);

    private record ComTaskMetadata(
        string Clsid,
        string Data,
        ComClsidResolver.ComResolutionResult Resolution);

    private record RawAutostartEntry(
        string Key,
        string SourceCategory,
        string Name,
        string Command,
        string LocationPath,
        bool IsRunOrStartup = false,
        bool IsIfeoOrWinlogon = false,
        ServiceMetadata? ServiceMeta = null,
        ComTaskMetadata? ComMeta = null);

    public List<FindingReport> Scan()
    {
        EnsureBaselineLoaded();
        var rawEntries = new List<RawAutostartEntry>();

        ScanRunRegistryKeys(rawEntries);
        ScanWinlogonKeys(rawEntries);
        ScanIfeoKeys(rawEntries);
        ScanStartupFolders(rawEntries);
        ScanServices(rawEntries);
        ScanScheduledTasks(rawEntries);

        bool isFirstBaseline = _baseline.Count == 0;
        bool isSchemaUpgrade = !isFirstBaseline && !_baseline.ContainsKey(SchemaVersionKey);
        bool baselineModified = false;

        if (isFirstBaseline || isSchemaUpgrade)
        {
            _baseline[SchemaVersionKey] = "1";
            baselineModified = true;
        }

        var reports = new List<FindingReport>();

        foreach (var entry in rawEntries)
        {
            string canonicalBaselineValue = BuildCanonicalBaselineValue(entry);
            _latestBaselineValues[entry.Key] = canonicalBaselineValue;

            var semanticChanges = new List<BaselineChangeType>();
            string changeNote = "";

            if (isFirstBaseline)
            {
                _baseline[entry.Key] = canonicalBaselineValue;
                baselineModified = true;
            }
            else if (!_baseline.TryGetValue(entry.Key, out var oldVal))
            {
                // スキーマ移行時、または標準 Per-User サービス / Windows標準バイナリは初回自動登録して誤検知を防止
                if (isSchemaUpgrade ||
                    (entry.ServiceMeta != null && IsSafeSvchostOrWindowsService(entry.ServiceMeta)))
                {
                    _baseline[entry.Key] = canonicalBaselineValue;
                    baselineModified = true;
                }
                else
                {
                    semanticChanges.Add(BaselineChangeType.NewlyAdded);
                    changeNote = Loc.T(
                        "🆕 Newly registered autostart entry [NEWLY_ADDED]",
                        "🆕 监控开始后新注册的自启动项 [NEWLY_ADDED]",
                        "🆕 Entrada de autoinicio recién registrada [NEWLY_ADDED]",
                        "🆕 監視開始後に新規登録された自動起動エントリ [NEWLY_ADDED]");
                }
            }
            else
            {
                // 旧ベースラインとの意味的差分比較（svchost ImagePath と ServiceDll の混同による誤検知もここで吸収）
                semanticChanges = EvaluateSemanticBaselineDiff(entry, oldVal, canonicalBaselineValue, isSchemaUpgrade, ref baselineModified);
                if (semanticChanges.Count > 0)
                {
                    string changeTags = string.Join(", ", semanticChanges.Select(FormatChangeTag));
                    changeNote = Loc.T(
                        $"✏️ Semantic baseline change detected [{changeTags}]",
                        $"✏️ 检测到基线语义变更 [{changeTags}]",
                        $"✏️ Cambio semántico en línea base [{changeTags}]",
                        $"✏️ ベースラインの意味的変更を検知 [{changeTags}]");
                }
            }

            var report = EvaluateEntry(entry, semanticChanges, changeNote);
            if (report != null)
                reports.Add(report);
        }

        if (baselineModified)
            JsonStore.Save(BaselineFile, _baseline);

        return reports;
    }

    public void ApproveEntry(string findingKey)
    {
        if (!findingKey.StartsWith("AUTO:", StringComparison.OrdinalIgnoreCase)) return;
        string rawKey = findingKey["AUTO:".Length..];
        EnsureBaselineLoaded();
        if (_latestBaselineValues.TryGetValue(rawKey, out var currentVal))
        {
            _baseline[rawKey] = currentVal;
            JsonStore.Save(BaselineFile, _baseline);
        }
    }

    private void EnsureBaselineLoaded()
    {
        if (_baselineLoaded) return;
        _baselineLoaded = true;
        var loaded = JsonStore.Load<Dictionary<string, string>>(BaselineFile);
        if (loaded != null)
            _baseline = new Dictionary<string, string>(loaded, StringComparer.OrdinalIgnoreCase);
    }

    private static string BuildCanonicalBaselineValue(RawAutostartEntry entry)
    {
        if (entry.ServiceMeta != null)
        {
            var sm = entry.ServiceMeta;
            string normImg = PathHelper.NormalizeCommandForComparison(sm.ImagePath);
            string normDll = PathHelper.CleanFilePath(sm.ServiceDll).ToLowerInvariant();
            return $"IMG={normImg}|DLL={normDll}|GRP={sm.SvchostGroup.ToLowerInvariant()}|START={sm.StartType}|ACC={sm.ServiceAccount.ToLowerInvariant()}";
        }
        if (entry.ComMeta != null)
        {
            var cm = entry.ComMeta;
            string normBin = PathHelper.CleanFilePath(cm.Resolution.ResolvedBinaryPath).ToLowerInvariant();
            return $"CLSID={cm.Clsid.ToLowerInvariant()}|BIN={normBin}|DATA={cm.Data.Trim()}";
        }
        return PathHelper.NormalizeCommandForComparison(entry.Command);
    }

    private List<BaselineChangeType> EvaluateSemanticBaselineDiff(
        RawAutostartEntry entry,
        string oldVal,
        string newCanonicalVal,
        bool isSchemaUpgrade,
        ref bool baselineModified)
    {
        var changes = new List<BaselineChangeType>();
        if (string.Equals(oldVal, newCanonicalVal, StringComparison.OrdinalIgnoreCase))
            return changes;

        // 1. サービスの場合: 旧スキーマでは ImagePath ("svchost.exe -k UnistackSvcGroup") または ServiceDll ("MessagingService.dll") の片方だけが文字列で入っていた
        if (entry.ServiceMeta != null)
        {
            var sm = entry.ServiceMeta;
            if (!oldVal.StartsWith("IMG=", StringComparison.OrdinalIgnoreCase))
            {
                string normOld = PathHelper.NormalizeCommandForComparison(oldVal);
                string normImg = PathHelper.NormalizeCommandForComparison(sm.ImagePath);
                string normDll = PathHelper.CleanFilePath(sm.ServiceDll).ToLowerInvariant();

                // 旧値が ImagePath または ServiceDll のいずれかと実質一致するなら、単なるスキーマ表現差なのでベースラインを新形式に更新して差分なしとする
                if (string.Equals(normOld, normImg, StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrEmpty(normDll) && string.Equals(normOld, normDll, StringComparison.OrdinalIgnoreCase)) ||
                    IsSafeSvchostOrWindowsService(sm))
                {
                    _baseline[entry.Key] = newCanonicalVal;
                    baselineModified = true;
                    return changes;
                }
            }
            else
            {
                var oldParts = ParseKeyValueString(oldVal);
                var newParts = ParseKeyValueString(newCanonicalVal);

                if (!string.Equals(oldParts.GetValueOrDefault("DLL"), newParts.GetValueOrDefault("DLL"), StringComparison.OrdinalIgnoreCase))
                    changes.Add(BaselineChangeType.ServiceDllChanged);
                if (!string.Equals(oldParts.GetValueOrDefault("IMG"), newParts.GetValueOrDefault("IMG"), StringComparison.OrdinalIgnoreCase))
                    changes.Add(BaselineChangeType.PathChanged);
                if (!string.Equals(oldParts.GetValueOrDefault("START"), newParts.GetValueOrDefault("START"), StringComparison.OrdinalIgnoreCase))
                    changes.Add(BaselineChangeType.StartTypeChanged);

                if (changes.Count == 0)
                {
                    _baseline[entry.Key] = newCanonicalVal;
                    baselineModified = true;
                }
                return changes;
            }
        }

        // 2. COM タスクの場合
        if (entry.ComMeta != null)
        {
            if (!oldVal.StartsWith("CLSID=", StringComparison.OrdinalIgnoreCase))
            {
                if (oldVal.Contains(entry.ComMeta.Clsid, StringComparison.OrdinalIgnoreCase))
                {
                    _baseline[entry.Key] = newCanonicalVal;
                    baselineModified = true;
                    return changes;
                }
            }
            changes.Add(BaselineChangeType.TaskActionChanged);
            return changes;
        }

        // 3. 一般コマンド (Run / Startup / Task Exec): 大文字小文字、引用符、環境変数、8.3パスを正規化して比較
        var cmdChanges = PathHelper.CompareCommandsSemantically(oldVal, entry.Command);
        if (cmdChanges.Count == 0)
        {
            // 単なる文字列フォーマット差（"C:\Windows\..." vs "C:\WINDOWS\..."）はベースラインを更新してアラートにしない
            _baseline[entry.Key] = newCanonicalVal;
            baselineModified = true;
        }
        return cmdChanges;
    }

    private static Dictionary<string, string> ParseKeyValueString(string raw)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in raw.Split('|', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = part.IndexOf('=');
            if (eq > 0)
                dict[part[..eq]] = part[(eq + 1)..];
        }
        return dict;
    }

    private static string FormatChangeTag(BaselineChangeType t) => t switch
    {
        BaselineChangeType.NewlyAdded => "NEWLY_ADDED",
        BaselineChangeType.PathChanged => "PATH_CHANGED",
        BaselineChangeType.HashChanged => "HASH_CHANGED",
        BaselineChangeType.SignerChanged => "SIGNER_CHANGED",
        BaselineChangeType.StartTypeChanged => "START_TYPE_CHANGED",
        BaselineChangeType.ServiceDllChanged => "SERVICE_DLL_CHANGED",
        BaselineChangeType.ArgumentsChanged => "ARGUMENTS_CHANGED",
        BaselineChangeType.TaskActionChanged => "TASK_ACTION_CHANGED",
        BaselineChangeType.CertificateAdded => "CERTIFICATE_ADDED",
        _ => "MODIFIED"
    };

    private static bool IsSafeSvchostOrWindowsService(ServiceMetadata sm)
    {
        if (StandardPerUserServices.Contains(sm.NormalizedName))
        {
            string targetCheck = !string.IsNullOrWhiteSpace(sm.ServiceDll) ? sm.ServiceDll : sm.ImagePath;
            string clean = PathHelper.ExtractExecutablePath(targetCheck);
            if (string.IsNullOrEmpty(clean) || PathHelper.IsWindowsLocation(clean))
                return true;
        }

        string imgExe = PathHelper.ExtractExecutablePath(sm.ImagePath);
        bool isSvchost = Path.GetFileName(imgExe).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase) &&
                         PathHelper.IsWindowsLocation(imgExe);

        if (isSvchost)
        {
            if (string.IsNullOrWhiteSpace(sm.ServiceDll))
                return true;

            string dllPath = PathHelper.CleanFilePath(sm.ServiceDll);
            var sig = SignatureHelper.CheckExtended(dllPath);
            if (PathHelper.IsWindowsLocation(dllPath) && (sig.IsSigned || SignatureHelper.IsMicrosoftSigner(sig.Signer)))
                return true;
        }

        return false;
    }

    private static FindingReport? EvaluateEntry(
        RawAutostartEntry entry,
        List<BaselineChangeType> semanticChanges,
        string changeNote)
    {
        bool isNewOrChanged = semanticChanges.Count > 0;
        var reasons = new List<string>();
        var risk = RiskLevel.Safe;
        var confidence = ConfidenceLevel.High;

        // --- A. COM Scheduled Task の評価 (要件 #3) ---
        if (entry.ComMeta != null)
        {
            var cm = entry.ComMeta;
            var res = cm.Resolution;
            var sig = res.Signature;

            if (res.IsResolved)
            {
                if (sig.IsSigned && (SignatureHelper.IsMicrosoftSigner(sig.Signer) || PathHelper.IsWindowsLocation(res.ResolvedBinaryPath) || PathHelper.IsProgramFilesLocation(res.ResolvedBinaryPath)))
                {
                    if (!isNewOrChanged)
                        return null; // 正規署名済み COM タスクはノイズ防止のため非表示
                    risk = RiskLevel.Low;
                }
                else if (PathHelper.IsHighRiskTempLocation(res.ResolvedBinaryPath))
                {
                    risk = RiskLevel.High;
                    reasons.Add(Loc.T(
                        "COM server binary located in temporary folder (Suspected COM hijacking)",
                        "COM 服务器二进制文件位于临时目录（疑似 COM 劫持）",
                        "Binario de servidor COM en carpeta temporal (Sospecha de secuestro COM)",
                        "COMサーバー実体がTemp等の一時フォルダに配置されています (COMハイジャック懸念)"));
                }
                else if (PathHelper.IsUserWritableLocation(res.ResolvedBinaryPath) && sig.Status == SignatureStatus.Unsigned)
                {
                    risk = isNewOrChanged ? RiskLevel.High : RiskLevel.Medium;
                    confidence = ConfidenceLevel.Medium;
                    reasons.Add(Loc.T(
                        "Unsigned COM server binary in user-writable directory",
                        "位于用户可写目录的未签名 COM 服务器文件",
                        "Binario de servidor COM sin firma en carpeta de usuario",
                        "ユーザー書き込み可能領域の未署名COMサーバーバイナリ"));
                }
                else if (sig.Status == SignatureStatus.Unsigned)
                {
                    // 未署名単体では Low (要件 #2)
                    risk = isNewOrChanged ? RiskLevel.Medium : RiskLevel.Low;
                    confidence = ConfidenceLevel.Medium;
                    reasons.Add(Loc.T(
                        "COM server binary is unsigned",
                        "COM 服务器文件未签名",
                        "El binario del servidor COM no está firmado",
                        "COMサーバー実体ファイルにデジタル署名がありません"));
                }
            }
            else
            {
                // CLSID が解決できなかった場合は「未署名 (Unsigned)」ではなく「Unknown (COM server executable not resolved)」とする (要件 #3)
                risk = isNewOrChanged ? RiskLevel.Medium : RiskLevel.Low;
                confidence = ConfidenceLevel.Low;
                reasons.Add(Loc.T(
                    "⚪ COM server executable not resolved in HKCR\\CLSID (Signature: Unknown)",
                    "⚪ 未能在 HKCR\\CLSID 中解析出 COM 可执行文件 (签名状态: Unknown)",
                    "⚪ Ejecutable del servidor COM no resuelto en HKCR\\CLSID (Firma: Unknown)",
                    "⚪ HKCR\\CLSID からCOMサーバー実行ファイルを解決できませんでした (署名: Unknown)"));
            }

            if (isNewOrChanged && !string.IsNullOrEmpty(changeNote))
                reasons.Insert(0, changeNote);

            if (risk == RiskLevel.Safe)
                return null;

            string resolvedPathDisplay = res.IsResolved
                ? $"{res.ResolvedBinaryPath} ({res.ServerType})"
                : Loc.T("Unresolved (COM server executable not resolved)", "未解析 (COM server executable not resolved)", "No resuelto (COM server executable not resolved)", "未解決 (COM server executable not resolved)");
            string signDisplay = SignatureHelper.FormatSignatureLine(sig);
            string shaLine = string.IsNullOrEmpty(sig.Sha256) ? "—" : sig.Sha256;

            string comTech = Loc.T(
                $"Type: {entry.SourceCategory}\nTask Path: {entry.Name}\nCOM CLSID: {cm.Clsid}\nCOM Display Name: {(string.IsNullOrEmpty(res.DisplayName) ? "—" : res.DisplayName)}\nServer Type: {res.ServerType}\nResolved Binary: {resolvedPathDisplay}\nDigital Signature: {signDisplay}\nPublisher: {(string.IsNullOrEmpty(sig.Publisher) ? "—" : sig.Publisher)}\nSHA256: {shaLine}\nReason: {string.Join(" / ", reasons)}",
                $"类型: {entry.SourceCategory}\n任务路径: {entry.Name}\nCOM CLSID: {cm.Clsid}\nCOM 名称: {(string.IsNullOrEmpty(res.DisplayName) ? "—" : res.DisplayName)}\n服务器类型: {res.ServerType}\n解析出的文件: {resolvedPathDisplay}\n数字签名: {signDisplay}\n发布者: {(string.IsNullOrEmpty(sig.Publisher) ? "—" : sig.Publisher)}\nSHA256: {shaLine}\n判定原因: {string.Join(" / ", reasons)}",
                $"Tipo: {entry.SourceCategory}\nRuta de tarea: {entry.Name}\nCOM CLSID: {cm.Clsid}\nNombre COM: {(string.IsNullOrEmpty(res.DisplayName) ? "—" : res.DisplayName)}\nTipo de servidor: {res.ServerType}\nBinario resuelto: {resolvedPathDisplay}\nFirma digital: {signDisplay}\nEditor: {(string.IsNullOrEmpty(sig.Publisher) ? "—" : sig.Publisher)}\nSHA256: {shaLine}\nMotivo: {string.Join(" / ", reasons)}",
                $"種別: {entry.SourceCategory}\nタスク名: {entry.Name}\nCOM CLSID: {cm.Clsid}\nCOM表示名: {(string.IsNullOrEmpty(res.DisplayName) ? "—" : res.DisplayName)}\nサーバー種別: {res.ServerType}\n解決された実ファイル: {resolvedPathDisplay}\nデジタル署名: {signDisplay}\n発行元(Publisher): {(string.IsNullOrEmpty(sig.Publisher) ? "—" : sig.Publisher)}\nSHA256: {shaLine}\n判定理由: {string.Join(" / ", reasons)}");

            string storyKey = entry.Name.Contains("SoftLanding", StringComparison.OrdinalIgnoreCase)
                ? "STORY:TASK_SOFTLANDING"
                : $"STORY:COM_TASK:{cm.Clsid}";
            string storyTitle = entry.Name.Contains("SoftLanding", StringComparison.OrdinalIgnoreCase)
                ? "SoftLanding Scheduled Tasks"
                : $"COM Scheduled Task ({cm.Clsid})";

            return new FindingReport(
                Key: $"AUTO:{entry.Key}",
                Category: FindingCategory.Autostart,
                Severity: risk,
                State: isNewOrChanged ? FindingState.New : FindingState.Existing,
                Title: $"[{entry.SourceCategory}] {entry.Name}",
                Detail: $"{string.Join(" / ", reasons)} — CLSID:{cm.Clsid} -> {(res.IsResolved ? Path.GetFileName(res.ResolvedBinaryPath) : "Unresolved")}",
                Target: res.IsResolved ? res.ResolvedBinaryPath : $"CLSID:{cm.Clsid}",
                TechnicalDetails: comTech,
                RecommendedAction: Loc.T(
                    "COM scheduled tasks invoke a registered COM server via CLSID. If the CLSID is unresolved, it may be a leftover Windows feature task (such as SoftLanding). Verify in Task Scheduler before deleting.",
                    "COM 计划任务通过 CLSID 调用已注册的 COM 组件。如果 CLSID 未解析出文件，通常是 Windows 遗留任务（如 SoftLanding），无需恐慌，可在任务计划程序中核对。",
                    "Las tareas COM invocan un servidor COM mediante CLSID. Si no se resuelve, suele ser una tarea residual de Windows (como SoftLanding).",
                    "COMスケジュールタスクはCLSID経由で登録済みCOMサーバーを呼び出します。CLSIDが未解決の場合はWindows標準機能の残存エントリ（SoftLanding等）であることが多く、直ちに危険を意味しません。"),
                OpenLocationPath: res.IsResolved ? res.ResolvedBinaryPath : "",
                Confidence: confidence,
                StoryKey: storyKey,
                StoryTitle: storyTitle);
        }

        // --- B. Windows サービスの評価 (要件 #1) ---
        if (entry.ServiceMeta != null)
        {
            var sm = entry.ServiceMeta;
            // svchost.exe -> ServiceDll という正常なホスティング関係や標準Per-Userサービスは Safe
            if (IsSafeSvchostOrWindowsService(sm) && !semanticChanges.Contains(BaselineChangeType.ServiceDllChanged))
                return null;

            string evalPath = !string.IsNullOrWhiteSpace(sm.ServiceDll)
                ? PathHelper.CleanFilePath(sm.ServiceDll)
                : PathHelper.ExtractExecutablePath(sm.ImagePath);
            var sig = SignatureHelper.CheckExtended(evalPath);

            var cmdAnalysis = CommandLineAnalyzer.Analyze(sm.ImagePath, Path.GetFileNameWithoutExtension(evalPath));
            if (cmdAnalysis.IsSuspicious)
            {
                risk = cmdAnalysis.Risk;
                reasons.AddRange(cmdAnalysis.Reasons);
            }

            if (PathHelper.IsHighRiskTempLocation(evalPath))
            {
                risk = RiskLevel.Critical;
                reasons.Add(Loc.T(
                    "Service binary/DLL located in temporary folder (Temp / Downloads / Public)",
                    "服务可执行文件或 ServiceDll 位于临时文件夹 (Temp / Downloads / Public)",
                    "Binario/DLL del servicio en carpeta temporal (Temp / Downloads / Public)",
                    "サービス実行ファイルまたは ServiceDll が一時フォルダ (Temp / Downloads / Public) 内に配置されています"));
            }
            else if (PathHelper.IsUserWritableLocation(evalPath) && sig.Status == SignatureStatus.Unsigned)
            {
                if (risk < RiskLevel.High) risk = RiskLevel.High;
                reasons.Add(Loc.T(
                    "Unsigned service binary/DLL in user-writable folder (AppData / ProgramData)",
                    "位于用户可写目录 (AppData / ProgramData) 的未签名服务文件",
                    "Binario/DLL de servicio sin firma en carpeta de usuario",
                    "ユーザー領域 (AppData / ProgramData 等) のデジタル署名なしサービスバイナリ/DLL"));
            }
            else if (sig.Status == SignatureStatus.Unsigned && !PathHelper.IsWindowsLocation(evalPath))
            {
                if (PathHelper.IsProgramFilesLocation(evalPath) && !isNewOrChanged)
                {
                    // 要件 #2: Program Files 内の既存未署名サービスは Low (INFORMATIONAL)
                    if (risk < RiskLevel.Low) risk = RiskLevel.Low;
                    confidence = ConfidenceLevel.Medium;
                    reasons.Add(Loc.T(
                        "Unsigned service binary in Program Files (Low severity alone)",
                        "位于 Program Files 下的未签名服务文件 (仅凭未签名视为低风险提示)",
                        "Binario de servicio sin firma en Program Files (Riesgo bajo por sí solo)",
                        "Program Files 配下のデジタル署名なしサービス (未署名単独のため情報/Low判定)"));
                }
                else
                {
                    if (risk < RiskLevel.Medium) risk = RiskLevel.Medium;
                    confidence = ConfidenceLevel.Medium;
                    reasons.Add(Loc.T(
                        "Unsigned service binary outside Program Files / Windows",
                        "位于标准目录外的未签名服务程序",
                        "Binario de servicio sin firma fuera de carpetas estándar",
                        "標準フォルダ外のデジタル署名なしサービスプログラム"));
                }
            }

            if (semanticChanges.Contains(BaselineChangeType.ServiceDllChanged))
            {
                if (risk < RiskLevel.High) risk = RiskLevel.High;
                reasons.Insert(0, changeNote);
            }
            else if (isNewOrChanged && risk >= RiskLevel.Medium)
            {
                reasons.Insert(0, changeNote);
            }
            else if (isNewOrChanged && sig.IsSigned && (PathHelper.IsWindowsLocation(evalPath) || PathHelper.IsProgramFilesLocation(evalPath)))
            {
                // 正規署名付きのサービス追加は Info (Low)
                if (risk < RiskLevel.Low) risk = RiskLevel.Low;
                reasons.Add(changeNote);
            }

            if (risk == RiskLevel.Safe)
                return null;

            string signLine = SignatureHelper.FormatSignatureLine(sig);
            string svcTech = Loc.T(
                $"ServiceName: {sm.ServiceName} (Normalized: {sm.NormalizedName})\nImagePath: {sm.ImagePath}\nServiceDll: {(string.IsNullOrEmpty(sm.ServiceDll) ? "(None - direct executable)" : sm.ServiceDll)}\nSvchostGroup: {(string.IsNullOrEmpty(sm.SvchostGroup) ? "—" : sm.SvchostGroup)}\nServiceType: 0x{sm.ServiceType:X} ({(sm.IsPerUserService ? "Per-User Service" : "Win32 Service")})\nStartType: {sm.StartType} (Auto)\nServiceAccount: {sm.ServiceAccount}\nSigner: {signLine}\nSHA256: {(string.IsNullOrEmpty(sig.Sha256) ? "—" : sig.Sha256)}\nSemantic Changes: {(semanticChanges.Count > 0 ? string.Join(", ", semanticChanges.Select(FormatChangeTag)) : "NONE")}\nReason: {string.Join(" / ", reasons)}",
                $"ServiceName: {sm.ServiceName} (Normalized: {sm.NormalizedName})\nImagePath: {sm.ImagePath}\nServiceDll: {(string.IsNullOrEmpty(sm.ServiceDll) ? "(无 - 直接执行 EXE)" : sm.ServiceDll)}\nSvchostGroup: {(string.IsNullOrEmpty(sm.SvchostGroup) ? "—" : sm.SvchostGroup)}\nServiceType: 0x{sm.ServiceType:X}\nStartType: {sm.StartType} (Auto)\nServiceAccount: {sm.ServiceAccount}\nSigner: {signLine}\nSHA256: {(string.IsNullOrEmpty(sig.Sha256) ? "—" : sig.Sha256)}\n变更类型: {(semanticChanges.Count > 0 ? string.Join(", ", semanticChanges.Select(FormatChangeTag)) : "NONE")}\n判定原因: {string.Join(" / ", reasons)}",
                $"ServiceName: {sm.ServiceName}\nImagePath: {sm.ImagePath}\nServiceDll: {(string.IsNullOrEmpty(sm.ServiceDll) ? "(Ninguno)" : sm.ServiceDll)}\nSvchostGroup: {(string.IsNullOrEmpty(sm.SvchostGroup) ? "—" : sm.SvchostGroup)}\nServiceType: 0x{sm.ServiceType:X}\nStartType: {sm.StartType}\nServiceAccount: {sm.ServiceAccount}\nSigner: {signLine}\nSHA256: {(string.IsNullOrEmpty(sig.Sha256) ? "—" : sig.Sha256)}\nMotivo: {string.Join(" / ", reasons)}",
                $"ServiceName: {sm.ServiceName} (正規化名: {sm.NormalizedName})\nImagePath: {sm.ImagePath}\nServiceDll: {(string.IsNullOrEmpty(sm.ServiceDll) ? "(なし - 直接実行EXE)" : sm.ServiceDll)}\nSvchostGroup: {(string.IsNullOrEmpty(sm.SvchostGroup) ? "—" : sm.SvchostGroup)}\nServiceType: 0x{sm.ServiceType:X} ({(sm.IsPerUserService ? "Per-Userサービス" : "Win32サービス")})\nStartType: {sm.StartType} (自動起動)\nServiceAccount: {sm.ServiceAccount}\nSigner: {signLine}\nSHA256: {(string.IsNullOrEmpty(sig.Sha256) ? "—" : sig.Sha256)}\n意味的変更: {(semanticChanges.Count > 0 ? string.Join(", ", semanticChanges.Select(FormatChangeTag)) : "変更なし (NONE)")}\n判定理由: {string.Join(" / ", reasons)}");

            var vendorKey = ExtractVendorStoryKey(evalPath, sig.Signer, sig.Publisher, sm.ServiceName);

            return new FindingReport(
                Key: $"AUTO:{entry.Key}",
                Category: FindingCategory.Autostart,
                Severity: risk,
                State: isNewOrChanged ? FindingState.New : FindingState.Existing,
                Title: $"[{entry.SourceCategory}] {sm.ServiceName}",
                Detail: $"{string.Join(" / ", reasons)} — {(string.IsNullOrEmpty(sm.ServiceDll) ? CommandLineAnalyzer.Shorten(sm.ImagePath, 120) : $"svchost ({sm.SvchostGroup}) -> {sm.ServiceDll}")}",
                Target: evalPath,
                TechnicalDetails: svcTech,
                RecommendedAction: Loc.T(
                    "Verify the ServiceName, ImagePath, ServiceDll, and Signer. Legitimate third-party services in Program Files without Authenticode signatures are rated Informational/Caution unless combined with suspicious behavior.",
                    "请核对 ServiceName、ImagePath、ServiceDll 与签名。位于 Program Files 下的正规第三方未签名服务仅作低风险提示。",
                    "Verifique ServiceName, ImagePath, ServiceDll y firma. Los servicios legítimos en Program Files sin firma tienen severidad baja.",
                    "ServiceName・ImagePath・ServiceDll・署名を確認してください。Program Files 配下の正規サードパーティ製ソフト（未署名）であれば単独では低リスク（情報/注意）です。「✅ 承認」でベースライン登録できます。"),
                OpenLocationPath: File.Exists(evalPath) ? evalPath : "",
                Confidence: confidence,
                StoryKey: vendorKey.Key,
                StoryTitle: vendorKey.Title);
        }

        // --- C. 一般の自動起動 (Run / Startup / Winlogon / IFEO / Scheduled Task Exec) の複合評価 (要件 #2, #12) ---
        string exePath = PathHelper.ExtractExecutablePath(entry.Command);
        var sigRes = SignatureHelper.CheckExtended(exePath);

        // 1. コマンドライン解析 (PowerShell -enc, mshta, regsvr32 等)
        var cmdRes = CommandLineAnalyzer.Analyze(entry.Command, Path.GetFileNameWithoutExtension(exePath));
        if (cmdRes.IsSuspicious)
        {
            if (cmdRes.Risk > risk) risk = cmdRes.Risk;
            reasons.AddRange(cmdRes.Reasons);
        }

        // 2. 配置場所 × デジタル署名 × 新規性の複合スコアリング (要件 #2)
        bool inTemp = PathHelper.IsHighRiskTempLocation(exePath);
        bool inUserWritable = PathHelper.IsUserWritableLocation(exePath);
        bool inProgFiles = PathHelper.IsProgramFilesLocation(exePath);
        bool inWindows = PathHelper.IsWindowsLocation(exePath);

        if (inTemp)
        {
            risk = (sigRes.Status == SignatureStatus.Unsigned || cmdRes.IsSuspicious || isNewOrChanged)
                ? RiskLevel.Critical
                : RiskLevel.High;
            reasons.Add(Loc.T(
                "Autostart binary located in temporary folder (Temp / Downloads / Public)",
                "位于临时文件夹 (Temp / Downloads / Public) 内的程序被注册为自启动",
                "Programa en carpeta temporal (Temp / Downloads / Public) registrado en autoinicio",
                "一時フォルダ (Temp / Downloads / Public) 内のプログラムが自動起動登録されています"));
        }
        else if (inUserWritable && sigRes.Status == SignatureStatus.Unsigned)
        {
            // Unsigned + Temp/AppData + Persistence -> High (要件 #2)
            if (risk < RiskLevel.High) risk = RiskLevel.High;
            confidence = isNewOrChanged ? ConfidenceLevel.High : ConfidenceLevel.Medium;
            reasons.Add(Loc.T(
                "Unsigned autostart binary in user-writable folder (AppData / ProgramData)",
                "位于用户可写目录 (AppData / ProgramData) 的未签名自启动程序",
                "Programa sin firma digital en carpeta de usuario (AppData / ProgramData)",
                "ユーザー領域 (AppData / ProgramData 等) の未署名プログラムが永続化登録されています"));
        }
        else if (sigRes.Status == SignatureStatus.Unsigned && !inWindows)
        {
            if (!inProgFiles && isNewOrChanged)
            {
                // Unsigned + Program Files 外 + 新規出現 -> Medium (Caution) (要件 #2)
                if (risk < RiskLevel.Medium) risk = RiskLevel.Medium;
                confidence = ConfidenceLevel.Medium;
                reasons.Add(Loc.T(
                    "Newly observed unsigned autostart program outside Program Files",
                    "新出现的位于 Program Files 外的未签名自启动程序",
                    "Programa de autoinicio sin firma recién observado fuera de Program Files",
                    "Program Files 外に新規出現した未署名の自動起動プログラム"));
            }
            else
            {
                // Unsigned 単体 (Program Files 内や既存ソフト: Brother, ScanSnap, Hasleo, AWS VPN 等) -> Low (Informational) (要件 #2)
                if (risk < RiskLevel.Low) risk = RiskLevel.Low;
                confidence = ConfidenceLevel.Medium;
                reasons.Add(Loc.T(
                    "Unsigned autostart binary (Informational alone; located in standard application folder)",
                    "未签名的自启动程序（位于常规目录，仅凭未签名归为信息级 Low）",
                    "Programa de autoinicio sin firma (Informativo por sí solo)",
                    "デジタル署名なしの自動起動プログラム (単独指標のため情報/Low判定)"));
            }
        }
        else if (sigRes.Status == SignatureStatus.Unknown && !inWindows)
        {
            if (risk < RiskLevel.Low) risk = RiskLevel.Low;
            confidence = ConfidenceLevel.Low;
            reasons.Add(Loc.T(
                $"Signature status unknown ({sigRes.Reason})",
                $"数字签名状态未知 ({sigRes.Reason})",
                $"Estado de firma desconocido ({sigRes.Reason})",
                $"デジタル署名状態が未解決/不明 ({sigRes.Reason})"));
        }

        // 3. IFEO Debugger や Winlogon 改ざんは常に高リスク
        if (entry.IsIfeoOrWinlogon)
        {
            if (risk < RiskLevel.High) risk = RiskLevel.High;
            reasons.Add(Loc.T(
                $"Special persistence configuration via {entry.SourceCategory}",
                $"通过 {entry.SourceCategory} 设置的特殊持久化项",
                $"Configuración de persistencia especial mediante {entry.SourceCategory}",
                $"{entry.SourceCategory} による特殊永続化設定"));
        }

        // 4. ベースラインの意味的変更があった場合
        if (isNewOrChanged)
        {
            if (sigRes.IsSigned && (inWindows || inProgFiles) && !cmdRes.IsSuspicious && !entry.IsIfeoOrWinlogon)
            {
                // 署名済み正規ソフトのアップデートやタスク更新は Caution (Medium) または Info (Low) に抑える
                if (risk < RiskLevel.Low) risk = RiskLevel.Low;
                confidence = ConfidenceLevel.High;
            }
            else
            {
                if (risk < RiskLevel.Medium) risk = RiskLevel.Medium;
            }
            reasons.Insert(0, changeNote);
        }

        // 問題のない既存 OS/署名済みタスクはノイズになるため除外し、Run/Startup または要注意・情報項目のみ返す
        if (risk == RiskLevel.Safe && !entry.IsRunOrStartup)
            return null;

        if (reasons.Count == 0)
        {
            reasons.Add(sigRes.IsSigned
                ? Loc.T($"Signed ({sigRes.Signer})", $"已验证签名 ({sigRes.Signer})", $"Firma verificada ({sigRes.Signer})", $"署名確認済み ({sigRes.Signer})")
                : Loc.T("Existing autostart entry", "现有自启动项", "Entrada de autoinicio existente", "既存の自動起動項目"));
        }

        var state = isNewOrChanged ? FindingState.New : FindingState.Existing;
        string title = $"[{entry.SourceCategory}] {entry.Name}";
        string shortCmd = CommandLineAnalyzer.Shorten(entry.Command, 140);
        string cmdLabel = Loc.T("Cmd", "执行", "Cmd", "実行");
        string detail = $"{string.Join(" / ", reasons)} — {cmdLabel}: {shortCmd}";

        string unknownPath = Loc.T("(Unknown)", "(未知)", "(Desconocido)", "(不明)");
        string resolvedPath = string.IsNullOrEmpty(exePath) ? unknownPath : exePath;
        string signStatus = SignatureHelper.FormatSignatureLine(sigRes);
        string diffStatus = isNewOrChanged
            ? $"{Loc.T("🆕 Semantic change", "🆕 语义变更", "🆕 Cambio semántico", "🆕 意味的変更あり")} ({string.Join(", ", semanticChanges.Select(FormatChangeTag))})"
            : Loc.T("Existing (Matches normalized baseline)", "既有 (与规范化基线一致)", "Existente (Coincide con línea base)", "既存 (正規化ベースライン一致)");
        string reasonsJoined = string.Join(" / ", reasons);

        string tech = Loc.T(
            $"Type: {entry.SourceCategory}\nEntry Name: {entry.Name}\nLocation: {entry.LocationPath}\nCommand: {entry.Command}\nExecutable Path: {resolvedPath}\nDigital Signature: {signStatus}\nSHA256: {(string.IsNullOrEmpty(sigRes.Sha256) ? "—" : sigRes.Sha256)}\nBaseline Status: {diffStatus}\nReason: {reasonsJoined}",
            $"类型: {entry.SourceCategory}\n条目名称: {entry.Name}\n注册位置: {entry.LocationPath}\n执行命令: {entry.Command}\n可执行文件路径: {resolvedPath}\n数字签名: {signStatus}\nSHA256: {(string.IsNullOrEmpty(sigRes.Sha256) ? "—" : sigRes.Sha256)}\n基线状态: {diffStatus}\n判定原因: {reasonsJoined}",
            $"Tipo: {entry.SourceCategory}\nNombre: {entry.Name}\nUbicación: {entry.LocationPath}\nComando: {entry.Command}\nRuta estimada: {resolvedPath}\nFirma digital: {signStatus}\nSHA256: {(string.IsNullOrEmpty(sigRes.Sha256) ? "—" : sigRes.Sha256)}\nEstado de línea base: {diffStatus}\nMotivo: {reasonsJoined}",
            $"種別: {entry.SourceCategory}\nエントリ名: {entry.Name}\n登録場所: {entry.LocationPath}\n実行コマンド: {entry.Command}\n推定ファイルパス: {resolvedPath}\nデジタル署名: {signStatus}\nSHA256: {(string.IsNullOrEmpty(sigRes.Sha256) ? "—" : sigRes.Sha256)}\n差分状態: {diffStatus}\n判定理由: {reasonsJoined}");

        string recAction = Loc.T(
            "If you do not recognize this autostart entry, disable or delete it via Task Manager (Startup), Autoruns, Registry Editor, Services, or Task Scheduler. If it is a legitimate app update, click '✅ Ack' to update the baseline.",
            "如果是来历不明的自启动项，请通过任务管理器“启动应用”、Autoruns、注册表编辑器、服务管理或任务计划程序将其禁用或删除。如果是安全软件的新增或更新，可点击“✅ 确认”更新基线。",
            "Si no reconoce esta entrada de autoinicio, desactívela o elimínela mediante el Administrador de tareas (Inicio), Autoruns, Editor del Registro, Servicios o Programador de tareas. Si es legítima, pulse '✅ Ack' para actualizar la línea base.",
            "心当たりのない自動起動項目の場合は、タスクマネージャーの「スタートアップ」や Autoruns / レジストリエディタ / サービス管理 / タスクスケジューラで無効化・削除してください。安全なソフトの追加・更新であれば「✅ 承認」でベースラインを更新できます。");

        var storyInfo = ExtractVendorStoryKey(exePath, sigRes.Signer, sigRes.Publisher, entry.Name);

        return new FindingReport(
            Key: $"AUTO:{entry.Key}",
            Category: FindingCategory.Autostart,
            Severity: risk,
            State: state,
            Title: title,
            Detail: detail,
            Target: string.IsNullOrEmpty(exePath) ? entry.Command : exePath,
            TechnicalDetails: tech,
            RecommendedAction: recAction,
            OpenLocationPath: File.Exists(exePath) ? exePath : "",
            Confidence: confidence,
            StoryKey: storyInfo.Key,
            StoryTitle: storyInfo.Title);
    }

    public static (string Key, string Title) ExtractVendorStoryKey(string filePath, string signer, string publisher, string entryName)
    {
        string combined = $"{filePath} {signer} {publisher} {entryName}";
        if (combined.Contains("Brother", StringComparison.OrdinalIgnoreCase) || combined.Contains("BrStMonW", StringComparison.OrdinalIgnoreCase) || combined.Contains("BrYNSvc", StringComparison.OrdinalIgnoreCase))
            return ("STORY:VENDOR_BROTHER", "Brother Printer / Scanner Software Suite");
        if (combined.Contains("ScanSnap", StringComparison.OrdinalIgnoreCase) || combined.Contains("PFU", StringComparison.OrdinalIgnoreCase) || combined.Contains("Fujitsu", StringComparison.OrdinalIgnoreCase))
            return ("STORY:VENDOR_SCANSNAP", "PFU ScanSnap Software Suite");
        if (combined.Contains("Hasleo", StringComparison.OrdinalIgnoreCase))
            return ("STORY:VENDOR_HASLEO", "Hasleo Backup / Disk Suite");
        if (combined.Contains("AWS VPN", StringComparison.OrdinalIgnoreCase) || combined.Contains("Amazon", StringComparison.OrdinalIgnoreCase))
            return ("STORY:VENDOR_AWS_VPN", "AWS VPN Client Service");
        if (combined.Contains("Thunderbolt", StringComparison.OrdinalIgnoreCase) || combined.Contains("Intel", StringComparison.OrdinalIgnoreCase))
            return ("STORY:VENDOR_INTEL_TB", "Intel / Thunderbolt System Software");
        if (combined.Contains("Audials", StringComparison.OrdinalIgnoreCase))
            return ("STORY:VENDOR_AUDIALS", "Audials Media Software");
        if (combined.Contains("OfficeClickToRun", StringComparison.OrdinalIgnoreCase) || combined.Contains("OfficeC2RClient", StringComparison.OrdinalIgnoreCase) || combined.Contains("Microsoft Office", StringComparison.OrdinalIgnoreCase))
            return ("STORY:MS_OFFICE_UPDATE", "Microsoft Office Automatic Update & Background Tasks");

        // Program Files 配下のサブフォルダ名があればそれでグルーピング
        string clean = PathHelper.CleanFilePath(filePath);
        if (PathHelper.IsProgramFilesLocation(clean))
        {
            var parts = clean.Split('\\', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 3)
            {
                string vendorFolder = parts[2];
                return ($"STORY:APP:{vendorFolder.ToUpperInvariant()}", $"{vendorFolder} Application Suite");
            }
        }

        return ("", "");
    }

    private static void ScanRunRegistryKeys(List<RawAutostartEntry> list)
    {
        (RegistryKey Root, string RootName, string SubKey)[] targets =
        {
            (Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (Registry.CurrentUser, "HKCU", @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.CurrentUser, "HKCU", @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (Registry.LocalMachine, "HKLM", @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.LocalMachine, "HKLM", @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
        };

        foreach (var (root, rootName, subKey) in targets)
        {
            try
            {
                using var key = root.OpenSubKey(subKey, false);
                if (key == null) continue;
                foreach (var valName in key.GetValueNames())
                {
                    string cmd = key.GetValue(valName)?.ToString() ?? "";
                    if (string.IsNullOrWhiteSpace(cmd)) continue;
                    string loc = $"{rootName}\\{subKey}";
                    string catLabel = subKey.Contains("RunOnce", StringComparison.OrdinalIgnoreCase)
                        ? Loc.T($"Registry RunOnce ({rootName})", $"注册表 RunOnce ({rootName})", $"Registro RunOnce ({rootName})", $"レジストリRunOnce ({rootName})")
                        : subKey.Contains("Policies", StringComparison.OrdinalIgnoreCase)
                            ? Loc.T($"Policy Run ({rootName})", $"策略 Run ({rootName})", $"Directiva Run ({rootName})", $"ポリシーRun ({rootName})")
                            : Loc.T($"Registry Run ({rootName})", $"注册表 Run ({rootName})", $"Registro Run ({rootName})", $"レジストリRun ({rootName})");

                    string defaultValName = Loc.T("(Default)", "(默认)", "(Predeterminado)", "(既定)");
                    list.Add(new RawAutostartEntry(
                        $"REG:{loc}:{valName}",
                        catLabel,
                        string.IsNullOrEmpty(valName) ? defaultValName : valName,
                        cmd,
                        loc,
                        IsRunOrStartup: true));
                }
            }
            catch { }
        }
    }

    private static void ScanWinlogonKeys(List<RawAutostartEntry> list)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", false);
            if (key == null) return;

            string shell = (key.GetValue("Shell")?.ToString() ?? "").Trim();
            if (!string.IsNullOrEmpty(shell) && !shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
            {
                list.Add(new RawAutostartEntry(
                    "WINLOGON:Shell",
                    Loc.T("Winlogon Shell Tampering", "Winlogon Shell 篡改", "Manipulación de Winlogon Shell", "Winlogon Shell改ざん"),
                    "Shell",
                    shell,
                    @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
                    IsIfeoOrWinlogon: true));
            }

            string userinit = (key.GetValue("Userinit")?.ToString() ?? "").Trim();
            var parts = userinit.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length > 1 || (parts.Length == 1 && !parts[0].EndsWith("userinit.exe", StringComparison.OrdinalIgnoreCase)))
            {
                list.Add(new RawAutostartEntry(
                    "WINLOGON:Userinit",
                    Loc.T("Winlogon Userinit Tampering", "Winlogon Userinit 篡改", "Manipulación de Winlogon Userinit", "Winlogon Userinit改ざん"),
                    "Userinit",
                    userinit,
                    @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
                    IsIfeoOrWinlogon: true));
            }
        }
        catch { }
    }

    private static void ScanIfeoKeys(List<RawAutostartEntry> list)
    {
        try
        {
            const string ifeoPath = @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            using var key = Registry.LocalMachine.OpenSubKey(ifeoPath, false);
            if (key == null) return;
            foreach (var sub in key.GetSubKeyNames())
            {
                try
                {
                    using var subKey = key.OpenSubKey(sub, false);
                    string? debugger = subKey?.GetValue("Debugger")?.ToString();
                    if (!string.IsNullOrWhiteSpace(debugger))
                    {
                        list.Add(new RawAutostartEntry(
                            $"IFEO:{sub}",
                            Loc.T("IFEO Debugger Hijack", "IFEO Debugger 劫持", "Secuestro de IFEO Debugger", "IFEO Debuggerハイジャック"),
                            sub,
                            debugger,
                            $"HKLM\\{ifeoPath}\\{sub}",
                            IsIfeoOrWinlogon: true));
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static void ScanStartupFolders(List<RawAutostartEntry> list)
    {
        (string Label, Environment.SpecialFolder Folder)[] folders =
        {
            (Loc.T("Startup (User)", "启动文件夹(当前用户)", "Inicio (Usuario)", "スタートアップ(ユーザー)"), Environment.SpecialFolder.Startup),
            (Loc.T("Startup (All Users)", "启动文件夹(所有用户)", "Inicio (Todos los usuarios)", "スタートアップ(全ユーザー)"), Environment.SpecialFolder.CommonStartup)
        };

        foreach (var (label, sf) in folders)
        {
            try
            {
                string dir = Environment.GetFolderPath(sf);
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;

                foreach (var file in Directory.GetFiles(dir))
                {
                    string fileName = Path.GetFileName(file);
                    if (fileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;

                    string target = file;
                    if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    {
                        string resolved = ResolveShortcutTarget(file);
                        if (!string.IsNullOrEmpty(resolved)) target = resolved;
                    }

                    list.Add(new RawAutostartEntry(
                        $"STARTUP:{file.ToLowerInvariant()}",
                        label,
                        fileName,
                        target,
                        file,
                        IsRunOrStartup: true));
                }
            }
            catch { }
        }
    }

    private static string ResolveShortcutTarget(string lnkPath)
    {
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) return lnkPath;
            dynamic shell = Activator.CreateInstance(shellType)!;
            dynamic shortcut = shell.CreateShortcut(lnkPath);
            string targetPath = shortcut.TargetPath as string ?? "";
            string args = shortcut.Arguments as string ?? "";
            return string.IsNullOrWhiteSpace(args) ? targetPath : $"\"{targetPath}\" {args}";
        }
        catch
        {
            return lnkPath;
        }
    }

    private static void ScanServices(List<RawAutostartEntry> list)
    {
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false);
            if (servicesKey == null) return;

            string svcLabel = Loc.T("Autostart Service", "自启动服务", "Servicio de Autoinicio", "自動起動サービス");

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                try
                {
                    using var sk = servicesKey.OpenSubKey(svcName, false);
                    if (sk == null) continue;

                    // Start: 2=Auto (自動起動)
                    int start = Convert.ToInt32(sk.GetValue("Start") ?? 4);
                    int type = Convert.ToInt32(sk.GetValue("Type") ?? 0);
                    // Type 16 (OwnProcess) / 32 (ShareProcess) / 0x50 / 0x60 (Per-User Service) の Win32 サービスを対象
                    if (start != 2 || (type & 0xF0) == 0) continue;

                    string imagePath = sk.GetValue("ImagePath")?.ToString() ?? "";
                    if (string.IsNullOrWhiteSpace(imagePath)) continue;

                    string serviceAccount = sk.GetValue("ObjectName")?.ToString() ?? "LocalSystem";
                    string svchostGroup = ExtractSvchostGroup(imagePath);

                    // ImagePath と ServiceDll を混同せず別々に取得・保持する (要件 #1)
                    string serviceDll = "";
                    using (var paramKey = sk.OpenSubKey("Parameters", false))
                    {
                        serviceDll = paramKey?.GetValue("ServiceDll")?.ToString() ?? "";
                    }
                    if (string.IsNullOrWhiteSpace(serviceDll))
                    {
                        serviceDll = sk.GetValue("ServiceDll")?.ToString() ?? "";
                    }

                    var (normalizedName, isPerUser) = NormalizePerUserServiceName(svcName, type);

                    // 同一ベース名の Per-User サービスが既にリストにある場合、代表1件に統合（重複ノイズ防止）
                    string entryKey = $"SVC:{normalizedName}";
                    if (isPerUser && list.Any(x => x.Key.Equals(entryKey, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    var meta = new ServiceMetadata(
                        ServiceName: svcName,
                        NormalizedName: normalizedName,
                        ImagePath: imagePath,
                        ServiceDll: serviceDll,
                        SvchostGroup: svchostGroup,
                        ServiceType: type,
                        StartType: start,
                        ServiceAccount: serviceAccount,
                        IsPerUserService: isPerUser);

                    string displayCmd = !string.IsNullOrWhiteSpace(serviceDll)
                        ? $"{imagePath} -> [ServiceDll: {serviceDll}]"
                        : imagePath;

                    list.Add(new RawAutostartEntry(
                        entryKey,
                        svcLabel,
                        svcName,
                        displayCmd,
                        $"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svcName}",
                        ServiceMeta: meta));
                }
                catch { }
            }
        }
        catch { }
    }

    private static string ExtractSvchostGroup(string imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath) || !imagePath.Contains("svchost", StringComparison.OrdinalIgnoreCase))
            return "";
        var parts = imagePath.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < parts.Length - 1; i++)
        {
            if (parts[i].Equals("-k", StringComparison.OrdinalIgnoreCase) ||
                parts[i].Equals("/k", StringComparison.OrdinalIgnoreCase))
            {
                return parts[i + 1].Trim('"', '\'');
            }
        }
        return "";
    }

    private static (string NormalizedName, bool IsPerUser) NormalizePerUserServiceName(string svcName, int serviceType)
    {
        bool isPerUserType = (serviceType & 0x40) != 0;
        int idx = svcName.LastIndexOf('_');
        if (idx > 2 && idx + 1 < svcName.Length)
        {
            string suffix = svcName[(idx + 1)..];
            if (suffix.Length is >= 4 and <= 8 && suffix.All(Uri.IsHexDigit))
            {
                string baseName = svcName[..idx];
                return (baseName, true);
            }
        }
        if (StandardPerUserServices.Contains(svcName))
            return (svcName, true);

        return (svcName, isPerUserType);
    }

    private static void ScanScheduledTasks(List<RawAutostartEntry> list)
    {
        try
        {
            var entries = StaRunner.Run(() =>
            {
                var found = new List<RawAutostartEntry>();
                var t = Type.GetTypeFromProgID("Schedule.Service");
                if (t == null) return found;
                dynamic service = Activator.CreateInstance(t)!;
                service.Connect();
                dynamic root = service.GetFolder("\\");
                EnumTaskFolder(root, found, 0);
                return found;
            }, new List<RawAutostartEntry>(), 8000);

            list.AddRange(entries);
        }
        catch { }
    }

    private static void EnumTaskFolder(dynamic folder, List<RawAutostartEntry> found, int depth)
    {
        if (depth > 4) return;
        try
        {
            string folderPath = folder.Path as string ?? "\\";
            // Microsoft 標準タスクフォルダ (\Microsoft\Windows\...) は件数が多く標準機能のため除外
            if (folderPath.StartsWith(@"\Microsoft\Windows", StringComparison.OrdinalIgnoreCase))
                return;

            string taskLabel = Loc.T("Scheduled Task", "计划任务", "Tarea Programada", "スケジュールタスク");
            string taskComLabel = Loc.T("Scheduled Task (COM)", "计划任务(COM)", "Tarea Programada (COM)", "スケジュールタスク(COM)");

            dynamic tasks = folder.GetTasks(0);
            int count = tasks.Count;
            for (int i = 1; i <= count; i++)
            {
                try
                {
                    dynamic task = tasks[i];
                    bool enabled = false;
                    try { enabled = (bool)task.Enabled; } catch { }
                    if (!enabled) continue;

                    string name = task.Name as string ?? "Task";
                    string path = task.Path as string ?? name;
                    dynamic def = task.Definition;
                    dynamic actions = def.Actions;
                    int actCount = actions.Count;
                    for (int a = 1; a <= actCount; a++)
                    {
                        try
                        {
                            dynamic act = actions[a];
                            int actType = (int)act.Type;
                            if (actType == 0) // TASK_ACTION_EXEC
                            {
                                string exe = act.Path as string ?? "";
                                string args = "";
                                try { args = act.Arguments as string ?? ""; } catch { }
                                string fullCmd = string.IsNullOrWhiteSpace(args) ? exe : $"{exe} {args}";
                                if (!string.IsNullOrWhiteSpace(fullCmd))
                                {
                                    found.Add(new RawAutostartEntry(
                                        $"TASK:{path}:{a}",
                                        taskLabel,
                                        path,
                                        fullCmd,
                                        $"TaskScheduler:{path}"));
                                }
                            }
                            else if (actType == 5) // TASK_ACTION_COM_HANDLER (CLSID を HKCR\CLSID から実ファイルへ解決)
                            {
                                string clsid = "";
                                string data = "";
                                try { clsid = act.ClassId as string ?? ""; } catch { }
                                try { data = act.Data as string ?? ""; } catch { }
                                if (!string.IsNullOrWhiteSpace(clsid))
                                {
                                    var resolvedCom = ComClsidResolver.Resolve(clsid);
                                    var comMeta = new ComTaskMetadata(clsid, data, resolvedCom);
                                    string cmdDesc = resolvedCom.IsResolved
                                        ? $"COM CLSID:{clsid} -> {resolvedCom.ResolvedBinaryPath}"
                                        : $"COM CLSID:{clsid} (Unresolved)";

                                    found.Add(new RawAutostartEntry(
                                        $"TASK:{path}:{a}",
                                        taskComLabel,
                                        path,
                                        cmdDesc,
                                        $"TaskScheduler:{path}",
                                        ComMeta: comMeta));
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            dynamic subFolders = folder.GetFolders(0);
            int subCount = subFolders.Count;
            for (int i = 1; i <= subCount; i++)
            {
                try { EnumTaskFolder(subFolders[i], found, depth + 1); } catch { }
            }
        }
        catch { }
    }
}
