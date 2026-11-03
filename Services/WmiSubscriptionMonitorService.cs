using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Security.Principal;
using AnzenSecurityWatcher.Models;

namespace AnzenSecurityWatcher.Services;

/// <summary>
/// WMI イベントサブスクリプション監視サービス (要件 #4 改善版)
/// - __EventFilter / __FilterToConsumerBinding の存在だけで一律に危険視せず、
///   Consumer の型 (NTEventLogEventConsumer vs CommandLineEventConsumer vs ActiveScriptEventConsumer) と実際のペイロードで評価する。
/// - Filter, Consumer, Binding, CreatorSID, CommandLineTemplate / ScriptText を統合表示し、
///   無条件の削除推奨を行わない。
/// </summary>
public class WmiSubscriptionMonitorService
{
    private const string BaselineFile = "wmi_subscription_baseline.json";

    private Dictionary<string, string> _baseline = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _latestPayloads = new(StringComparer.OrdinalIgnoreCase);
    private bool _baselineLoaded;

    private record WmiFilterInfo(
        string Name,
        string Query,
        string QueryLanguage,
        string EventNamespace,
        string CreatorSid);

    private record WmiConsumerInfo(
        string Name,
        string ConsumerClass,      // NTEventLogEventConsumer / CommandLineEventConsumer / ActiveScriptEventConsumer / LogFileEventConsumer / Other
        string CommandOrScript,    // CommandLineTemplate / ExecutablePath / ScriptText / SourceName
        string CreatorSid,
        bool IsExecutableConsumer);

    private record RawWmiSubscriptionItem(
        string Key,
        string Namespace,
        string ConsumerClass,
        string Name,
        string FilterName,
        string FilterQuery,
        string ConsumerName,
        string CommandOrScript,
        string BindingSummary,
        string CreatorSid,
        bool IsExecutableConsumer);

    // Windows 既定の SCM Event Log Consumer / BVTFilter かどうか
    private static bool IsDefaultWindowsScmSubscription(string name, string filterName, string consumerName, string payload)
    {
        string all = $"{name} {filterName} {consumerName} {payload}";
        if (all.Contains("SCM Event Log Consumer", StringComparison.OrdinalIgnoreCase) ||
            all.Contains("BVTFilter", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    public List<FindingReport> Scan()
    {
        EnsureBaselineLoaded();
        var reports = new List<FindingReport>();

        var rawItems = StaRunner.Run(QueryAllWmiSubscriptions, new List<RawWmiSubscriptionItem>(), 8000);

        bool isFirstBaseline = _baseline.Count == 0;
        bool baselineModified = false;

        if (isFirstBaseline)
        {
            _baseline["__INITIALIZED__"] = DateTime.Now.ToString("O");
            baselineModified = true;
        }

        foreach (var item in rawItems)
        {
            _latestPayloads[item.Key] = item.CommandOrScript;

            bool isDefaultScm = IsDefaultWindowsScmSubscription(item.Name, item.FilterName, item.ConsumerName, item.CommandOrScript);
            bool isNewOrChanged = false;
            string changeNote = "";

            if (isFirstBaseline)
            {
                _baseline[item.Key] = item.CommandOrScript;
                baselineModified = true;
            }
            else if (!_baseline.TryGetValue(item.Key, out var oldVal))
            {
                isNewOrChanged = true;
                changeNote = Loc.T(
                    "🆕 Newly registered WMI event subscription after monitoring started",
                    "🆕 监控开始后新注册的 WMI 事件订阅",
                    "🆕 Suscripción de eventos WMI recién registrada tras iniciar el monitoreo",
                    "🆕 監視開始後に新規登録された WMI イベントサブスクリプション");
            }
            else if (!string.Equals(oldVal.Trim(), item.CommandOrScript.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                isNewOrChanged = true;
                string shortOld = CommandLineAnalyzer.Shorten(oldVal, 80);
                changeNote = Loc.T(
                    $"✏️ Existing WMI subscription payload modified (Prev: {shortOld})",
                    $"✏️ 现有 WMI 订阅内容已被修改 (原: {shortOld})",
                    $"✏️ Contenido de suscripción WMI existente modificado (Ant.: {shortOld})",
                    $"✏️ 既存の WMI サブスクリプション内容が変更されました (旧: {shortOld})");
            }

            // Windows 標準の SCM Event Log Consumer は変更がない限りスキップ
            if (isDefaultScm && !isNewOrChanged)
                continue;

            var reasons = new List<string>();
            RiskLevel risk;
            ConfidenceLevel confidence;

            // 要件 #4: Consumer 種別とペイロード内容による段階的危険度判定
            if (item.ConsumerClass.Equals("NTEventLogEventConsumer", StringComparison.OrdinalIgnoreCase) ||
                item.ConsumerClass.Equals("LogFileEventConsumer", StringComparison.OrdinalIgnoreCase) ||
                !item.IsExecutableConsumer)
            {
                // NTEventLogEventConsumer やコマンド実行を伴わない Filter/Binding は Low (Informational)
                risk = isNewOrChanged ? RiskLevel.Medium : RiskLevel.Low;
                confidence = ConfidenceLevel.High;
                reasons.Add(Loc.T(
                    $"Non-executable WMI subscription ({item.ConsumerClass} — event logging / filter only)",
                    $"非命令执行型 WMI 订阅 ({item.ConsumerClass} — 仅用于事件日志记录或过滤)",
                    $"Suscripción WMI no ejecutable ({item.ConsumerClass} — solo registro de eventos)",
                    $"コマンド実行を伴わないWMI定義 ({item.ConsumerClass} — イベントログ記録/フィルタのみ)"));
            }
            else if (item.ConsumerClass.Equals("CommandLineEventConsumer", StringComparison.OrdinalIgnoreCase))
            {
                // CommandLineEventConsumer: 基本は Medium (Caution)、PowerShell/cmd/wscript/mshta 等の不審ペイロードがあれば High/Critical
                risk = RiskLevel.Medium;
                confidence = ConfidenceLevel.Medium;

                var cmdAnalysis = CommandLineAnalyzer.Analyze(item.CommandOrScript, "wmiprvse");
                bool invokesShellOrLolbin = ContainsShellOrScriptHost(item.CommandOrScript);

                if (cmdAnalysis.IsSuspicious || invokesShellOrLolbin)
                {
                    risk = (cmdAnalysis.Risk == RiskLevel.Critical || isNewOrChanged) ? RiskLevel.Critical : RiskLevel.High;
                    confidence = ConfidenceLevel.High;
                    reasons.Add(Loc.T(
                        "CommandLineEventConsumer executing shell/script host (PowerShell / cmd / wscript / mshta)",
                        "CommandLineEventConsumer 正在调用命令行或脚本宿主 (PowerShell / cmd / wscript / mshta)",
                        "CommandLineEventConsumer ejecutando intérprete de comandos/scripts",
                        "CommandLineEventConsumer がシェル/スクリプトホスト (PowerShell / cmd / wscript / mshta等) を実行"));
                    if (cmdAnalysis.Reasons.Count > 0)
                        reasons.AddRange(cmdAnalysis.Reasons);
                }
                else
                {
                    reasons.Add(Loc.T(
                        "CommandLineEventConsumer registered (Verify the target executable path and arguments)",
                        "已注册 CommandLineEventConsumer（请核对目标可执行文件路径与参数）",
                        "CommandLineEventConsumer registrado (Verifique la ruta del ejecutable y argumentos)",
                        "CommandLineEventConsumer が登録されています (実行先バイナリと引数を確認してください)"));
                }
            }
            else if (item.ConsumerClass.Equals("ActiveScriptEventConsumer", StringComparison.OrdinalIgnoreCase))
            {
                var scriptAnalysis = CommandLineAnalyzer.Analyze(item.CommandOrScript, "wscript");
                bool isObfuscated = scriptAnalysis.IsSuspicious ||
                                    item.CommandOrScript.Contains("CreateObject", StringComparison.OrdinalIgnoreCase) ||
                                    item.CommandOrScript.Contains("WScript.Shell", StringComparison.OrdinalIgnoreCase) ||
                                    item.CommandOrScript.Contains("XMLHTTP", StringComparison.OrdinalIgnoreCase) ||
                                    item.CommandOrScript.Contains("chr(", StringComparison.OrdinalIgnoreCase);

                risk = isObfuscated ? (isNewOrChanged ? RiskLevel.Critical : RiskLevel.High) : RiskLevel.Medium;
                confidence = isObfuscated ? ConfidenceLevel.High : ConfidenceLevel.Medium;
                reasons.Add(isObfuscated
                    ? Loc.T(
                        "ActiveScriptEventConsumer containing suspicious/obfuscated script payload",
                        "ActiveScriptEventConsumer 包含可疑或混淆的脚本载荷",
                        "ActiveScriptEventConsumer con script sospechoso u ofuscado",
                        "ActiveScriptEventConsumer に不審または難読化されたスクリプトが含まれています")
                    : Loc.T(
                        "ActiveScriptEventConsumer registered (Inspect ScriptText content)",
                        "已注册 ActiveScriptEventConsumer（请检查 ScriptText 内容）",
                        "ActiveScriptEventConsumer registrado (Inspeccione ScriptText)",
                        "ActiveScriptEventConsumer が登録されています (ScriptTextの内容を確認してください)"));
            }
            else
            {
                risk = RiskLevel.Low;
                confidence = ConfidenceLevel.Low;
                reasons.Add($"WMI Subscription ({item.ConsumerClass})");
            }

            if (isNewOrChanged && !string.IsNullOrEmpty(changeNote))
            {
                reasons.Insert(0, changeNote);
            }

            var state = isNewOrChanged ? FindingState.New : FindingState.Existing;
            string title = $"👻 [WMI {item.ConsumerClass}] {item.Name} ({item.Namespace})";
            string contentLabel = Loc.T("Payload", "载荷", "Carga", "実行内容");
            string detail = $"{string.Join(" / ", reasons)} — {contentLabel}: {CommandLineAnalyzer.Shorten(item.CommandOrScript, 130)}";

            string diffStatus = isNewOrChanged
                ? Loc.T("🆕 Newly added or modified", "🆕 新增或已修改", "🆕 Nuevo o modificado", "🆕 新規登録または変更")
                : Loc.T("Existing (Matches baseline)", "既有 (与基线一致)", "Existente (Coincide con línea base)", "既存 (ベースライン一致)");
            string reasonsJoined = string.Join(" / ", reasons);

            // 要件 #4: Filter, Consumer, Binding, CreatorSID, CommandLineTemplate / ScriptText をすべて明示表示
            string tech = Loc.T(
                $"WMI Namespace: {item.Namespace}\n" +
                $"Consumer Type: {item.ConsumerClass}\n" +
                $"Filter: {item.FilterName} — Query: {(string.IsNullOrEmpty(item.FilterQuery) ? "(None)" : item.FilterQuery)}\n" +
                $"Consumer: {item.ConsumerName}\n" +
                $"Binding: {item.BindingSummary}\n" +
                $"CreatorSID: {item.CreatorSid}\n" +
                $"CommandLineTemplate / ScriptText:\n{item.CommandOrScript}\n" +
                $"Baseline Status: {diffStatus}\n" +
                $"Reason: {reasonsJoined}",
                $"WMI 命名空间: {item.Namespace}\n" +
                $"Consumer 类型: {item.ConsumerClass}\n" +
                $"Filter (触发器): {item.FilterName} — WQL: {(string.IsNullOrEmpty(item.FilterQuery) ? "(无)" : item.FilterQuery)}\n" +
                $"Consumer (消费者): {item.ConsumerName}\n" +
                $"Binding (绑定): {item.BindingSummary}\n" +
                $"CreatorSID (创建者SID): {item.CreatorSid}\n" +
                $"CommandLineTemplate / ScriptText:\n{item.CommandOrScript}\n" +
                $"基线状态: {diffStatus}\n" +
                $"判定原因: {reasonsJoined}",
                $"Espacio de nombres WMI: {item.Namespace}\n" +
                $"Tipo de Consumer: {item.ConsumerClass}\n" +
                $"Filter: {item.FilterName} — WQL: {(string.IsNullOrEmpty(item.FilterQuery) ? "(Ninguno)" : item.FilterQuery)}\n" +
                $"Consumer: {item.ConsumerName}\n" +
                $"Binding: {item.BindingSummary}\n" +
                $"CreatorSID: {item.CreatorSid}\n" +
                $"CommandLineTemplate / ScriptText:\n{item.CommandOrScript}\n" +
                $"Estado de línea base: {diffStatus}\n" +
                $"Motivo: {reasonsJoined}",
                $"WMI 名前空間: {item.Namespace}\n" +
                $"Consumer 種別: {item.ConsumerClass}\n" +
                $"Filter (イベント条件): {item.FilterName} — WQL: {(string.IsNullOrEmpty(item.FilterQuery) ? "(なし)" : item.FilterQuery)}\n" +
                $"Consumer (実行定義): {item.ConsumerName}\n" +
                $"Binding (紐付け): {item.BindingSummary}\n" +
                $"CreatorSID (作成者SID): {item.CreatorSid}\n" +
                $"CommandLineTemplate / ScriptText:\n{item.CommandOrScript}\n" +
                $"差分状態: {diffStatus}\n" +
                $"判定理由: {reasonsJoined}");

            // 要件 #4: WMI サブスクリプションの存在だけで無条件の削除を勧めない
            string recAction = item.IsExecutableConsumer
                ? Loc.T(
                    "Review the Filter, Consumer, CreatorSID, and CommandLineTemplate/ScriptText above. Do NOT delete WMI subscriptions blindly; only remove them via Autoruns (WMI tab) if the command or script payload is confirmed to be unauthorized.",
                    "请先核对上方的 Filter、Consumer、CreatorSID 以及 CommandLineTemplate/ScriptText。切勿仅因存在 WMI 订阅就盲目删除；仅在确认命令或脚本属于未授权恶意载荷时，再通过 Autoruns (WMI 选项卡) 清除。",
                    "Revise Filter, Consumer, CreatorSID y CommandLineTemplate/ScriptText antes de actuar. No elimine suscripciones WMI solo por existir; hágalo únicamente si confirma que el comando o script no está autorizado.",
                    "上記の Filter・Consumer・Binding・CreatorSID・CommandLineTemplate/ScriptText の内容を確認してください。WMIサブスクリプションの存在だけで安易に削除せず、実行コマンドやスクリプトが身に覚えのない不正なものであると確認できた場合のみ Autoruns (WMIタブ) 等で対処してください。")
                : Loc.T(
                    "This WMI subscription uses a non-executable consumer (such as NTEventLogEventConsumer) or is a standard system filter. No deletion is required.",
                    "此 WMI 订阅使用非执行型消费者（如 NTEventLogEventConsumer）或标准系统过滤器，属于正常机制，无需删除。",
                    "Esta suscripción WMI utiliza un consumidor no ejecutable (como NTEventLogEventConsumer). No requiere eliminación.",
                    "このWMIサブスクリプションはコマンド実行を伴わない標準機構（NTEventLogEventConsumer等）です。削除の必要はありません。");

            reports.Add(new FindingReport(
                Key: $"WMI:{item.Key}",
                Category: FindingCategory.WmiSubscription,
                Severity: risk,
                State: state,
                Title: title,
                Detail: detail,
                Target: $"{item.Namespace}:{item.ConsumerClass}:{item.Name}",
                TechnicalDetails: tech,
                RecommendedAction: recAction,
                Confidence: confidence,
                StoryKey: item.IsExecutableConsumer ? $"STORY:WMI_EXEC:{item.Name}" : "STORY:WMI_STD",
                StoryTitle: item.IsExecutableConsumer ? $"WMI Executable Persistence ({item.Name})" : "Standard WMI Event Subscriptions"));
        }

        if (baselineModified)
            JsonStore.Save(BaselineFile, _baseline);

        ScanWmiActivityEventLog(reports);
        return reports;
    }

    private static bool ContainsShellOrScriptHost(string cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd)) return false;
        string lower = cmd.ToLowerInvariant();
        return lower.Contains("powershell") ||
               lower.Contains("pwsh") ||
               lower.Contains("cmd.exe") ||
               lower.Contains("cmd /c") ||
               lower.Contains("wscript") ||
               lower.Contains("cscript") ||
               lower.Contains("mshta") ||
               lower.Contains("rundll32") ||
               lower.Contains("regsvr32") ||
               lower.Contains("certutil") ||
               lower.Contains("bitsadmin");
    }

    public void ApproveEntry(string findingKey)
    {
        if (!findingKey.StartsWith("WMI:", StringComparison.OrdinalIgnoreCase)) return;
        string rawKey = findingKey["WMI:".Length..];
        EnsureBaselineLoaded();
        if (_latestPayloads.TryGetValue(rawKey, out var currentVal))
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

    private static List<RawWmiSubscriptionItem> QueryAllWmiSubscriptions()
    {
        var result = new List<RawWmiSubscriptionItem>();
        string[] namespaces = { @"root\subscription", @"root\default" };

        foreach (var ns in namespaces)
        {
            try
            {
                var filterMap = new Dictionary<string, WmiFilterInfo>(StringComparer.OrdinalIgnoreCase);
                var consumerMap = new Dictionary<string, WmiConsumerInfo>(StringComparer.OrdinalIgnoreCase);
                var boundFilterNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var boundConsumerNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                // 1. __EventFilter の取得
                var filters = WmiHelper.Query(ns, "SELECT Name, Query, QueryLanguage, EventNamespace, CreatorSID FROM __EventFilter",
                    "Name", "Query", "QueryLanguage", "EventNamespace", "CreatorSID");
                if (filters != null)
                {
                    foreach (var f in filters)
                    {
                        string name = f.GetValueOrDefault("Name")?.ToString() ?? "(UnnamedFilter)";
                        string query = f.GetValueOrDefault("Query")?.ToString() ?? "";
                        string lang = f.GetValueOrDefault("QueryLanguage")?.ToString() ?? "WQL";
                        string evNs = f.GetValueOrDefault("EventNamespace")?.ToString() ?? "";
                        string sid = FormatCreatorSid(f.GetValueOrDefault("CreatorSID"));
                        filterMap[name] = new WmiFilterInfo(name, query, lang, evNs, sid);
                    }
                }

                // 2. NTEventLogEventConsumer の取得
                var ntLogConsumers = WmiHelper.Query(ns,
                    "SELECT Name, SourceName, EventID, CreatorSID FROM NTEventLogEventConsumer",
                    "Name", "SourceName", "EventID", "CreatorSID");
                if (ntLogConsumers != null)
                {
                    foreach (var c in ntLogConsumers)
                    {
                        string name = c.GetValueOrDefault("Name")?.ToString() ?? "(UnnamedNTLogConsumer)";
                        string src = c.GetValueOrDefault("SourceName")?.ToString() ?? "EventLog";
                        string evId = c.GetValueOrDefault("EventID")?.ToString() ?? "";
                        string sid = FormatCreatorSid(c.GetValueOrDefault("CreatorSID"));
                        consumerMap[name] = new WmiConsumerInfo(
                            name,
                            "NTEventLogEventConsumer",
                            $"NTEventLog Source={src}, EventID={evId}",
                            sid,
                            IsExecutableConsumer: false);
                    }
                }

                // 3. CommandLineEventConsumer の取得
                var cmdConsumers = WmiHelper.Query(ns,
                    "SELECT Name, CommandLineTemplate, ExecutablePath, WorkingDirectory, CreatorSID FROM CommandLineEventConsumer",
                    "Name", "CommandLineTemplate", "ExecutablePath", "WorkingDirectory", "CreatorSID");
                if (cmdConsumers != null)
                {
                    foreach (var c in cmdConsumers)
                    {
                        string name = c.GetValueOrDefault("Name")?.ToString() ?? "(UnnamedCmdConsumer)";
                        string tpl = c.GetValueOrDefault("CommandLineTemplate")?.ToString() ?? "";
                        string exe = c.GetValueOrDefault("ExecutablePath")?.ToString() ?? "";
                        string dir = c.GetValueOrDefault("WorkingDirectory")?.ToString() ?? "";
                        string sid = FormatCreatorSid(c.GetValueOrDefault("CreatorSID"));
                        string cmd = !string.IsNullOrWhiteSpace(tpl) ? tpl : exe;
                        if (!string.IsNullOrWhiteSpace(exe) && !string.IsNullOrWhiteSpace(tpl) && !tpl.Contains(exe, StringComparison.OrdinalIgnoreCase))
                            cmd = $"\"{exe}\" {tpl}";
                        if (!string.IsNullOrWhiteSpace(dir))
                            cmd += $" (WorkDir: {dir})";

                        consumerMap[name] = new WmiConsumerInfo(
                            name,
                            "CommandLineEventConsumer",
                            cmd,
                            sid,
                            IsExecutableConsumer: true);
                    }
                }

                // 4. ActiveScriptEventConsumer の取得
                var scriptConsumers = WmiHelper.Query(ns,
                    "SELECT Name, ScriptingEngine, ScriptText, ScriptFileName, CreatorSID FROM ActiveScriptEventConsumer",
                    "Name", "ScriptingEngine", "ScriptText", "ScriptFileName", "CreatorSID");
                if (scriptConsumers != null)
                {
                    foreach (var s in scriptConsumers)
                    {
                        string name = s.GetValueOrDefault("Name")?.ToString() ?? "(UnnamedScriptConsumer)";
                        string engine = s.GetValueOrDefault("ScriptingEngine")?.ToString() ?? "Script";
                        string text = s.GetValueOrDefault("ScriptText")?.ToString() ?? "";
                        string file = s.GetValueOrDefault("ScriptFileName")?.ToString() ?? "";
                        string sid = FormatCreatorSid(s.GetValueOrDefault("CreatorSID"));
                        string payload = !string.IsNullOrWhiteSpace(text)
                            ? $"[{engine}] {text}"
                            : $"[{engine}] File: {file}";

                        consumerMap[name] = new WmiConsumerInfo(
                            name,
                            "ActiveScriptEventConsumer",
                            payload,
                            sid,
                            IsExecutableConsumer: true);
                    }
                }

                // 5. __FilterToConsumerBinding を走査し、Filter と Consumer を1つの完全なサブスクリプションエントリとして結合評価する
                var bindings = WmiHelper.Query(ns,
                    "SELECT Filter, Consumer, CreatorSID FROM __FilterToConsumerBinding",
                    "Filter", "Consumer", "CreatorSID");
                if (bindings != null)
                {
                    foreach (var b in bindings)
                    {
                        string filterRef = b.GetValueOrDefault("Filter")?.ToString() ?? "";
                        string consumerRef = b.GetValueOrDefault("Consumer")?.ToString() ?? "";
                        if (string.IsNullOrWhiteSpace(filterRef) && string.IsNullOrWhiteSpace(consumerRef))
                            continue;

                        string fName = ExtractWmiObjectName(filterRef);
                        string cName = ExtractWmiObjectName(consumerRef);
                        boundFilterNames.Add(fName);
                        boundConsumerNames.Add(cName);

                        filterMap.TryGetValue(fName, out var fInfo);
                        consumerMap.TryGetValue(cName, out var cInfo);

                        string cClass = cInfo?.ConsumerClass ?? ExtractConsumerClassFromRef(consumerRef);
                        bool isExec = cInfo?.IsExecutableConsumer
                                      ?? (cClass.Equals("CommandLineEventConsumer", StringComparison.OrdinalIgnoreCase) ||
                                          cClass.Equals("ActiveScriptEventConsumer", StringComparison.OrdinalIgnoreCase));

                        string sid = FormatCreatorSid(b.GetValueOrDefault("CreatorSID"));
                        if (sid == "—" && cInfo != null && cInfo.CreatorSid != "—") sid = cInfo.CreatorSid;
                        if (sid == "—" && fInfo != null && fInfo.CreatorSid != "—") sid = fInfo.CreatorSid;

                        string bindingName = $"{fName} -> {cName}";
                        string payload = cInfo != null
                            ? cInfo.CommandOrScript
                            : $"Filter: {filterRef} ==> Consumer: {consumerRef}";

                        result.Add(new RawWmiSubscriptionItem(
                            Key: $"{ns}:Subscription:{bindingName}",
                            Namespace: ns,
                            ConsumerClass: cClass,
                            Name: bindingName,
                            FilterName: fName,
                            FilterQuery: fInfo?.Query ?? "",
                            ConsumerName: cName,
                            CommandOrScript: payload,
                            BindingSummary: $"{filterRef} ==> {consumerRef}",
                            CreatorSid: sid,
                            IsExecutableConsumer: isExec));
                    }
                }

                // 6. まだバインドされていない独立した CommandLine / ActiveScript Consumer が残っていれば追加
                foreach (var kv in consumerMap)
                {
                    if (boundConsumerNames.Contains(kv.Key)) continue;
                    var c = kv.Value;
                    result.Add(new RawWmiSubscriptionItem(
                        Key: $"{ns}:{c.ConsumerClass}:{c.Name}",
                        Namespace: ns,
                        ConsumerClass: c.ConsumerClass,
                        Name: c.Name,
                        FilterName: "(Unbound)",
                        FilterQuery: "",
                        ConsumerName: c.Name,
                        CommandOrScript: c.CommandOrScript,
                        BindingSummary: "(No active __FilterToConsumerBinding)",
                        CreatorSid: c.CreatorSid,
                        IsExecutableConsumer: c.IsExecutableConsumer));
                }
            }
            catch { }
        }

        return result;
    }

    private static string ExtractConsumerClassFromRef(string consumerRef)
    {
        if (string.IsNullOrWhiteSpace(consumerRef)) return "UnknownConsumer";
        if (consumerRef.Contains("NTEventLogEventConsumer", StringComparison.OrdinalIgnoreCase))
            return "NTEventLogEventConsumer";
        if (consumerRef.Contains("CommandLineEventConsumer", StringComparison.OrdinalIgnoreCase))
            return "CommandLineEventConsumer";
        if (consumerRef.Contains("ActiveScriptEventConsumer", StringComparison.OrdinalIgnoreCase))
            return "ActiveScriptEventConsumer";
        if (consumerRef.Contains("LogFileEventConsumer", StringComparison.OrdinalIgnoreCase))
            return "LogFileEventConsumer";
        return "WmiEventConsumer";
    }

    private static string FormatCreatorSid(object? rawSid)
    {
        try
        {
            if (rawSid is Array arr && arr.Length > 0)
            {
                byte[] bytes = new byte[arr.Length];
                for (int i = 0; i < arr.Length; i++)
                    bytes[i] = Convert.ToByte(arr.GetValue(i));

                var sid = new SecurityIdentifier(bytes, 0);
                string sidStr = sid.Value;
                try
                {
                    var acct = (NTAccount)sid.Translate(typeof(NTAccount));
                    return $"{acct.Value} ({sidStr})";
                }
                catch
                {
                    return sidStr;
                }
            }
        }
        catch { }
        return "—";
    }

    private static string ExtractWmiObjectName(string wmiRef)
    {
        if (string.IsNullOrEmpty(wmiRef)) return Loc.T("(Unknown)", "(未知)", "(Desconocido)", "(不明)");
        int idx = wmiRef.IndexOf("Name=", StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
        {
            string sub = wmiRef[(idx + 5)..].Trim();
            return sub.Trim('"', '\'');
        }
        return wmiRef;
    }

    private static void ScanWmiActivityEventLog(List<FindingReport> reports)
    {
        try
        {
            long msWindow = 7L * 24 * 3600 * 1000;
            string xpath = $"*[System[(EventID=5861) and TimeCreated[timediff(@SystemTime) <= {msWindow}]]]";
            var query = new EventLogQuery("Microsoft-Windows-WMI-Activity/Operational", PathType.LogName, xpath)
            {
                ReverseDirection = true
            };

            using var reader = new EventLogReader(query);
            int readCount = 0;
            for (EventRecord? rec = reader.ReadEvent(); rec != null && readCount < 25; rec = reader.ReadEvent(), readCount++)
            {
                using (rec)
                {
                    DateTime time = rec.TimeCreated ?? DateTime.Now;
                    string desc = "";
                    try { desc = rec.FormatDescription() ?? ""; } catch { }
                    if (IsDefaultWindowsScmSubscription("", "", "", desc))
                        continue;

                    bool isRecent = (DateTime.Now - time).TotalHours <= 24;
                    bool hasExecConsumer = desc.Contains("CommandLineEventConsumer", StringComparison.OrdinalIgnoreCase) ||
                                           desc.Contains("ActiveScriptEventConsumer", StringComparison.OrdinalIgnoreCase);
                    bool isNtEventLog = desc.Contains("NTEventLogEventConsumer", StringComparison.OrdinalIgnoreCase);

                    var risk = hasExecConsumer
                        ? (ContainsShellOrScriptHost(desc) ? RiskLevel.High : RiskLevel.Medium)
                        : isNtEventLog
                            ? RiskLevel.Low
                            : RiskLevel.Low;
                    var conf = hasExecConsumer ? ConfidenceLevel.High : ConfidenceLevel.Medium;

                    string oneLine = desc.Replace("\r", " ").Replace("\n", " ");

                    string title = Loc.T(
                        $"👻 [WMI Event Log (ID:5861)] Subscription Binding ({time:MM/dd HH:mm})",
                        $"👻 [WMI 事件日志 (ID:5861)] 订阅绑定记录 ({time:MM/dd HH:mm})",
                        $"👻 [Evento WMI (ID:5861)] Registro de suscripción ({time:MM/dd HH:mm})",
                        $"👻 [WMIイベントログ (ID:5861)] サブスクリプションバインディング記録 ({time:MM/dd HH:mm})");

                    string noDesc = Loc.T("(Details unavailable)", "(无法获取详情)", "(Detalles no disponibles)", "(詳細取得不可)");
                    string descShort = string.IsNullOrEmpty(desc) ? noDesc : CommandLineAnalyzer.Shorten(desc, 800);

                    string tech = Loc.T(
                        $"Channel: Microsoft-Windows-WMI-Activity/Operational\nEvent ID: 5861 (Permanent Subscription Binding)\nTimestamp: {time:yyyy-MM-dd HH:mm:ss}\nDetails:\n{descShort}",
                        $"通道: Microsoft-Windows-WMI-Activity/Operational\n事件 ID: 5861 (永久订阅绑定)\n发生时间: {time:yyyy-MM-dd HH:mm:ss}\n详情:\n{descShort}",
                        $"Canal: Microsoft-Windows-WMI-Activity/Operational\nID de evento: 5861 (Enlace de suscripción permanente)\nFecha/Hora: {time:yyyy-MM-dd HH:mm:ss}\nDetalles:\n{descShort}",
                        $"チャネル: Microsoft-Windows-WMI-Activity/Operational\nイベントID: 5861 (永続的サブスクリプションバインディング)\n発生日時: {time:yyyy-MM-dd HH:mm:ss}\n詳細:\n{descShort}");

                    string recAction = Loc.T(
                        "A WMI permanent subscription binding event (ID:5861) was logged. Check the Consumer type and payload before taking action.",
                        "已记录 WMI 永久订阅绑定事件 (ID:5861)，请先检查其 Consumer 类型与载荷内容。",
                        "Se registró un evento de suscripción WMI (ID:5861). Verifique el tipo de Consumer y contenido.",
                        "WMI永続サブスクリプションのバインディングイベント(ID:5861)が記録されています。Consumerの種別と実行コマンド内容を確認してください。");

                    reports.Add(new FindingReport(
                        Key: $"WMI:EVTLOG_5861:{rec.RecordId}",
                        Category: FindingCategory.WmiSubscription,
                        Severity: risk,
                        State: isRecent ? FindingState.New : FindingState.Existing,
                        Title: title,
                        Detail: CommandLineAnalyzer.Shorten(oneLine, 160),
                        Target: $"WMI-Activity EventID:5861 (#{rec.RecordId})",
                        TechnicalDetails: tech,
                        RecommendedAction: recAction,
                        Confidence: conf,
                        StoryKey: hasExecConsumer ? "STORY:WMI_EXEC_LOG" : "STORY:WMI_STD",
                        StoryTitle: hasExecConsumer ? "WMI Executable Subscription Log" : "Standard WMI Event Subscriptions"));
                }
            }
        }
        catch { }
    }
}
