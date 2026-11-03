using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Text;
using Microsoft.Win32;
using AnzenSecurityWatcher.Models;

namespace AnzenSecurityWatcher.Services;

/// <summary>
/// プライバシー・デバイス監視サービス
/// 1. カメラ・マイク・画面キャプチャの使用検知 (CapabilityAccessManager\ConsentStore)
/// 2. キーロガーの兆候検知 (非標準/未署名プロセスの SetWindowsHookEx / GetAsyncKeyState 呼び出し・インポート解析)
/// 3. クリップボードを監視・読み書きするプロセスの検知 (GetClipboardOwner / GetOpenClipboardWindow / SequenceNumber)
/// 4. USB デバイスの接続検知・BadUSB (複合キーボード型デバイス) 警戒
/// </summary>
public class PrivacyHardwareMonitorService
{
    private const string UsbBaselineFile = "usb_baseline.json";
    private HashSet<string> _usbBaseline = new(StringComparer.OrdinalIgnoreCase);
    private bool _usbBaselineLoaded;

    private readonly ConcurrentDictionary<string, KeyloggerPeInspection> _peHookCache = new(StringComparer.OrdinalIgnoreCase);
    private uint _lastClipboardSeq;
    private readonly Dictionary<string, (int Count, DateTime LastAccess, string Path)> _clipboardAccessHistory = new(StringComparer.OrdinalIgnoreCase);

    private record KeyloggerPeInspection(bool ImportsHookApi, bool ImportsAsyncKeyApi, string MatchedApis);

    // 新規接続されたHIDキーボードの履歴（BadUSB 攻撃シーケンス相関用: 最大15秒以内のコマンド実行を警戒）
    private static readonly ConcurrentDictionary<string, DateTime> RecentNewHidKeyboards = new();

    /// <summary>
    /// 直近15秒以内に新規HIDキーボードが接続された状態で、シェルやコマンドが起動したかを判定
    /// </summary>
    public static bool IsRecentBadUsbSequence(string procName, DateTime procStartTime, out string matchedDeviceId)
    {
        matchedDeviceId = "";
        if (string.IsNullOrWhiteSpace(procName)) return false;

        string p = procName.ToLowerInvariant();
        bool isShellOrDownload = p is "cmd" or "powershell" or "pwsh" or "mshta" or "wscript" or "cscript" or "rundll32" or "regsvr32" or "certutil" or "bitsadmin" or "curl";
        if (!isShellOrDownload) return false;

        foreach (var kvp in RecentNewHidKeyboards)
        {
            double sec = (procStartTime - kvp.Value).TotalSeconds;
            if (sec >= 0 && sec <= 15.0)
            {
                matchedDeviceId = kvp.Key;
                return true;
            }
        }
        return false;
    }

    private static readonly HashSet<string> KnownLegitInputProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "dwm", "csrss", "winlogon", "ctfmon", "TextInputHost", "SearchHost",
        "StartMenuExperienceHost", "ShellExperienceHost", "sihost", "SystemSettings",
        "AutoHotkey", "AutoHotkeyU64", "PowerToys.KeyboardManagerEngine", "PowerToys.PowerLauncher",
        "PowerToys.FancyZones", "LogiOptionsMgr", "LogiOptionsPlus_agent", "lghub_agent",
        "RazerSynapse", "igfxEM", "nvcontainer", " NVIDIA Share", "steam", "discord",
        "Code", "devenv", "mstsc", "AnzenSecurityWatcher"
    };

    public List<FindingReport> ScanFast()
    {
        var list = new List<FindingReport>();
        ScanCameraAndMicrophone(list);
        ScanClipboardMonitor(list);
        return list;
    }

    public List<FindingReport> ScanSlow()
    {
        var list = new List<FindingReport>();
        ScanKeyloggerIndicators(list);
        ScanUsbDevices(list);
        return list;
    }

    // =========================================================================
    // 1. カメラ・マイク・画面キャプチャ使用検知 (CapabilityAccessManager)
    // =========================================================================
    private static void ScanCameraAndMicrophone(List<FindingReport> reports)
    {
        (string CapabilityKey, string Label, string Icon)[] capabilities =
        {
            ("webcam", Loc.T("Webcam", "摄像头", "Cámara Web", "カメラ (Webカメラ)"), "📷"),
            ("microphone", Loc.T("Microphone", "麦克风", "Micrófono", "マイク (音声入力)"), "🎙️"),
            ("graphicsCaptureProgrammatic", Loc.T("Screen Capture API", "屏幕捕获 API", "API de Captura de Pantalla", "画面キャプチャAPI"), "🖼️"),
            ("graphicsCaptureWithoutBorder", Loc.T("Borderless Screen Capture", "无边框屏幕捕获", "Captura de Pantalla sin Bordes", "枠なし画面キャプチャ"), "🕵️")
        };

        (RegistryKey Root, string HiveName)[] roots =
        {
            (Registry.CurrentUser, "HKCU"),
            (Registry.LocalMachine, "HKLM")
        };

        foreach (var (capKey, label, icon) in capabilities)
        {
            foreach (var (root, hiveName) in roots)
            {
                string basePath = $@"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{capKey}";
                try
                {
                    using var baseReg = root.OpenSubKey(basePath, false);
                    if (baseReg == null) continue;

                    foreach (var subName in baseReg.GetSubKeyNames())
                    {
                        if (subName.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase))
                        {
                            using var npKey = baseReg.OpenSubKey("NonPackaged", false);
                            if (npKey == null) continue;
                            foreach (var appSub in npKey.GetSubKeyNames())
                            {
                                using var appKey = npKey.OpenSubKey(appSub, false);
                                InspectConsentEntry(appKey, appSub, isPackaged: false, capKey, label, icon, $"{hiveName}\\{basePath}\\NonPackaged\\{appSub}", reports);
                            }
                        }
                        else
                        {
                            using var pkgKey = baseReg.OpenSubKey(subName, false);
                            InspectConsentEntry(pkgKey, subName, isPackaged: true, capKey, label, icon, $"{hiveName}\\{basePath}\\{subName}", reports);
                        }
                    }
                }
                catch { }
            }
        }
    }

    private static void InspectConsentEntry(
        RegistryKey? key,
        string rawName,
        bool isPackaged,
        string capKey,
        string capLabel,
        string icon,
        string regLocation,
        List<FindingReport> reports)
    {
        if (key == null) return;
        try
        {
            long startFt = Convert.ToInt64(key.GetValue("LastUsedTimeStart") ?? 0L);
            long stopFt = Convert.ToInt64(key.GetValue("LastUsedTimeStop") ?? 0L);
            if (startFt <= 0) return;

            // Stop == 0 (または Stop < Start) は「現在使用中 (ACTIVE)」を表す
            bool isCurrentlyInUse = stopFt == 0 || stopFt < startFt;
            DateTime startTime = DateTime.FromFileTime(startFt);
            DateTime stopTime = stopFt > 0 ? DateTime.FromFileTime(stopFt) : DateTime.Now;

            // NonPackaged はパス区切りが '#' に置換されている (例: C:#Users#...#app.exe)
            string appPathOrPkg = isPackaged ? rawName : rawName.Replace('#', '\\');
            string displayName = isPackaged
                ? rawName.Split('_')[0]
                : Path.GetFileName(appPathOrPkg);

            // 現在使用中か、直近15分以内に使用されたもののみレポートする
            if (!isCurrentlyInUse && (DateTime.Now - stopTime).TotalMinutes > 15)
                return;

            var (isSigned, signer) = isPackaged
                ? (true, Loc.T("Microsoft Store / Packaged App", "Microsoft Store / 商店应用", "Microsoft Store / App Empaquetada", "Microsoft Store / パッケージアプリ"))
                : SignatureHelper.Check(appPathOrPkg);

            RiskLevel risk;
            if (isCurrentlyInUse)
            {
                risk = (!isSigned || PathHelper.IsUserWritableLocation(appPathOrPkg))
                    ? RiskLevel.Critical
                    : RiskLevel.High;
            }
            else
            {
                risk = (!isSigned && !isPackaged) ? RiskLevel.Medium : RiskLevel.Low;
            }

            var state = isCurrentlyInUse ? FindingState.Active : FindingState.Existing;
            string statusText = isCurrentlyInUse
                ? Loc.T(
                    $"🔴 Currently using {capLabel} (Started: {startTime:HH:mm:ss})",
                    $"🔴 当前正在使用 {capLabel} (开始: {startTime:HH:mm:ss})",
                    $"🔴 Usando {capLabel} actualmente (Inicio: {startTime:HH:mm:ss})",
                    $"🔴 現在 {capLabel} を使用中 (開始: {startTime:HH:mm:ss})")
                : Loc.T(
                    $"Recently used (Ended: {stopTime:HH:mm:ss})",
                    $"近期使用记录 (结束: {stopTime:HH:mm:ss})",
                    $"Usado recientemente (Fin: {stopTime:HH:mm:ss})",
                    $"直近使用履歴あり (終了: {stopTime:HH:mm:ss})");

            string title = isCurrentlyInUse
                ? Loc.T(
                    $"{icon} [{capLabel} Active] {displayName}",
                    $"{icon} 【正在使用{capLabel}】{displayName}",
                    $"{icon} [{capLabel} en Uso] {displayName}",
                    $"{icon} 【{capLabel}使用中】{displayName}")
                : Loc.T(
                    $"{icon} [{capLabel} History] {displayName}",
                    $"{icon} [{capLabel}历史记录] {displayName}",
                    $"{icon} [Historial de {capLabel}] {displayName}",
                    $"{icon} [{capLabel}履歴] {displayName}");

            string unsignedText = Loc.T("Unsigned", "未签名", "Sin firma", "未署名");
            string targetLabel = Loc.T("Target", "目标", "Destino", "対象");
            string detail = $"{statusText} — {targetLabel}: {appPathOrPkg} ({(isSigned ? signer : unsignedText)})";

            string signDesc = isSigned
                ? Loc.T($"Signed ({signer})", $"有 ({signer})", $"Firmado ({signer})", $"あり ({signer})")
                : Loc.T("Unsigned", "无 (未签名)", "Sin firma", "なし (未署名)");
            string curStateDesc = isCurrentlyInUse
                ? Loc.T("ACTIVE (Currently accessing)", "ACTIVE (正在访问)", "ACTIVO (Accediendo)", "ACTIVE (現在アクセス中)")
                : Loc.T("Ended", "已结束", "Finalizado", "使用終了");
            string endTimeDesc = isCurrentlyInUse
                ? Loc.T("(Ongoing)", "(持续中)", "(En curso)", "(継続中)")
                : stopTime.ToString("yyyy-MM-dd HH:mm:ss");

            string tech = Loc.T(
                $"Device Type: {capLabel} ({capKey})\nApplication: {displayName}\nPath / Package: {appPathOrPkg}\nDigital Signature: {signDesc}\nCurrent Status: {curStateDesc}\nStart Time: {startTime:yyyy-MM-dd HH:mm:ss}\nStop Time: {endTimeDesc}\nEvidence Registry: {regLocation}",
                $"设备类型: {capLabel} ({capKey})\n应用程序: {displayName}\n路径/包名: {appPathOrPkg}\n数字签名: {signDesc}\n当前状态: {curStateDesc}\n开始使用时间: {startTime:yyyy-MM-dd HH:mm:ss}\n结束使用时间: {endTimeDesc}\n证据注册表: {regLocation}",
                $"Tipo de dispositivo: {capLabel} ({capKey})\nAplicación: {displayName}\nRuta / Paquete: {appPathOrPkg}\nFirma digital: {signDesc}\nEstado actual: {curStateDesc}\nHora de inicio: {startTime:yyyy-MM-dd HH:mm:ss}\nHora de fin: {endTimeDesc}\nRegistro de evidencia: {regLocation}",
                $"デバイス種別: {capLabel} ({capKey})\nアプリケーション: {displayName}\n実体パス/パッケージ: {appPathOrPkg}\nデジタル署名: {signDesc}\n現在の状態: {curStateDesc}\n使用開始時刻: {startTime:yyyy-MM-dd HH:mm:ss}\n使用終了時刻: {endTimeDesc}\n証跡レジストリ: {regLocation}");

            string recAction = Loc.T(
                "If this camera or microphone usage is unintended, revoke permissions in Windows 'Settings > Privacy & security > Camera / Microphone' or terminate the process.",
                "如果是意外的摄像头或麦克风使用，请在 Windows“设置 > 隐私和安全性 > 摄像头/麦克风”中关闭访问权限，或结束该进程。",
                "Si el uso de cámara o micrófono no es intencional, desactive los permisos en 'Configuración > Privacidad y seguridad > Cámara / Micrófono' o termine el proceso.",
                "意図しないカメラ・マイク使用の場合は、Windowsの「設定 > プライバシーとセキュリティ > カメラ / マイク」からアクセス権をオフにするか、該当プロセスを終了してください。");

            reports.Add(new FindingReport(
                Key: $"CAMMIC:{capKey}:{rawName}",
                Category: FindingCategory.CameraMic,
                Severity: risk,
                State: state,
                Title: title,
                Detail: detail,
                Target: appPathOrPkg,
                TechnicalDetails: tech,
                RecommendedAction: recAction,
                OpenLocationPath: (!isPackaged && File.Exists(appPathOrPkg)) ? appPathOrPkg : ""));
        }
        catch { }
    }

    // =========================================================================
    // 2. キーロガーの兆候検知 (SetWindowsHookEx / GetAsyncKeyState 等の静的+動的解析)
    // =========================================================================
    private void ScanKeyloggerIndicators(List<FindingReport> reports)
    {
        Process[] procs;
        try { procs = Process.GetProcesses(); }
        catch { return; }

        try
        {
            foreach (var p in procs)
            {
                try
                {
                    int pid = p.Id;
                    if (pid <= 4) continue;
                    string procName = p.ProcessName;
                    if (KnownLegitInputProcesses.Contains(procName)) continue;

                    string exePath = NativeSecurity.QueryProcessImagePath(pid);
                    if (string.IsNullOrEmpty(exePath)) continue;

                    // Windows 標準フォルダや Microsoft 署名バイナリは除外
                    if (PathHelper.IsWindowsLocation(exePath)) continue;

                    var sigResult = SignatureHelper.CheckExtended(exePath);
                    bool inUserFolder = PathHelper.IsUserWritableLocation(exePath);

                    // 署名済みかつ Program Files 配下の正規アプリはスキップ
                    if (sigResult.Status == SignatureStatus.Signed && PathHelper.IsProgramFilesLocation(exePath)) continue;

                    var inspection = InspectBinaryForKeyHookApis(exePath);
                    if (!inspection.ImportsHookApi && !inspection.ImportsAsyncKeyApi) continue;

                    // 要件 #5: PE import は「Capability (機能保持)」であり「Behavior (実攻撃)」ではない。
                    // 単に import されているだけでは過剰警告（Medium/High/Critical）にせず、Informational (Confidence: Low) を基本とする。
                    // ユーザー書き込み可能フォルダ (Temp/Downloads) かつ未署名の場合のみ慎重度を上げて Caution とする。
                    var risk = (sigResult.Status == SignatureStatus.Unsigned && inUserFolder)
                        ? RiskLevel.Caution
                        : RiskLevel.Informational;
                    var confidence = ConfidenceLevel.Low;

                    string title = Loc.T(
                        $"ℹ️ [Keyboard Capability] {procName} (PID:{pid})",
                        $"ℹ️ [键盘监控功能保持] {procName} (PID:{pid})",
                        $"ℹ️ [Capacidad de Teclado] {procName} (PID:{pid})",
                        $"ℹ️ [キー監視機能保持] {procName} (PID:{pid})");

                    string detail = Loc.T(
                        $"Executable imports keyboard-related Win32 APIs ({inspection.MatchedApis}). No actual keystroke capture has been confirmed.",
                        $"可执行文件导入了键盘相关 Win32 API ({inspection.MatchedApis})。尚未确认实际按键捕获行为。",
                        $"El ejecutable importa APIs Win32 de teclado ({inspection.MatchedApis}). No se ha confirmado captura real.",
                        $"実行ファイルがキー関連 Win32 API ({inspection.MatchedApis}) をインポートしています。実際のキー入力傍受は確認されていません。");

                    string signDesc = SignatureHelper.FormatSignatureLine(sigResult);

                    string tech = Loc.T(
                        $"Process Name: {procName} (PID: {pid})\nExecutable Path: {exePath}\nDigital Signature: {signDesc}\nDetected API Imports: {inspection.MatchedApis}\nAssessment: Level 1 Capability only. Legitimate software such as device utilities or hotkey tools frequently import these APIs without malicious intent.",
                        $"进程名: {procName} (PID: {pid})\n可执行文件路径: {exePath}\n数字签名: {signDesc}\n检测到的 API 导入: {inspection.MatchedApis}\n判定评估: 仅为第 1 阶段功能保持 (Capability)。外设管理工具或快捷键辅助等正常软件经常导入此类 API，并不等同于恶意木马。",
                        $"Proceso: {procName} (PID: {pid})\nRuta del ejecutable: {exePath}\nFirma digital: {signDesc}\nAPIs detectadas: {inspection.MatchedApis}\nEvaluación: Nivel 1 solo Capacidad. Software legítimo importa estas APIs sin intención maliciosa.",
                        $"プロセス名: {procName} (PID: {pid})\n実行ファイルパス: {exePath}\nデジタル署名: {signDesc}\n検出されたAPIインポート: {inspection.MatchedApis}\n判定評価: レベル1 (機能保持) のみ。周辺機器ユーティリティやショートカット補助等の正規アプリでも日常的に使用されます。実際のキー入力監視行動は確認されていません。");

                    string recAction = Loc.T(
                        "Informational: Check if this application requires global hotkeys or device control (e.g., printer/scanner utility). No immediate action required unless accompanied by suspicious network traffic.",
                        "参考信息：确认该应用是否需要快捷键或外设联动功能（如打印机/扫描仪工具）。若无异常外部通信，通常无需采取措施。",
                        "Informativo: Verifique si la aplicación requiere teclas rápidas o utilidades. No se requiere acción inmediata salvo tráfico sospechoso.",
                        "情報: プリンター・スキャナー・ショートカットキー等の正規ユーティリティかご確認ください。不審な外部通信が伴わない限り、即時の対処は不要です。");

                    reports.Add(new FindingReport(
                        Key: $"KEYLOG:{exePath.ToLowerInvariant()}",
                        Category: FindingCategory.Keylogger,
                        Severity: risk,
                        State: FindingState.Active,
                        Title: title,
                        Detail: detail,
                        Target: exePath,
                        TechnicalDetails: tech,
                        RecommendedAction: recAction,
                        OpenLocationPath: exePath,
                        ProcessId: pid,
                        Confidence: confidence,
                        StoryKey: "Story:KeyhookCapability",
                        StoryTitle: $"{procName} Keyboard API Imports"));
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
            // ループ途中で抜けた場合の残余インスタンスも破棄
            foreach (var p in procs)
            {
                try { p.Dispose(); } catch { }
            }
        }
    }

    private KeyloggerPeInspection InspectBinaryForKeyHookApis(string filePath)
    {
        if (_peHookCache.TryGetValue(filePath, out var cached))
            return cached;

        var empty = new KeyloggerPeInspection(false, false, "");
        try
        {
            var fi = new FileInfo(filePath);
            if (!fi.Exists || fi.Length > 25 * 1024 * 1024) // 25MB超の巨大アプリはスキップ
            {
                _peHookCache[filePath] = empty;
                return empty;
            }

            byte[] bytes = File.ReadAllBytes(filePath);
            string ascii = Encoding.ASCII.GetString(bytes);

            var matched = new List<string>();
            bool hasHook = false;
            bool hasAsync = false;

            if (ascii.Contains("SetWindowsHookEx", StringComparison.Ordinal))
            {
                hasHook = true;
                matched.Add("SetWindowsHookEx");
            }
            if (ascii.Contains("GetAsyncKeyState", StringComparison.Ordinal) &&
                ascii.Contains("GetKeyboardState", StringComparison.Ordinal))
            {
                hasAsync = true;
                matched.Add("GetAsyncKeyState + GetKeyboardState");
            }
            if (ascii.Contains("RegisterRawInputDevices", StringComparison.Ordinal) && hasHook)
            {
                matched.Add("RegisterRawInputDevices");
            }

            var result = new KeyloggerPeInspection(hasHook, hasAsync, string.Join(", ", matched));
            _peHookCache[filePath] = result;
            return result;
        }
        catch
        {
            _peHookCache[filePath] = empty;
            return empty;
        }
    }

    // =========================================================================
    // 3. クリップボードを読み取る / 保持するプロセスの監視
    // =========================================================================
    private void ScanClipboardMonitor(List<FindingReport> reports)
    {
        try
        {
            uint seq = NativeSecurity.GetClipboardSequenceNumber();
            IntPtr ownerHwnd = NativeSecurity.GetClipboardOwner();
            IntPtr openHwnd = NativeSecurity.GetOpenClipboardWindow();
            IntPtr fgHwnd = NativeSecurity.GetForegroundWindow();

            int ownerPid = NativeSecurity.GetWindowPid(ownerHwnd);
            int openPid = NativeSecurity.GetWindowPid(openHwnd);
            int fgPid = NativeSecurity.GetWindowPid(fgHwnd);

            bool seqChanged = _lastClipboardSeq != 0 && seq != _lastClipboardSeq;
            _lastClipboardSeq = seq;

            foreach (int pid in new[] { ownerPid, openPid }.Where(x => x > 4).Distinct())
            {
                if (pid == Environment.ProcessId) continue;

                string exePath = NativeSecurity.QueryProcessImagePath(pid);
                string procName = "";
                try
                {
                    using var proc = Process.GetProcessById(pid);
                    procName = proc.ProcessName;
                }
                catch { continue; }

                if (string.IsNullOrEmpty(procName)) continue;

                string key = string.IsNullOrEmpty(exePath) ? procName.ToLowerInvariant() : exePath.ToLowerInvariant();
                if (!_clipboardAccessHistory.TryGetValue(key, out var hist))
                {
                    hist = (seqChanged ? 1 : 0, DateTime.Now, exePath);
                }
                else if (seqChanged || pid == openPid)
                {
                    hist = (hist.Count + 1, DateTime.Now, exePath);
                }
                _clipboardAccessHistory[key] = hist;

                var (isSigned, signer) = SignatureHelper.Check(exePath);
                bool isBackgroundAccess = (pid != fgPid) && (pid == openPid || seqChanged);
                bool isSuspiciousProc = !isSigned || PathHelper.IsUserWritableLocation(exePath);

                // 標準の explorer / rdpclip 以外の不審プロセスやバックグラウンド連続アクセスを報告
                if (!isSuspiciousProc && !isBackgroundAccess && hist.Count < 3)
                    continue;

                var risk = RiskLevel.Low;
                var reasons = new List<string>();

                if (!isSigned && !PathHelper.IsWindowsLocation(exePath))
                {
                    risk = RiskLevel.High;
                    reasons.Add(Loc.T(
                        "Unsigned process holding/accessing clipboard",
                        "未签名进程正在占用或访问剪贴板",
                        "Proceso sin firmar reteniendo/accediendo al portapapeles",
                        "未署名プロセスがクリップボードを保持/アクセス"));
                }
                if (isBackgroundAccess)
                {
                    if (risk < RiskLevel.Medium) risk = RiskLevel.Medium;
                    reasons.Add(Loc.T(
                        "Accessing clipboard while in background (inactive)",
                        "在后台（非活动窗口）状态下访问剪贴板",
                        "Accediendo al portapapeles en segundo plano (inactivo)",
                        "非アクティブ(バックグラウンド)状態でクリップボードにアクセス"));
                }
                if (reasons.Count == 0)
                {
                    int cnt = Math.Max(1, hist.Count);
                    reasons.Add(Loc.T(
                        $"Current clipboard owner (Detected {cnt} time(s))",
                        $"当前剪贴板所有者 (检测次数:{cnt}次)",
                        $"Propietario actual del portapapeles (Detectado {cnt} veces)",
                        $"クリップボード現在の所有者 (検知回数:{cnt}回)"));
                }

                string title = Loc.T(
                    $"📋 [Clipboard Monitor] {procName} (PID:{pid})",
                    $"📋 [剪贴板监控] {procName} (PID:{pid})",
                    $"📋 [Monitor de Portapapeles] {procName} (PID:{pid})",
                    $"📋 [クリップボード監視] {procName} (PID:{pid})");
                string detail = $"{string.Join(" / ", reasons)} — {exePath}";

                string signDesc = isSigned
                    ? Loc.T($"Signed ({signer})", $"有 ({signer})", $"Firmado ({signer})", $"あり ({signer})")
                    : Loc.T("Unsigned", "无 (未签名)", "Sin firma", "なし (未署名)");
                string roleDesc = pid == openPid
                    ? Loc.T("Currently OpenClipboard", "当前正在打开剪贴板 (OpenClipboard)", "Abriendo portapapeles (OpenClipboard)", "現在OpenClipboard中")
                    : Loc.T("Current Owner", "当前所有者 (Owner)", "Propietario actual (Owner)", "現在のOwner");
                string fgDesc = pid == fgPid
                    ? Loc.T("Active foreground window", "当前活动前台窗口", "Ventana activa en primer plano", "操作中の前面ウィンドウ")
                    : Loc.T("Background process", "后台进程", "Proceso en segundo plano", "バックグラウンドプロセス");
                string reasonsJoined = string.Join(" / ", reasons);

                string tech = Loc.T(
                    $"Process Name: {procName} (PID: {pid})\nExecutable Path: {exePath}\nDigital Signature: {signDesc}\nClipboard Role: {roleDesc}\nForeground Status: {fgDesc}\nReason: {reasonsJoined}",
                    $"进程名: {procName} (PID: {pid})\n可执行文件路径: {exePath}\n数字签名: {signDesc}\n剪贴板角色: {roleDesc}\n前后台状态: {fgDesc}\n判定原因: {reasonsJoined}",
                    $"Proceso: {procName} (PID: {pid})\nRuta del ejecutable: {exePath}\nFirma digital: {signDesc}\nRol de portapapeles: {roleDesc}\nEstado de ventana: {fgDesc}\nMotivo: {reasonsJoined}",
                    $"プロセス名: {procName} (PID: {pid})\n実行ファイルパス: {exePath}\nデジタル署名: {signDesc}\nクリップボード役割: {roleDesc}\nフォアグラウンド判定: {fgDesc}\n判定理由: {reasonsJoined}");

                string recAction = Loc.T(
                    "Clipper malware can hijack cryptocurrency addresses or steal copied passwords. Terminate any unrecognized process holding the clipboard.",
                    "剪贴板木马（Clipper）可篡改加密货币地址或窃取复制的密码内容。如果发现不明进程占用剪贴板，请将其结束。",
                    "El malware Clipper puede reemplazar direcciones cripto o robar contenido copiado. Termine cualquier proceso desconocido que retenga el portapapeles.",
                    "暗号資産アドレスのすり替え（クリッパー）やコピー内容の盗み見を行うマルウェアが存在します。見覚えのないプロセスがクリップボードを保持している場合は終了してください。");

                reports.Add(new FindingReport(
                    Key: $"CLIP:{key}",
                    Category: FindingCategory.Clipboard,
                    Severity: risk,
                    State: pid == openPid ? FindingState.Active : FindingState.Existing,
                    Title: title,
                    Detail: detail,
                    Target: string.IsNullOrEmpty(exePath) ? procName : exePath,
                    TechnicalDetails: tech,
                    RecommendedAction: recAction,
                    OpenLocationPath: File.Exists(exePath) ? exePath : "",
                    ProcessId: pid));
            }
        }
        catch { }
    }

    // =========================================================================
    // 4. USB デバイスの接続検知 (BadUSB / 見知らぬHIDキーボード・USBストレージ警告)
    // =========================================================================
    private void ScanUsbDevices(List<FindingReport> reports)
    {
        EnsureUsbBaselineLoaded();
        bool isFirst = _usbBaseline.Count == 0;
        bool modified = false;

        var devices = EnumeratePresentUsbDevices();
        foreach (var dev in devices)
        {
            bool isNew = false;
            if (isFirst)
            {
                _usbBaseline.Add(dev.DeviceId);
                modified = true;
            }
            else if (_usbBaseline.Add(dev.DeviceId))
            {
                isNew = true;
                modified = true;
            }

            var risk = RiskLevel.Safe;
            var confidence = ConfidenceLevel.High;
            var reasons = new List<string>();

            if (isNew)
            {
                // 要件 #11: 新規接続されただけで即座に Critical/High にしない。まずは Informational / Caution
                risk = RiskLevel.Informational;
                confidence = ConfidenceLevel.Medium;
                reasons.Add(Loc.T(
                    "Newly connected/recognized USB device after monitoring started",
                    "监控开始后新连接或识别的 USB 设备",
                    "Dispositivo USB recién conectado tras iniciar el monitoreo",
                    "監視開始後に新しく接続・認識されたUSBデバイス"));

                if (dev.IsCompositeHidKeyboard)
                {
                    RecentNewHidKeyboards[dev.DeviceId] = DateTime.Now;
                    risk = RiskLevel.Caution;
                    confidence = ConfidenceLevel.Low;
                    reasons.Add(Loc.T(
                        "Newly attached USB HID keyboard (Caution: If physical device is an unfamiliar USB flash drive, beware of BadUSB keystroke injection)",
                        "新连接的 USB HID 键盘设备（注意：若外观为不熟悉的普通 U 盘，请警惕 BadUSB 键盘注入攻击）",
                        "Teclado USB HID recién conectado (Precaución: Si es una memoria USB desconocida, cuidado con inyección BadUSB)",
                        "新規接続されたUSB HIDキーボード (注意: 見知らぬUSBメモリ形状の場合は BadUSB による自動キーストローク注入に注意)"));
                }
                else if (dev.IsMassStorage)
                {
                    risk = RiskLevel.Informational;
                    confidence = ConfidenceLevel.High;
                    reasons.Add(Loc.T(
                        "USB Mass Storage device (External drive)",
                        "USB 大容量存储设备（外部存储介质）",
                        "Dispositivo de almacenamiento masivo USB (Unidad externa)",
                        "USB大容量ストレージ (外部記憶媒体)"));
                }
            }
            else
            {
                // 既存の接続済みデバイス（キーボード、マウス、Bluetooth等）は正常・情報レベル
                if (dev.IsCompositeHidKeyboard)
                {
                    risk = RiskLevel.Safe;
                    reasons.Add(Loc.T(
                        "Existing connected USB HID input device (Normal keyboard/mouse/dongle)",
                        "既有连接的 USB HID 输入设备（正常键盘/鼠标/接收器）",
                        "Dispositivo USB HID existente (Teclado/ratón normal)",
                        "既存接続のUSB HID入力デバイス (通常のキーボード/マウス/ドングル)"));
                }
                else if (dev.IsMassStorage)
                {
                    risk = RiskLevel.Informational;
                    reasons.Add(Loc.T(
                        "Connected USB Mass Storage device",
                        "已连接的 USB 大容量存储设备",
                        "Dispositivo de almacenamiento masivo USB conectado",
                        "接続中のUSB大容量ストレージ"));
                }
            }

            // 既存の通常HIDやハブ等はノイズ削減のため除外
            if (!isNew && risk == RiskLevel.Safe)
                continue;

            string title = $"🔌 [{dev.CategoryLabel}] {dev.FriendlyName}";
            string detail = $"{string.Join(" / ", reasons)} — ID: {dev.ShortHardwareId}";

            string connStatus = isNew
                ? Loc.T("🆕 Newly connected", "🆕 新连接检测", "🆕 Recién conectado", "🆕 新規接続検知")
                : Loc.T("Connected (Existing)", "已连接 (既有)", "Conectado (Existente)", "接続済み (既存)");
            string reasonsJoined = string.Join(" / ", reasons);

            string tech = Loc.T(
                $"Device Name: {dev.FriendlyName}\nCategory: {dev.CategoryLabel}\nDevice Instance ID: {dev.DeviceId}\nService / Driver: {dev.Service}\nStatus: {connStatus}\nAssessment: {reasonsJoined}",
                $"设备名称: {dev.FriendlyName}\n分类: {dev.CategoryLabel}\n设备实例 ID: {dev.DeviceId}\n服务/驱动: {dev.Service}\n状态: {connStatus}\n评估说明: {reasonsJoined}",
                $"Nombre del dispositivo: {dev.FriendlyName}\nCategoría: {dev.CategoryLabel}\nID de instancia: {dev.DeviceId}\nServicio / Controlador: {dev.Service}\nEstado: {connStatus}\nEvaluación: {reasonsJoined}",
                $"デバイス名: {dev.FriendlyName}\n分類: {dev.CategoryLabel}\nデバイスインスタンスID: {dev.DeviceId}\nサービス/ドライバ: {dev.Service}\n状態: {connStatus}\n評価理由: {reasonsJoined}");

            string recAction = isNew && dev.IsCompositeHidKeyboard
                ? Loc.T(
                    "If you just plugged in an ordinary USB flash drive or cable and it registered as a keyboard, unplug it immediately. If you intentionally connected a keyboard or mouse, no action is needed.",
                    "如果您刚刚插入的是普通 U 盘或充电线，但被识别为键盘，请立即拔出。如果您是正常连接新的键盘鼠标，则无需担心。",
                    "Si conectó una memoria USB o cable y se reconoció como teclado, desconéctelo. Si conectó un teclado real, no se requiere acción.",
                    "普通のUSBメモリや充電ケーブルを挿したのにキーボードとして認識された場合は、直ちに抜いてください。通常のキーボードやマウスを接続した場合は問題ありません。")
                : Loc.T(
                    "Standard USB device connected. Inspect unfamiliar devices as needed.",
                    "标准 USB 设备已连接。如有不明设备可进一步确认。",
                    "Dispositivo USB estándar conectado. Revise dispositivos desconocidos.",
                    "通常のUSBデバイスが接続されています。心当たりのない機器がある場合は確認してください。");

            reports.Add(new FindingReport(
                Key: $"USB:{dev.DeviceId}",
                Category: FindingCategory.UsbDevice,
                Severity: risk,
                State: isNew ? FindingState.New : FindingState.Existing,
                Title: title,
                Detail: detail,
                Target: dev.DeviceId,
                TechnicalDetails: tech,
                RecommendedAction: recAction,
                Confidence: confidence,
                StoryKey: dev.IsCompositeHidKeyboard ? "Story:UsbInputDevice" : "Story:UsbStorageDevice",
                StoryTitle: dev.FriendlyName));
        }

        if (modified)
            JsonStore.Save(UsbBaselineFile, _usbBaseline.ToList());
    }

    private void EnsureUsbBaselineLoaded()
    {
        if (_usbBaselineLoaded) return;
        _usbBaselineLoaded = true;
        var list = JsonStore.Load<List<string>>(UsbBaselineFile);
        if (list != null)
            _usbBaseline = new HashSet<string>(list, StringComparer.OrdinalIgnoreCase);
    }

    private record UsbDeviceEntry(
        string DeviceId,
        string ShortHardwareId,
        string FriendlyName,
        string Service,
        string CategoryLabel,
        bool IsMassStorage,
        bool IsCompositeHidKeyboard);

    private static List<UsbDeviceEntry> EnumeratePresentUsbDevices()
    {
        var result = new List<UsbDeviceEntry>();
        string storageLabel = Loc.T("USB Storage", "USB 存储设备", "Almacenamiento USB", "USBストレージ");
        string hidLabel = Loc.T("USB HID / Input Device", "USB HID/输入设备", "Dispositivo USB HID", "USB HID/入力デバイス");

        try
        {
            // 1. USBSTOR (USBストレージ) のレジストリ列挙
            using (var usbstor = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR", false))
            {
                if (usbstor != null)
                {
                    foreach (var devClass in usbstor.GetSubKeyNames())
                    {
                        using var dcKey = usbstor.OpenSubKey(devClass, false);
                        if (dcKey == null) continue;
                        foreach (var instance in dcKey.GetSubKeyNames())
                        {
                            using var instKey = dcKey.OpenSubKey(instance, false);
                            if (instKey == null) continue;
                            string friendly = CleanDeviceName(instKey.GetValue("FriendlyName")?.ToString()
                                ?? instKey.GetValue("DeviceDesc")?.ToString()
                                ?? devClass);
                            string fullId = $"USBSTOR\\{devClass}\\{instance}";
                            result.Add(new UsbDeviceEntry(fullId, devClass, friendly, "USBSTOR", storageLabel, true, false));
                        }
                    }
                }
            }

            // 2. USB キーボード / 複合HID デバイスの列挙
            using (var usb = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB", false))
            {
                if (usb != null)
                {
                    foreach (var vidPid in usb.GetSubKeyNames())
                    {
                        if (!vidPid.StartsWith("VID_", StringComparison.OrdinalIgnoreCase)) continue;
                        using var vpKey = usb.OpenSubKey(vidPid, false);
                        if (vpKey == null) continue;

                        foreach (var instance in vpKey.GetSubKeyNames())
                        {
                            using var instKey = vpKey.OpenSubKey(instance, false);
                            if (instKey == null) continue;

                            string service = instKey.GetValue("Service")?.ToString() ?? "";
                            string desc = CleanDeviceName(instKey.GetValue("FriendlyName")?.ToString()
                                ?? instKey.GetValue("DeviceDesc")?.ToString()
                                ?? vidPid);

                            bool isHidOrKbd = service.Equals("HidUsb", StringComparison.OrdinalIgnoreCase) ||
                                              service.Equals("kbdhid", StringComparison.OrdinalIgnoreCase) ||
                                              desc.Contains("Keyboard", StringComparison.OrdinalIgnoreCase) ||
                                              desc.Contains("キーボード", StringComparison.OrdinalIgnoreCase);

                            if (!isHidOrKbd) continue;

                            string fullId = $"USB\\{vidPid}\\{instance}";
                            result.Add(new UsbDeviceEntry(fullId, vidPid, desc, service, hidLabel, false, true));
                        }
                    }
                }
            }
        }
        catch { }

        return result;
    }

    private static string CleanDeviceName(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "USB Device";
        int semi = raw.LastIndexOf(';');
        return semi >= 0 && semi + 1 < raw.Length ? raw[(semi + 1)..].Trim() : raw.Trim();
    }
}
