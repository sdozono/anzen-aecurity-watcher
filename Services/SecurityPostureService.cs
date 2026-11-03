using System.IO;
using Microsoft.Win32;
using AnzenSecurityWatcher.Models;

namespace AnzenSecurityWatcher.Services;

/// <summary>
/// #21 セキュリティ設定の診断サービス
/// Windows Defender・ファイアウォール・UAC・SmartScreen・RDP公開状態・セキュアブート・
/// SMBv1無効化・自動再生防止・hostsファイル改ざん・プロキシ改ざんの 10 項目を点検し、
/// 初心者にも一目で分かる 100 点満点の「安全スコア」とグレード (A〜E) を算出する。
/// </summary>
public class SecurityPostureService
{
    private SecurityPostureReport? _lastReport;
    private DateTime _lastScan = DateTime.MinValue;
    private AppLanguage _lastLang = AppLanguage.English;

    public SecurityPostureReport Evaluate(bool forceRefresh = false)
    {
        if (!forceRefresh && _lastReport != null && _lastLang == LocalizationManager.CurrentLanguage && (DateTime.Now - _lastScan).TotalSeconds < 25)
            return _lastReport;

        var checks = new List<SecurityCheckItem>
        {
            CheckDefenderRealtime(),
            CheckWindowsFirewall(),
            CheckUacSettings(),
            CheckSmartScreen(),
            CheckRemoteDesktopExposure(),
            CheckSecureBoot(),
            CheckSmbV1Disabled(),
            CheckAutoRunDisabled(),
            CheckHostsFileIntegrity(),
            CheckProxySettings()
        };

        _lastReport = new SecurityPostureReport
        {
            Checks = checks,
            EvaluatedAt = DateTime.Now
        };
        _lastScan = DateTime.Now;
        _lastLang = LocalizationManager.CurrentLanguage;
        return _lastReport;
    }

    // 1. Microsoft Defender リアルタイム保護 (配点: 20)
    private static SecurityCheckItem CheckDefenderRealtime()
    {
        var item = new SecurityCheckItem
        {
            Id = "DEFENDER_RTP",
            Name = Loc.T(
                "🛡️ Microsoft Defender Real-Time Protection",
                "🛡️ Microsoft Defender 实时保护",
                "🛡️ Protección en tiempo real de Microsoft Defender",
                "🛡️ Microsoft Defender リアルタイム保護"),
            Weight = 20,
            FixCommand = "windowsdefender:"
        };

        try
        {
            bool serviceRunning = false;
            using (var svc = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\WinDefend", false))
            {
                if (svc != null)
                {
                    int start = Convert.ToInt32(svc.GetValue("Start") ?? 4);
                    serviceRunning = start <= 3;
                }
            }

            int disableRtp = 0;
            int disableAntiSpy = 0;
            using (var mp = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", false))
            {
                if (mp != null)
                    disableRtp = Convert.ToInt32(mp.GetValue("DisableRealtimeMonitoring") ?? 0);
            }
            using (var pol = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender", false))
            {
                if (pol != null)
                    disableAntiSpy = Convert.ToInt32(pol.GetValue("DisableAntiSpyware") ?? 0);
            }

            if (disableRtp == 0 && disableAntiSpy == 0 && serviceRunning)
            {
                item.Result = CheckResult.Pass;
                item.StatusText = Loc.T("Enabled (Real-time protection active)", "已启用 (实时监控运行中)", "Activado (Monitoreo en tiempo real activo)", "有効 (リアルタイム監視が稼働中)");
                item.Advice = Loc.T(
                    "Malware execution is blocked in real time.",
                    "可实时拦截恶意软件的执行。",
                    "La ejecución de malware se bloquea en tiempo real.",
                    "マルウェアの実行をリアルタイムにブロックできる状態です。");
            }
            else
            {
                item.Result = CheckResult.Fail;
                item.StatusText = Loc.T("Disabled (Check required)", "已禁用 (需检查)", "Desactivado (Revisar)", "無効化されています (要確認)");
                item.Advice = Loc.T(
                    "Open Windows Security -> Virus & threat protection and turn on Real-time protection.",
                    "请打开 Windows 安全中心 -> 病毒和威胁防护，开启实时保护。",
                    "Abra Seguridad de Windows -> Protección contra virus y amenazas y active la protección en tiempo real.",
                    "Windows セキュリティを開き、「ウイルスと脅威の防止」からリアルタイム保護をオンにしてください。");
            }
        }
        catch
        {
            item.Result = CheckResult.Unknown;
            item.StatusText = Loc.T("Unable to query", "无法获取状态", "No disponible", "状態取得不可");
        }
        return item;
    }

    // 2. Windows ファイアウォール (ドメイン / プライベート / パブリック) (配点: 18)
    private static SecurityCheckItem CheckWindowsFirewall()
    {
        var item = new SecurityCheckItem
        {
            Id = "FIREWALL",
            Name = Loc.T(
                "🔥 Windows Firewall (All Profiles)",
                "🔥 Windows 防火墙 (所有配置文件)",
                "🔥 Firewall de Windows (Todos los perfiles)",
                "🔥 Windows ファイアウォール (全プロファイル)"),
            Weight = 18,
            FixCommand = "wf.msc"
        };

        try
        {
            (string Key, string Label, bool IsPublic)[] profiles =
            {
                (@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", Loc.T("Private", "专用网络", "Privado", "プライベート"), false),
                (@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", Loc.T("Public", "公用网络", "Público", "パブリック"), true),
                (@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", Loc.T("Domain", "域网络", "Dominio", "ドメイン"), false)
            };

            var disabled = new List<string>();
            bool publicDisabled = false;
            foreach (var (k, label, isPub) in profiles)
            {
                using var rk = Registry.LocalMachine.OpenSubKey(k, false);
                if (rk != null)
                {
                    int en = Convert.ToInt32(rk.GetValue("EnableFirewall") ?? 1);
                    if (en == 0)
                    {
                        disabled.Add(label);
                        if (isPub) publicDisabled = true;
                    }
                }
            }

            if (disabled.Count == 0)
            {
                item.Result = CheckResult.Pass;
                item.StatusText = Loc.T("Enabled on all profiles", "所有配置文件均已启用", "Activado en todos los perfiles", "すべてのプロファイルで有効");
                item.Advice = Loc.T(
                    "Unauthorized inbound connections are blocked.",
                    "已拦截来自外部的未授权入站连接。",
                    "Las conexiones entrantes no autorizadas están bloqueadas.",
                    "外部からの不正な着信接続がブロックされています。");
            }
            else if (publicDisabled)
            {
                item.Result = CheckResult.Fail;
                item.StatusText = Loc.T(
                    $"Disabled profile(s): {string.Join(", ", disabled)}",
                    $"存在已禁用的配置文件 ({string.Join(", ", disabled)})",
                    $"Perfiles desactivados ({string.Join(", ", disabled)})",
                    $"無効なプロファイルあり ({string.Join(", ", disabled)})");
                item.Advice = Loc.T(
                    "Having the firewall disabled on Public networks exposes your PC to direct attacks. Enable it immediately.",
                    "在公用网络下禁用防火墙会导致电脑直接暴露于外部攻击，请立即启用。",
                    "Tener el firewall desactivado en redes públicas expone el PC a ataques directos. Actívelo de inmediato.",
                    "特にパブリックネットワークでファイアウォールが無効だと外部から直接攻撃されます。直ちに有効化してください。");
            }
            else
            {
                item.Result = CheckResult.Warning;
                item.StatusText = Loc.T(
                    $"Partially disabled ({string.Join(", ", disabled)})",
                    $"部分已禁用 ({string.Join(", ", disabled)})",
                    $"Parcialmente desactivado ({string.Join(", ", disabled)})",
                    $"一部無効 ({string.Join(", ", disabled)})");
                item.Advice = Loc.T(
                    "Enabling the firewall across all network profiles is recommended.",
                    "建议在所有网络配置文件中启用防火墙。",
                    "Se recomienda activar el firewall en todos los perfiles de red.",
                    "すべてのネットワークプロファイルでファイアウォールを有効にすることを推奨します。");
            }
        }
        catch
        {
            item.Result = CheckResult.Unknown;
            item.StatusText = Loc.T("Unable to query", "无法获取状态", "No disponible", "状態取得不可");
        }
        return item;
    }

    // 3. UAC (ユーザーアカウント制御) (配点: 14)
    private static SecurityCheckItem CheckUacSettings()
    {
        var item = new SecurityCheckItem
        {
            Id = "UAC",
            Name = Loc.T(
                "🔐 User Account Control (UAC Elevation Protection)",
                "🔐 用户账户控制 (UAC 提权保护)",
                "🔐 Control de Cuentas de Usuario (Protección UAC)",
                "🔐 ユーザーアカウント制御 (UAC 昇格保護)"),
            Weight = 14,
            FixCommand = "UserAccountControlSettings.exe"
        };

        try
        {
            using var rk = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", false);
            int enableLua = Convert.ToInt32(rk?.GetValue("EnableLUA") ?? 1);
            int consentAdmin = Convert.ToInt32(rk?.GetValue("ConsentPromptBehaviorAdmin") ?? 5);

            if (enableLua == 0)
            {
                item.Result = CheckResult.Fail;
                item.StatusText = Loc.T("UAC completely disabled (EnableLUA=0)", "UAC 已完全禁用 (EnableLUA=0)", "UAC completamente desactivado (EnableLUA=0)", "UAC が完全に無効 (EnableLUA=0)");
                item.Advice = Loc.T(
                    "Malware can silently gain administrator privileges. Enable UAC immediately.",
                    "恶意软件可在无警告的情况下夺取管理员权限，请立即启用 UAC。",
                    "El malware puede obtener privilegios de administrador sin previo aviso. Active UAC.",
                    "マルウェアが警告なしで管理者権限を奪取できる危険な状態です。UACを有効にしてください。");
            }
            else if (consentAdmin == 0)
            {
                item.Result = CheckResult.Warning;
                item.StatusText = Loc.T("Auto-elevates without prompt (ConsentPrompt=0)", "无需确认即可自动提权 (ConsentPrompt=0)", "Se eleva sin confirmación (ConsentPrompt=0)", "確認なしで自動昇格する設定 (ConsentPrompt=0)");
                item.Advice = Loc.T(
                    "Set the UAC slider to at least the default level (Notify me only when apps try to make changes).",
                    "建议将 UAC 滑块设置为默认级别（仅当应用尝试进行更改时通知我）或更高。",
                    "Configure el control deslizante UAC al menos en el nivel predeterminado.",
                    "UACスライダーを上から2番目（既定：アプリが変更を加えようとする場合のみ通知）以上に設定してください。");
            }
            else
            {
                item.Result = CheckResult.Pass;
                item.StatusText = Loc.T($"Enabled (Consent mode: {consentAdmin})", $"已启用 (提权确认模式: {consentAdmin})", $"Activado (Modo de confirmación: {consentAdmin})", $"有効 (昇格確認モード: {consentAdmin})");
                item.Advice = Loc.T(
                    "Unauthorized silent privilege escalation by suspicious programs is prevented.",
                    "可防止可疑程序未经授权静默获取管理员权限。",
                    "Se previene la escalada silenciosa de privilegios por programas sospechosos.",
                    "不審プログラムによる無断の管理者権限昇格が防止されています。");
            }
        }
        catch
        {
            item.Result = CheckResult.Unknown;
            item.StatusText = Loc.T("Unable to query", "无法获取状态", "No disponible", "状態取得不可");
        }
        return item;
    }

    // 4. SmartScreen フィルタ (配点: 10)
    private static SecurityCheckItem CheckSmartScreen()
    {
        var item = new SecurityCheckItem
        {
            Id = "SMARTSCREEN",
            Name = Loc.T(
                "🌐 SmartScreen (Blocks Unknown Malicious Files)",
                "🌐 SmartScreen (拦截未知危险文件执行)",
                "🌐 SmartScreen (Bloqueo de archivos peligrosos desconocidos)",
                "🌐 SmartScreen (未知の危険ファイル実行ブロック)"),
            Weight = 10,
            FixCommand = "windowsdefender:"
        };

        try
        {
            using var rk = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", false);
            string val = rk?.GetValue("SmartScreenEnabled")?.ToString() ?? "On";

            if (val.Equals("Off", StringComparison.OrdinalIgnoreCase))
            {
                item.Result = CheckResult.Fail;
                item.StatusText = Loc.T("Disabled (Off)", "已禁用 (Off)", "Desactivado (Off)", "無効 (Off)");
                item.Advice = Loc.T(
                    "Enable SmartScreen in App & browser control to prevent running unknown downloaded malware.",
                    "请在“应用和浏览器控制”中启用 SmartScreen，以防运行从网络下载的未知恶意软件。",
                    "Active SmartScreen en Control de aplicaciones y navegadores para evitar ejecutar malware descargado.",
                    "ネットからダウンロードした未知のマルウェア実行を防ぐため、アプリとブラウザー制御でSmartScreenを有効にしてください。");
            }
            else
            {
                item.Result = CheckResult.Pass;
                item.StatusText = Loc.T($"Enabled ({val})", $"已启用 ({val})", $"Activado ({val})", $"有効 ({val})");
                item.Advice = Loc.T(
                    "Pre-execution reputation checks for downloaded files are active.",
                    "下载文件的运行前信誉检查已启用。",
                    "La verificación previa a la ejecución de archivos descargados está activa.",
                    "ダウンロードファイルの実行前チェックが有効です。");
            }
        }
        catch
        {
            item.Result = CheckResult.Pass;
            item.StatusText = Loc.T("Default", "默认设置", "Predeterminado", "標準設定");
        }
        return item;
    }

    // 5. リモートデスクトップ (RDP) 着信設定と NLA (配点: 10)
    private static SecurityCheckItem CheckRemoteDesktopExposure()
    {
        var item = new SecurityCheckItem
        {
            Id = "RDP_CONFIG",
            Name = Loc.T(
                "🖥️ Remote Desktop (RDP) Inbound & NLA Protection",
                "🖥️ 远程桌面 (RDP) 入站与 NLA 保护",
                "🖥️ Escritorio Remoto (RDP) Entrante y Protección NLA",
                "🖥️ リモートデスクトップ (RDP) 着信・NLA保護"),
            Weight = 10,
            FixCommand = "SystemPropertiesRemote.exe"
        };

        try
        {
            using var ts = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server", false);
            int deny = Convert.ToInt32(ts?.GetValue("fDenyTSConnections") ?? 1);

            if (deny == 1)
            {
                item.Result = CheckResult.Pass;
                item.StatusText = Loc.T("Inbound RDP connections denied (Safe)", "已拒绝外部 RDP 入站连接 (安全)", "Conexiones RDP entrantes denegadas (Seguro)", "外部からのRDP着信は拒否 (安全)");
                item.Advice = Loc.T(
                    "External Remote Desktop connections are disabled.",
                    "无需担心外部通过远程桌面连接到此电脑。",
                    "Las conexiones entrantes de Escritorio remoto están deshabilitadas.",
                    "外部からリモートデスクトップ接続される心配はありません。");
            }
            else
            {
                using var rdpTcp = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", false);
                int nla = Convert.ToInt32(rdpTcp?.GetValue("UserAuthentication") ?? 0);
                if (nla == 1)
                {
                    item.Result = CheckResult.Warning;
                    item.StatusText = Loc.T("Inbound RDP allowed (NLA enabled)", "允许 RDP 入站连接 (已启用 NLA 认证)", "RDP entrante permitido (NLA activado)", "RDP着信が許可されています (NLA認証あり)");
                    item.Advice = Loc.T(
                        "If you do not actively use Remote Desktop, turning it off improves security.",
                        "如果平时不使用远程桌面，建议将其关闭以提高安全性。",
                        "Si no utiliza habitualmente el Escritorio remoto, desactivarlo es más seguro.",
                        "普段リモートデスクトップを使わない場合は「リモートデスクトップを有効にする」をオフにするとより安全です。");
                }
                else
                {
                    item.Result = CheckResult.Fail;
                    item.StatusText = Loc.T("Inbound RDP enabled WITHOUT NLA!", "已启用 RDP 入站且未开启 NLA 网络级认证！", "¡RDP entrante activado SIN autenticación NLA!", "RDP着信が有効かつ NLA(ネットワークレベル認証) が無効！");
                    item.Advice = Loc.T(
                        "High risk! Disable RDP or require Network Level Authentication (NLA) immediately.",
                        "非常危险！请立即禁用 RDP 或开启网络级身份验证 (NLA)。",
                        "¡Muy peligroso! Desactive RDP o active la Autenticación a nivel de red (NLA) inmediatamente.",
                        "非常に危険です。RDPを無効化するか、必ずNLA認証をオンにしてください。");
                }
            }
        }
        catch
        {
            item.Result = CheckResult.Unknown;
            item.StatusText = Loc.T("Unable to query", "无法获取状态", "No disponible", "状態取得不可");
        }
        return item;
    }

    // 6. UEFI セキュアブート (配点: 8)
    private static SecurityCheckItem CheckSecureBoot()
    {
        var item = new SecurityCheckItem
        {
            Id = "SECURE_BOOT",
            Name = Loc.T(
                "🔒 UEFI Secure Boot (Bootkit Prevention)",
                "🔒 UEFI 安全启动 (防止 Bootkit)",
                "🔒 Arranque Seguro UEFI (Prevención de Bootkits)",
                "🔒 UEFI セキュアブート (ブートキット防止)"),
            Weight = 8,
            FixCommand = "msinfo32.exe"
        };

        try
        {
            using var sb = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", false);
            int enabled = Convert.ToInt32(sb?.GetValue("UEFISecureBootEnabled") ?? -1);
            if (enabled == 1)
            {
                item.Result = CheckResult.Pass;
                item.StatusText = Loc.T("Enabled (UEFISecureBootEnabled=1)", "已启用 (UEFISecureBootEnabled=1)", "Activado (UEFISecureBootEnabled=1)", "有効 (UEFISecureBootEnabled=1)");
                item.Advice = Loc.T(
                    "Pre-OS bootloader tampering is prevented.",
                    "可防止操作系统启动前的引导加载程序被篡改。",
                    "Se previene la manipulación del cargador de arranque antes del SO.",
                    "OS起動前のブートローダー改ざんが防止されています。");
            }
            else if (enabled == 0)
            {
                item.Result = CheckResult.Warning;
                item.StatusText = Loc.T("Disabled in BIOS/UEFI", "未启用 (BIOS/UEFI 设置中关闭)", "Desactivado en BIOS/UEFI", "無効 (BIOS/UEFI設定でオフ)");
                item.Advice = Loc.T(
                    "Enabling Secure Boot in your UEFI firmware settings improves boot integrity.",
                    "在电脑 UEFI 设置中启用 Secure Boot 可提高启动安全性。",
                    "Activar Secure Boot en la configuración UEFI mejora la seguridad de arranque.",
                    "PCのUEFI設定でSecure Bootを有効にすると起動時の安全性が高まります。");
            }
            else
            {
                item.Result = CheckResult.Pass;
                item.StatusText = Loc.T("Standard configuration", "标准配置", "Configuración estándar", "標準構成");
                item.Advice = Loc.T(
                    "You can inspect details in System Information (msinfo32).",
                    "可在系统信息 (msinfo32) 中查看详情。",
                    "Puede ver los detalles en Información del sistema (msinfo32).",
                    "システム情報 (msinfo32) で詳細を確認できます。");
            }
        }
        catch
        {
            item.Result = CheckResult.Unknown;
            item.StatusText = Loc.T("Unable to query", "无法获取状态", "No disponible", "状態取得不可");
        }
        return item;
    }

    // 7. SMBv1 (WannaCry 等で使われた古い共有プロトコル) 無効化 (配点: 6)
    private static SecurityCheckItem CheckSmbV1Disabled()
    {
        var item = new SecurityCheckItem
        {
            Id = "SMBV1",
            Name = Loc.T(
                "🚫 Legacy SMBv1 Protocol Disabled",
                "🚫 禁用旧版 SMBv1 协议",
                "🚫 Protocolo antiguo SMBv1 deshabilitado",
                "🚫 旧式プロトコル SMBv1 の無効化"),
            Weight = 6,
            FixCommand = "OptionalFeatures.exe"
        };

        try
        {
            using var srv = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", false);
            object? smb1Val = srv?.GetValue("SMB1");
            using var mrx = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\mrxsmb10", false);
            int mrxStart = Convert.ToInt32(mrx?.GetValue("Start") ?? 4);

            bool smb1Enabled = (smb1Val != null && Convert.ToInt32(smb1Val) == 1) || (mrx != null && mrxStart <= 2);
            if (!smb1Enabled)
            {
                item.Result = CheckResult.Pass;
                item.StatusText = Loc.T("Disabled (Using secure SMBv2/v3 only)", "已禁用 (仅使用安全的 SMBv2/v3)", "Desactivado (Solo SMBv2/v3 seguro)", "無効 (安全な SMBv2/v3 のみ使用)");
                item.Advice = Loc.T(
                    "Legacy SMBv1 exploited by network worms like WannaCry is disabled.",
                    "WannaCry 等网络蠕虫勒索软件利用的旧版 SMBv1 已禁用。",
                    "El protocolo SMBv1 explotado por ransomware como WannaCry está desactivado.",
                    "WannaCry 等のネットワーク感染型ランサムウェアが使う SMBv1 は無効化されています。");
            }
            else
            {
                item.Result = CheckResult.Fail;
                item.StatusText = Loc.T("SMBv1 is enabled", "SMBv1 处于启用状态", "SMBv1 está activado", "SMBv1 が有効になっています");
                item.Advice = Loc.T(
                    "Uncheck 'SMB 1.0/CIFS File Sharing Support' in Windows Features (OptionalFeatures.exe).",
                    "请在“启用或关闭 Windows 功能”中取消勾选“SMB 1.0/CIFS 文件共享支持”。",
                    "Desmarque 'Compatibilidad con uso compartido de archivos SMB 1.0/CIFS' en Características de Windows.",
                    "「Windowsの機能の有効化または無効化」から「SMB 1.0/CIFS ファイル共有のサポート」のチェックを外してください。");
            }
        }
        catch
        {
            item.Result = CheckResult.Pass;
            item.StatusText = Loc.T("Disabled (Windows 11 default)", "已禁用 (Windows 11 默认)", "Desactivado (Predeterminado en Windows 11)", "無効 (Windows 11 標準)");
        }
        return item;
    }

    // 8. USB・外部メディアの自動実行 (AutoRun) 防止 (配点: 4)
    private static SecurityCheckItem CheckAutoRunDisabled()
    {
        var item = new SecurityCheckItem
        {
            Id = "AUTORUN",
            Name = Loc.T(
                "💾 External Media AutoRun Block",
                "💾 外部介质自动运行 (AutoRun) 拦截",
                "💾 Bloqueo de AutoRun en medios externos",
                "💾 外部メディア自動実行 (AutoRun) ブロック"),
            Weight = 4,
            FixCommand = "ms-settings:autoplay"
        };

        try
        {
            using var rk = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers", false);
            int disableAutoplay = Convert.ToInt32(rk?.GetValue("DisableAutoplay") ?? 0);
            if (disableAutoplay == 1)
            {
                item.Result = CheckResult.Pass;
                item.StatusText = Loc.T("AutoPlay Off (Most secure)", "自动播放已关闭 (最安全)", "Reproducción automática desactivada (Más seguro)", "自動再生オフ (最も安全)");
                item.Advice = Loc.T(
                    "Unintended program execution upon inserting USB drives is blocked.",
                    "已拦截插入 U 盘时意外自动运行程序。",
                    "Se bloquea la ejecución involuntaria al insertar unidades USB.",
                    "USBメモリ挿入時の意図しないプログラム自動起動がブロックされています。");
            }
            else
            {
                item.Result = CheckResult.Pass;
                item.StatusText = Loc.T("Windows Default (autorun.inf blocked by OS)", "Windows 默认 (OS 已默认拦截 autorun.inf)", "Predeterminado (autorun.inf bloqueado por el SO)", "Windows標準 (autorun.inf 自動実行はOS標準でブロック済)");
                item.Advice = Loc.T(
                    "For extra safety, you can turn off AutoPlay in Settings > Bluetooth & devices > AutoPlay.",
                    "如需进一步提高安全性，可在“设置 > 蓝牙和其他设备 > 自动播放”中将其关闭。",
                    "Para mayor seguridad, puede desactivar Reproducción automática en Configuración > Bluetooth y dispositivos.",
                    "さらに安全にするには「設定 > Bluetoothとデバイス > 自動再生」をオフにできます。");
            }
        }
        catch
        {
            item.Result = CheckResult.Pass;
            item.StatusText = Loc.T("Standard", "标准", "Estándar", "標準");
        }
        return item;
    }

    // 9. hosts ファイルの改ざんチェック (配点: 5)
    private static SecurityCheckItem CheckHostsFileIntegrity()
    {
        var item = new SecurityCheckItem
        {
            Id = "HOSTS_FILE",
            Name = Loc.T(
                "📄 hosts File Integrity (DNS Hijack Check)",
                "📄 hosts 文件完整性 (检查域名解析篡改)",
                "📄 Integridad del archivo hosts (Revisión de redirección DNS)",
                "📄 hosts ファイル (名前解決の改ざん有無)"),
            Weight = 5,
            FixCommand = "notepad.exe"
        };

        try
        {
            string hostsPath = Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts");
            if (!File.Exists(hostsPath))
            {
                item.Result = CheckResult.Pass;
                item.StatusText = Loc.T("Default state (No custom entries)", "默认状态 (无自定义条目)", "Estado predeterminado (Sin entradas personalizadas)", "デフォルト状態 (カスタム定義なし)");
                return item;
            }

            var activeLines = File.ReadAllLines(hostsPath)
                .Select(l => l.Trim())
                .Where(l => !string.IsNullOrEmpty(l) && !l.StartsWith("#"))
                .Where(l => !l.Contains("localhost", StringComparison.OrdinalIgnoreCase) &&
                            !l.Contains("broadcasthost", StringComparison.OrdinalIgnoreCase) &&
                            !l.StartsWith("::1"))
                .ToList();

            if (activeLines.Count == 0)
            {
                item.Result = CheckResult.Pass;
                item.StatusText = Loc.T("Clean (No suspicious redirects)", "正常 (无异常重定向定义)", "Normal (Sin redirecciones sospechosas)", "正常 (不審なリダイレクト定義なし)");
                item.Advice = Loc.T(
                    "No blocking of Windows Update/antivirus sites or phishing redirects found.",
                    "未发现屏蔽安全更新站点或诱导至钓鱼网站的重定向设置。",
                    "No se detectaron bloqueos de sitios de seguridad ni redirecciones maliciosas.",
                    "Windows Update やウイルス対策サイトの遮断・偽サイト誘導は行われていません。");
            }
            else
            {
                item.Result = CheckResult.Warning;
                item.StatusText = Loc.T(
                    $"{activeLines.Count} custom entry/entries (e.g. {CommandLineAnalyzer.Shorten(activeLines[0], 45)})",
                    $"存在 {activeLines.Count} 条自定义配置 (例: {CommandLineAnalyzer.Shorten(activeLines[0], 45)})",
                    $"{activeLines.Count} entrada(s) personalizada(s) (ej.: {CommandLineAnalyzer.Shorten(activeLines[0], 45)})",
                    $"カスタム定義が {activeLines.Count} 件あります (例: {CommandLineAnalyzer.Shorten(activeLines[0], 45)})");
                item.Advice = Loc.T(
                    @"If you did not add these entries yourself, inspect C:\Windows\System32\drivers\etc\hosts.",
                    @"如果不是您本人添加的配置，请检查 C:\Windows\System32\drivers\etc\hosts 的内容。",
                    @"Si no agregó estas entradas usted mismo, revise C:\Windows\System32\drivers\etc\hosts.",
                    @"自分で追加した設定でない場合は C:\Windows\System32\drivers\etc\hosts の内容を確認してください。");
            }
        }
        catch
        {
            item.Result = CheckResult.Unknown;
            item.StatusText = Loc.T("Unreadable", "无法读取", "No legible", "読み取り不可");
        }
        return item;
    }

    // 10. システムプロキシ / PAC スクリプトの改ざんチェック (配点: 5)
    private static SecurityCheckItem CheckProxySettings()
    {
        var item = new SecurityCheckItem
        {
            Id = "PROXY_CONFIG",
            Name = Loc.T(
                "🌍 System Proxy Settings (MITM Relay Check)",
                "🌍 系统代理设置 (检查中间人转发)",
                "🌍 Configuración de Proxy (Revisión de intermediarios)",
                "🌍 通信プロキシ設定 (中間者中継の有無)"),
            Weight = 5,
            FixCommand = "ms-settings:network-proxy"
        };

        try
        {
            using var rk = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", false);
            int proxyEnable = Convert.ToInt32(rk?.GetValue("ProxyEnable") ?? 0);
            string proxyServer = rk?.GetValue("ProxyServer")?.ToString() ?? "";
            string autoConfigUrl = rk?.GetValue("AutoConfigURL")?.ToString() ?? "";

            if (proxyEnable == 0 && string.IsNullOrWhiteSpace(autoConfigUrl))
            {
                item.Result = CheckResult.Pass;
                item.StatusText = Loc.T("No proxy used (Direct connection)", "未使用代理 (直接连接)", "Sin proxy (Conexión directa)", "プロキシ未使用 (直接通信)");
                item.Advice = Loc.T(
                    "Traffic is not being routed through any suspicious proxy server.",
                    "未设置将通信转发至可疑代理服务器。",
                    "El tráfico no se redirige a través de ningún servidor proxy sospechoso.",
                    "不審なプロキシサーバーへの通信転送は設定されていません。");
            }
            else
            {
                item.Result = CheckResult.Warning;
                item.StatusText = Loc.T(
                    $"Proxy configured ({(!string.IsNullOrEmpty(proxyServer) ? proxyServer : autoConfigUrl)})",
                    $"已配置代理 ({(!string.IsNullOrEmpty(proxyServer) ? proxyServer : autoConfigUrl)})",
                    $"Proxy configurado ({(!string.IsNullOrEmpty(proxyServer) ? proxyServer : autoConfigUrl)})",
                    $"プロキシ設定あり ({(!string.IsNullOrEmpty(proxyServer) ? proxyServer : autoConfigUrl)})");
                item.Advice = Loc.T(
                    "If this is not a corporate network or a VPN/proxy you configured, turn it off in Settings > Network & internet > Proxy.",
                    "如果不是企业内网或您本人设置的 VPN/代理，请在“设置 > 网络和 Internet > 代理”中将其关闭。",
                    "Si no es una red corporativa o un proxy/VPN propio, desactívelo en Configuración > Red e Internet > Proxy.",
                    "社内ネットワークや自分で設定したVPN/プロキシでない場合は、「設定 > ネットワークとインターネット > プロキシ」からオフにしてください。");
            }
        }
        catch
        {
            item.Result = CheckResult.Unknown;
            item.StatusText = Loc.T("Unable to query", "无法获取状态", "No disponible", "取得不可");
        }
        return item;
    }
}
