using System.Diagnostics.Eventing.Reader;
using System.Security.Cryptography.X509Certificates;
using AnzenSecurityWatcher.Models;

namespace AnzenSecurityWatcher.Services;

/// <summary>
/// システム整合性・アカウント・証明書監視サービス
/// 1. ルート証明書ストアへの不審な追加の検知 (MITM 通信盗聴対策)
/// 2. ログオン失敗 (4625) やアカウント新規作成 (4720) / グループ追加 (4732, 4728) のイベントログ監視
/// 3. ローカル管理者グループ (Administrators) およびローカルユーザー一覧の変更検知
/// </summary>
public class SystemIntegrityMonitorService
{
    private const string CertBaselineFile = "rootcert_baseline.json";
    private const string AdminBaselineFile = "admingroup_baseline.json";

    private HashSet<string> _certBaseline = new(StringComparer.OrdinalIgnoreCase);
    private bool _certBaselineLoaded;

    private AdminBaselineData? _adminBaseline;
    private bool _adminBaselineLoaded;

    public class AdminBaselineData
    {
        public List<string> AdminMembers { get; set; } = new();
        public List<string> LocalUsers { get; set; } = new();
    }

    // 代表的な信頼された商用/OSルートCA発行者キーワード
    private static readonly string[] KnownRootCaKeywords =
    {
        "Microsoft", "DigiCert", "GlobalSign", "Sectigo", "COMODO", "Entrust", "VeriSign",
        "Symantec", "Thawte", "GeoTrust", "Baltimore", "CyberTrust", "IdenTrust",
        "ISRG Root", "Let's Encrypt", "Go Daddy", "GoDaddy", "Starfield", "Amazon",
        "Google Trust Services", "GTS Root", "Apple", "USERTrust", "AAA Certificate",
        "QuoVadis", "SwissSign", "Certum", "Actalis", "Buypass", "SSL.com", "HARICA",
        "SECOM", "Security Communication RootCA", "Japan Certification Services", "AffirmTrust",
        "TrustWave", "XRamp", "eMudhra", "Telia", "T-TeleSec", "D-TRUST", " Chambers of Commerce"
    };

    // 通信復号・プロキシ・開発ツール系のルート証明書キーワード（インストールされているとHTTPS復号が可能）
    private static readonly string[] MitmProxyCertKeywords =
    {
        "Fiddler", "DO_NOT_TRUST", "Charles Proxy", "mitmproxy", "Burp", "PortSwigger",
        "Zscaler", "Netskope", "Fortinet", "FortiGate", "Palo Alto", "Check Point",
        "Kaspersky", "ESET SSL", "Avast", "Bitdefender", "AdGuard", "Proxyman", "mkcert", "localhost"
    };

    public List<FindingReport> Scan()
    {
        var reports = new List<FindingReport>();
        ScanRootCertificates(reports);
        ScanAdminGroupAndUsers(reports);
        ScanSecurityEventLogs(reports);
        return reports;
    }

    // =========================================================================
    // 1. ルート証明書ストアの監視 (CurrentUser & LocalMachine)
    // =========================================================================
    private void ScanRootCertificates(List<FindingReport> reports)
    {
        EnsureCertBaselineLoaded();
        bool isFirst = _certBaseline.Count == 0;
        bool modified = false;

        (StoreLocation Loc, string Label)[] locations =
        {
            (StoreLocation.CurrentUser, Loc.T("CurrentUser (User-specific)", "CurrentUser (当前用户)", "CurrentUser (Usuario actual)", "CurrentUser (ユーザー固有)")),
            (StoreLocation.LocalMachine, Loc.T("LocalMachine (System-wide)", "LocalMachine (整机范围)", "LocalMachine (Todo el equipo)", "LocalMachine (PC全体)"))
        };

        foreach (var (loc, locLabel) in locations)
        {
            try
            {
                using var store = new X509Store(StoreName.Root, loc);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                foreach (var cert in store.Certificates)
                {
                    try
                    {
                        string thumb = cert.Thumbprint ?? "";
                        if (string.IsNullOrEmpty(thumb)) continue;

                        string storeKey = $"{loc}:{thumb}";
                        bool isNew = false;
                        if (isFirst)
                        {
                            _certBaseline.Add(storeKey);
                            modified = true;
                        }
                        else if (_certBaseline.Add(storeKey))
                        {
                            isNew = true;
                            modified = true;
                        }

                        string subject = cert.Subject ?? "";
                        string issuer = cert.Issuer ?? "";
                        string cn = SignatureHelper.ExtractCommonName(subject);

                        var category = ClassifyRootCert(cert, subject, issuer, loc);
                        var (risk, confidence, categoryLabel) = EvaluateRootCert(category, isNew, cert, loc);
                        var reasons = new List<string> { categoryLabel };
                        if (isNew)
                            reasons.Insert(0, Loc.T(
                                "Root certificate newly added after monitoring started",
                                "监控开始后新增的根证书",
                                "Certificado raíz añadido tras iniciar el monitoreo",
                                "監視開始後に新規追加されたルート証明書"));

                        // 既知の公開CA/レガシーCAで新規でないものは通知しない
                        if (risk == RiskLevel.Safe) continue;

                        string title = $"📜 [ルート証明書] {cn} ({loc})";
                        string detail = $"{string.Join(" / ", reasons)} — 有効期限:{cert.NotAfter:yyyy-MM-dd}";
                        string tech =
                            $"格納ストア: {locLabel} — 信頼されたルート証明機関 (Root)\n" +
                            $"分類: {category}\n" +
                            $"サブジェクト (CN): {subject}\n" +
                            $"発行者 (Issuer): {issuer}\n" +
                            $"拇印 (Thumbprint): {thumb}\n" +
                            $"有効期間: {cert.NotBefore:yyyy-MM-dd} ～ {cert.NotAfter:yyyy-MM-dd}\n" +
                            $"判定理由: {string.Join(" / ", reasons)}";

                        reports.Add(new FindingReport(
                            Key: $"CERT:{storeKey}",
                            Category: FindingCategory.RootCertificate,
                            Severity: risk,
                            State: isNew ? FindingState.New : FindingState.Existing,
                            Title: title,
                            Detail: detail,
                            Target: $"{cn} ({thumb[..Math.Min(12, thumb.Length)]}...)",
                            TechnicalDetails: tech,
                            RecommendedAction: "このルート証明書が信頼されている場合、対応する秘密鍵を保持する主体が証明書を発行できるため、HTTPS検証に影響する可能性があります。ただし、この証明書の存在だけでHTTPS通信が盗聴されていることを意味しません。心当たりがなければ certmgr.msc / certlm.msc で発行者・有効期間・導入時期を確認してください。",
                            Confidence: confidence,
                            StoryKey: "STORY:ROOT_CERTS",
                            StoryTitle: "Root Certificate Store"));
                    }
                    finally
                    {
                        cert.Dispose();
                    }
                }
            }
            catch { }
        }

        if (modified)
            JsonStore.Save(CertBaselineFile, _certBaseline.ToList());
    }

    private enum RootCertCategory
    {
        KnownPublicCa, KnownLegacyOrExpiredCa, EnterpriseCa, VpnOrSecurityProductCa,
        LocalhostInterceptionCa, UserInstalledUnknownCa, RecentlyCreatedUnknownCa
    }

    private static readonly string[] LegacyCaKeywords =
    {
        "DST Root CA X3", "AddTrust", "Hotspot 2.0", "SecureTrust", "Trustwave", "XRamp",
        "UTN-USERFirst", "Equifax", "GTE CyberTrust", "Thawte", "VeriSign", "Baltimore"
    };
    private static readonly string[] SecurityProductCaKeywords =
    {
        "Zscaler", "Netskope", "Fortinet", "FortiGate", "Palo Alto", "Check Point",
        "Kaspersky", "ESET SSL", "Avast", "Bitdefender", "AdGuard", "Cisco Umbrella", "Forcepoint"
    };
    private static readonly string[] LocalhostInterceptionKeywords =
    {
        "Fiddler", "DO_NOT_TRUST", "Charles Proxy", "mitmproxy", "Burp", "PortSwigger", "Proxyman", "mkcert", "localhost"
    };

    private static RootCertCategory ClassifyRootCert(X509Certificate2 cert, string subject, string issuer, StoreLocation loc)
    {
        bool Has(string[] kws) => kws.Any(k => subject.Contains(k, StringComparison.OrdinalIgnoreCase) || issuer.Contains(k, StringComparison.OrdinalIgnoreCase));

        if (Has(LocalhostInterceptionKeywords)) return RootCertCategory.LocalhostInterceptionCa;
        if (Has(SecurityProductCaKeywords)) return RootCertCategory.VpnOrSecurityProductCa;
        if (Has(LegacyCaKeywords) || cert.NotAfter < DateTime.Now) return RootCertCategory.KnownLegacyOrExpiredCa;
        if (Has(KnownRootCaKeywords)) return RootCertCategory.KnownPublicCa;
        // 自己署名でなく、ドメイン内CA風 (DC= を含む) の場合は Enterprise CA
        if (subject.Contains("DC=", StringComparison.OrdinalIgnoreCase)) return RootCertCategory.EnterpriseCa;
        if (loc == StoreLocation.CurrentUser)
        {
            bool recent = cert.NotBefore > DateTime.Now.AddDays(-90);
            bool longValidity = (cert.NotAfter - cert.NotBefore).TotalDays > 365 * 5;
            if (recent && longValidity) return RootCertCategory.RecentlyCreatedUnknownCa;
            return RootCertCategory.UserInstalledUnknownCa;
        }
        // LocalMachine の未知CAは Windows Update 配布のバンドル CA が大半
        return RootCertCategory.KnownPublicCa;
    }

    private static (RiskLevel Risk, ConfidenceLevel Conf, string Label) EvaluateRootCert(
        RootCertCategory cat, bool isNew, X509Certificate2 cert, StoreLocation loc)
    {
        // 新規追加は一段階引き上げる
        RiskLevel Bump(RiskLevel r) => isNew && r < RiskLevel.Critical ? r + 1 : r;
        return cat switch
        {
            RootCertCategory.KnownPublicCa => (isNew ? RiskLevel.Low : RiskLevel.Safe, ConfidenceLevel.High,
                "Known public CA (標準的な公開CA)"),
            RootCertCategory.KnownLegacyOrExpiredCa => (isNew ? RiskLevel.Low : RiskLevel.Safe, ConfidenceLevel.High,
                "Known legacy/expired CA (既知の歴史的・期限切れCA。非MicrosoftであることだけではSuspiciousではない)"),
            RootCertCategory.EnterpriseCa => (Bump(RiskLevel.Low), ConfidenceLevel.Medium,
                "Enterprise CA (組織内CAの可能性)"),
            RootCertCategory.VpnOrSecurityProductCa => (Bump(RiskLevel.Low), ConfidenceLevel.Medium,
                "VPN/security-product CA (セキュリティ製品・プロキシ由来のCA)"),
            RootCertCategory.LocalhostInterceptionCa => (Bump(RiskLevel.Medium), ConfidenceLevel.High,
                "Localhost/debug interception CA (ローカルHTTPS復号・開発用プロキシCA)"),
            RootCertCategory.UserInstalledUnknownCa => (Bump(RiskLevel.Low), ConfidenceLevel.Low,
                "User-installed unknown CA (CurrentUser に導入された未知のCA)"),
            _ => (RiskLevel.High, ConfidenceLevel.Medium,
                "Recently-created unknown CA (CurrentUser + 未知CA + 直近作成 + 長期有効)")
        };
    }

    private void EnsureCertBaselineLoaded()
    {
        if (_certBaselineLoaded) return;
        _certBaselineLoaded = true;
        var loaded = JsonStore.Load<List<string>>(CertBaselineFile);
        if (loaded != null)
            _certBaseline = new HashSet<string>(loaded, StringComparer.OrdinalIgnoreCase);
    }

    // =========================================================================
    // 2. ローカル管理者グループ (Administrators) ＆ ローカルユーザーの変更検知
    // =========================================================================
    private void ScanAdminGroupAndUsers(List<FindingReport> reports)
    {
        EnsureAdminBaselineLoaded();

        // Administrators グループ（英語/日本語環境対応）
        var adminMembers = NativeSecurity.GetLocalGroupMembers("Administrators")
                        ?? NativeSecurity.GetLocalGroupMembers("管理者")
                        ?? new List<string>();

        var localUsers = NativeSecurity.GetLocalUsers() ?? new List<NativeSecurity.LocalUserInfo>();
        var activeUserNames = localUsers.Select(u => $"{u.Name}:{(u.IsDisabled ? "Disabled" : "Enabled")}").ToList();

        bool isFirst = _adminBaseline == null;
        if (isFirst)
        {
            _adminBaseline = new AdminBaselineData
            {
                AdminMembers = adminMembers,
                LocalUsers = activeUserNames
            };
            JsonStore.Save(AdminBaselineFile, _adminBaseline);
        }

        var baseAdmins = new HashSet<string>(_adminBaseline!.AdminMembers, StringComparer.OrdinalIgnoreCase);
        var baseUsers = new HashSet<string>(_adminBaseline.LocalUsers, StringComparer.OrdinalIgnoreCase);
        bool baselineUpdated = false;

        // 2-A. 管理者グループのメンバー確認（新規追加は Critical、既存も一覧として可視化）
        foreach (var member in adminMembers)
        {
            bool isAdded = !isFirst && !baseAdmins.Contains(member);
            if (isAdded)
            {
                _adminBaseline.AdminMembers.Add(member);
                baselineUpdated = true;
            }

            var risk = isAdded ? RiskLevel.Critical : RiskLevel.Low;
            string title = isAdded
                ? Loc.T(
                    $"👑 [New Administrator Added!] {member}",
                    $"👑 【新增管理员组成员！】{member}",
                    $"👑 [¡Nuevo Administrador Añadido!] {member}",
                    $"👑 【管理者グループ新規追加！】{member}")
                : Loc.T(
                    $"👑 [Local Administrator Member] {member}",
                    $"👑 [本地管理员组成员] {member}",
                    $"👑 [Miembro Administrador Local] {member}",
                    $"👑 [ローカル管理者メンバー] {member}");

            string detail = isAdded
                ? Loc.T(
                    $"Account '{member}' was added to the local Administrators group after monitoring started!",
                    $"监控开始后，账户“{member}”被添加到了本地 Administrators 组！",
                    $"¡La cuenta '{member}' fue añadida al grupo local Administrators tras iniciar el monitoreo!",
                    $"監視開始後に Administrators グループへ『{member}』が追加されました！")
                : Loc.T(
                    $"Member of Administrators group (Total: {adminMembers.Count})",
                    $"Administrators 组成员账户 (共 {adminMembers.Count} 名)",
                    $"Cuenta miembro del grupo Administrators (Total: {adminMembers.Count})",
                    $"Administrators グループ所属アカウント (計{adminMembers.Count}名)");

            string stateDesc = isAdded
                ? Loc.T("🆕 Newly added after monitoring started", "🆕 监控开始后新增", "🆕 Recién añadido", "🆕 監視開始後に新規追加")
                : Loc.T("Existing administrator member", "既有管理员成员", "Miembro administrador existente", "既存の管理者メンバー");
            string allMembers = string.Join(", ", adminMembers);

            string tech = Loc.T(
                $"Group Name: Administrators (Local Administrators)\nAccount Name: {member}\nStatus: {stateDesc}\nAll Current Administrators: {allMembers}",
                $"组名称: Administrators (本地管理员)\n账户名: {member}\n状态: {stateDesc}\n当前所有管理员成员: {allMembers}",
                $"Grupo: Administrators (Administradores locales)\nCuenta: {member}\nEstado: {stateDesc}\nTodos los administradores actuales: {allMembers}",
                $"グループ名: Administrators (ローカル管理者)\nアカウント名: {member}\n状態: {stateDesc}\n現在の全管理者メンバー: {allMembers}");

            string recAction = Loc.T(
                "If an unrecognized account is in the Administrators group, revoke its privileges immediately via Computer Management (lusrmgr.msc) or `net localgroup administrators <name> /delete`.",
                "如果 Administrators 组中包含不明账户，请立即通过“计算机管理 (lusrmgr.msc)”或 `net localgroup administrators <名称> /delete` 撤销其权限。",
                "Si hay una cuenta desconocida en el grupo Administrators, revoque sus privilegios de inmediato mediante Administración de equipos (lusrmgr.msc) o `net localgroup administrators <nombre> /delete`.",
                "身に覚えのないアカウントが Administrators に含まれている場合は、『コンピューターの管理 (lusrmgr.msc)』または `net localgroup administrators <名前> /delete` で直ちに権限を剥奪してください。");

            reports.Add(new FindingReport(
                Key: $"ADMIN_MEMBER:{member}",
                Category: FindingCategory.AdminGroup,
                Severity: risk,
                State: isAdded ? FindingState.New : FindingState.Existing,
                Title: title,
                Detail: detail,
                Target: member,
                TechnicalDetails: tech,
                RecommendedAction: recAction));
        }

        // 2-B. ローカルユーザーの新規作成・有効化検知
        foreach (var u in localUsers)
        {
            string entryKey = $"{u.Name}:{(u.IsDisabled ? "Disabled" : "Enabled")}";
            bool isNewOrEnabled = !isFirst && !baseUsers.Contains(entryKey);
            if (isNewOrEnabled)
            {
                _adminBaseline.LocalUsers.Add(entryKey);
                baselineUpdated = true;

                string enabledDesc = u.IsDisabled
                    ? Loc.T("Disabled", "已禁用", "Deshabilitado", "無効")
                    : Loc.T("Enabled", "已启用", "Habilitado", "有効");

                string title = Loc.T(
                    $"👤 [Local Account Change Detected] {u.Name}",
                    $"👤 【检测到本地账户变更】{u.Name}",
                    $"👤 [Cambio de Cuenta Local Detectado] {u.Name}",
                    $"👤 【ローカルアカウント変更検知】{u.Name}");

                string detail = Loc.T(
                    $"Account '{u.Name}' was newly created or enabled (Status: {enabledDesc}, Admin: {u.IsAdminPriv})",
                    $"账户“{u.Name}”被新创建或启用 (状态:{enabledDesc}, 管理员权限:{u.IsAdminPriv})",
                    $"La cuenta '{u.Name}' fue creada o habilitada (Estado: {enabledDesc}, Admin: {u.IsAdminPriv})",
                    $"アカウント『{u.Name}』が新規作成または有効化されました (状態:{enabledDesc}, 管理者権限:{u.IsAdminPriv})");

                string tech = Loc.T(
                    $"Username: {u.Name}\nAccount Status: {enabledDesc}\nAdmin Privileges: {u.IsAdminPriv}\nPassword Age: {u.PasswordAgeDays} day(s)\nComment: {u.Comment}",
                    $"用户名: {u.Name}\n启用状态: {enabledDesc}\n管理员权限: {u.IsAdminPriv}\n密码已用天数: {u.PasswordAgeDays}天\n备注: {u.Comment}",
                    $"Usuario: {u.Name}\nEstado: {enabledDesc}\nPrivilegios Admin: {u.IsAdminPriv}\nAntigüedad de contraseña: {u.PasswordAgeDays} día(s)\nComentario: {u.Comment}",
                    $"ユーザー名: {u.Name}\n有効状態: {enabledDesc}\n管理者権限: {u.IsAdminPriv}\nパスワード経過日数: {u.PasswordAgeDays}日\nコメント: {u.Comment}");

                string recAction = Loc.T(
                    "An attacker may have created or enabled a backdoor account. Inspect local users via lusrmgr.msc or netplwiz.",
                    "攻击者可能创建或启用了后门账户。请通过 lusrmgr.msc 或 netplwiz 检查本地用户。",
                    "Un atacante podría haber creado o habilitado una cuenta de puerta trasera. Revise con lusrmgr.msc o netplwiz.",
                    "攻撃者がバックドア用アカウントを作成・有効化した可能性があります。lusrmgr.msc または netplwiz で確認してください。");

                reports.Add(new FindingReport(
                    Key: $"LOCAL_USER_CHANGE:{entryKey}",
                    Category: FindingCategory.Account,
                    Severity: RiskLevel.Critical,
                    State: FindingState.New,
                    Title: title,
                    Detail: detail,
                    Target: u.Name,
                    TechnicalDetails: tech,
                    RecommendedAction: recAction));
            }
        }

        if (baselineUpdated)
            JsonStore.Save(AdminBaselineFile, _adminBaseline);
    }

    private void EnsureAdminBaselineLoaded()
    {
        if (_adminBaselineLoaded) return;
        _adminBaselineLoaded = true;
        _adminBaseline = JsonStore.Load<AdminBaselineData>(AdminBaselineFile);
    }

    // =========================================================================
    // 3. セキュリティイベントログ監視 (ID: 4625 ログオン失敗, 4720 作成, 4732/4728 グループ追加)
    // =========================================================================
    private static void ScanSecurityEventLogs(List<FindingReport> reports)
    {
        try
        {
            // 直近24時間の 4625(ログオン失敗), 4720(アカウント作成), 4732(ローカルグループ追加), 4728(グローバルグループ追加)
            long msWindow = 24L * 3600 * 1000;
            string xpath = $"*[System[(EventID=4625 or EventID=4720 or EventID=4732 or EventID=4728) and TimeCreated[timediff(@SystemTime) <= {msWindow}]]]";
            var query = new EventLogQuery("Security", PathType.LogName, xpath)
            {
                ReverseDirection = true
            };

            using var reader = new EventLogReader(query);
            int failedLogonCount = 0;
            DateTime latestFailTime = DateTime.MinValue;
            var failedSamples = new List<string>();

            int readCount = 0;
            for (EventRecord? rec = reader.ReadEvent(); rec != null && readCount < 120; rec = reader.ReadEvent(), readCount++)
            {
                using (rec)
                {
                    int id = rec.Id;
                    DateTime time = rec.TimeCreated ?? DateTime.Now;
                    string desc = "";
                    try { desc = rec.FormatDescription() ?? ""; } catch { }
                    string firstLine = desc.Split('\n').FirstOrDefault()?.Trim() ?? $"EventID {id}";

                    if (id == 4625)
                    {
                        failedLogonCount++;
                        if (time > latestFailTime) latestFailTime = time;
                        if (failedSamples.Count < 4)
                            failedSamples.Add($"{time:HH:mm:ss} - {firstLine}");
                    }
                    else if (id is 4720 or 4732 or 4728)
                    {
                        string eventLabel = id switch
                        {
                            4720 => Loc.T("User Account Created (ID:4720)", "新建用户账户 (ID:4720)", "Cuenta de Usuario Creada (ID:4720)", "ユーザーアカウント新規作成 (ID:4720)"),
                            4732 => Loc.T("Member Added to Security Group (ID:4732)", "向安全组添加成员 (ID:4732)", "Miembro Añadido a Grupo de Seguridad (ID:4732)", "セキュリティグループへのメンバー追加 (ID:4732)"),
                            4728 => Loc.T("Member Added to Global Group (ID:4728)", "向全局组添加成员 (ID:4728)", "Miembro Añadido a Grupo Global (ID:4728)", "グローバルグループへのメンバー追加 (ID:4728)"),
                            _ => $"EventID:{id}"
                        };

                        string noDesc = Loc.T("(Details unavailable)", "(无法获取详细消息)", "(Detalles no disponibles)", "(詳細メッセージ取得不可)");
                        string descShort = string.IsNullOrEmpty(desc) ? noDesc : CommandLineAnalyzer.Shorten(desc, 600);

                        string tech = Loc.T(
                            $"Event ID: {id} ({eventLabel})\nTimestamp: {time:yyyy-MM-dd HH:mm:ss}\nDetails:\n{descShort}",
                            $"事件 ID: {id} ({eventLabel})\n发生时间: {time:yyyy-MM-dd HH:mm:ss}\n详情:\n{descShort}",
                            $"ID de evento: {id} ({eventLabel})\nFecha/Hora: {time:yyyy-MM-dd HH:mm:ss}\nDetalles:\n{descShort}",
                            $"イベントID: {id} ({eventLabel})\n発生日時: {time:yyyy-MM-dd HH:mm:ss}\n詳細:\n{descShort}");

                        string recAction = Loc.T(
                            "If this account creation or group modification event is unrecognized, it may indicate privilege escalation or backdoor creation. Inspect details in Event Viewer (eventvwr.msc).",
                            "如果是来历不明的账户创建或组成员变更事件，可能意味着入侵后的提权或后门创建。请在事件查看器 (eventvwr.msc) 中检查详情。",
                            "Si no reconoce este evento de creación de cuenta o cambio de grupo, puede indicar escalada de privilegios. Revise los detalles en el Visor de eventos (eventvwr.msc).",
                            "心当たりのないアカウント作成・グループ変更イベントの場合は、不正侵入後の権限昇格・バックドア作成の疑いがあります。イベントビューアー (eventvwr.msc) で詳細を確認してください。");

                        reports.Add(new FindingReport(
                            Key: $"EVTLOG:{id}:{rec.RecordId}",
                            Category: FindingCategory.Account,
                            Severity: RiskLevel.High,
                            State: (DateTime.Now - time).TotalMinutes <= 30 ? FindingState.New : FindingState.Existing,
                            Title: $"🔐 [{eventLabel}] ({time:MM/dd HH:mm})",
                            Detail: $"{firstLine}",
                            Target: $"Security EventID {id} (Record #{rec.RecordId})",
                            TechnicalDetails: tech,
                            RecommendedAction: recAction));
                    }
                }
            }

            if (failedLogonCount > 0)
            {
                var risk = failedLogonCount >= 10 ? RiskLevel.Critical
                         : failedLogonCount >= 3 ? RiskLevel.High
                         : RiskLevel.Medium;

                string title = Loc.T(
                    $"🔐 [Failed Logon Detected (ID:4625)] {failedLogonCount} time(s) in last 24h",
                    $"🔐 [检测到登录失败 (ID:4625)] 最近24小时内 {failedLogonCount} 次",
                    $"🔐 [Inicio de Sesión Fallido (ID:4625)] {failedLogonCount} veces en 24h",
                    $"🔐 [ログオン失敗検知 (ID:4625)] 直近24時間で {failedLogonCount} 回");

                string note = failedLogonCount >= 5
                    ? Loc.T("Beware of brute-force password attack", "警惕密码暴力破解攻击", "Cuidado con ataques de fuerza bruta", "ブルートフォース(総当たり攻撃)に注意")
                    : Loc.T("Failed logon recorded", "存在登录失败记录", "Registro de fallo de inicio de sesión", "ログオン失敗記録あり");

                string lastFailLabel = Loc.T("Latest failure", "最近失败", "Último fallo", "最終失敗");
                string detail = $"{lastFailLabel}: {latestFailTime:MM/dd HH:mm:ss} — {note}";
                string samplesJoined = string.Join("\n  ", failedSamples);

                string tech = Loc.T(
                    $"Event ID: 4625 (Failed Logon)\nCount in Last 24h: {failedLogonCount}\nLatest Timestamp: {latestFailTime:yyyy-MM-dd HH:mm:ss}\nRecent Samples:\n  {samplesJoined}",
                    $"事件 ID: 4625 (登录失败)\n最近24小时发生次数: {failedLogonCount} 次\n最后发生时间: {latestFailTime:yyyy-MM-dd HH:mm:ss}\n最近样本:\n  {samplesJoined}",
                    $"ID de evento: 4625 (Inicio de sesión fallido)\nVeces en últimas 24h: {failedLogonCount}\nÚltima vez: {latestFailTime:yyyy-MM-dd HH:mm:ss}\nMuestras recientes:\n  {samplesJoined}",
                    $"イベントID: 4625 (ログオン失敗)\n直近24時間の発生回数: {failedLogonCount} 回\n最終発生時刻: {latestFailTime:yyyy-MM-dd HH:mm:ss}\n直近サンプル:\n  {samplesJoined}");

                string recAction = Loc.T(
                    "Your PC may be experiencing a password brute-force attack via RDP or SMB. Check 'Windows Logs > Security' in Event Viewer to inspect the source IP address and target account name.",
                    "电脑可能正在遭受通过 RDP 或 SMB 发起的密码暴力破解攻击。请在事件查看器的“Windows 日志 > 安全”中检查来源 IP 地址与目标账户名。",
                    "Su PC podría estar sufriendo un ataque de fuerza bruta por RDP o SMB. Revise 'Registros de Windows > Seguridad' en el Visor de eventos para ver la IP de origen y la cuenta objetivo.",
                    "RDPやSMB経由でのパスワード総当たり攻撃（ブルートフォース）を受けている可能性があります。イベントビューアーの「Windows ログ > セキュリティ」で送信元IPアドレスと対象アカウント名を確認してください。");

                reports.Add(new FindingReport(
                    Key: "EVTLOG:4625_SUMMARY",
                    Category: FindingCategory.Account,
                    Severity: risk,
                    State: (DateTime.Now - latestFailTime).TotalMinutes <= 15 ? FindingState.Active : FindingState.Existing,
                    Title: title,
                    Detail: detail,
                    Target: "Security EventLog ID:4625",
                    TechnicalDetails: tech,
                    RecommendedAction: recAction));
            }
        }
        catch (UnauthorizedAccessException)
        {
            // 非管理者実行時は Security イベントログの読み取り権限がないため案内を1件出す
            reports.Add(new FindingReport(
                Key: "EVTLOG:4625_NEED_ADMIN",
                Category: FindingCategory.Account,
                Severity: RiskLevel.Low,
                State: FindingState.Existing,
                Title: Loc.T(
                    "ℹ️ [Event Log Monitor] Run as Administrator to directly monitor ID:4625 (Failed Logons)",
                    "ℹ️ [事件日志监控] 以管理员身份运行可直接监控 ID:4625 (登录失败)",
                    "ℹ️ [Monitor de Eventos] Ejecute como Administrador para monitorear ID:4625 (Fallos de sesión)",
                    "ℹ️ [イベントログ監視] 管理者として起動すると ID:4625(ログオン失敗) も直接監視できます"),
                Detail: Loc.T(
                    "Running as standard user: Local accounts & Administrators group are monitored directly via API (Reading Security event log requires Administrator privileges)",
                    "当前以普通用户权限运行：本地账户与管理员组已通过 API 直接监控（仅读取 Security 事件日志需要管理员权限）",
                    "Ejecutando como usuario estándar: Las cuentas locales y el grupo Administrators se monitorean por API (Leer el registro Security requiere permisos de Administrador)",
                    "現在は一般ユーザー権限で稼働中のため、ローカルアカウント・管理者グループはAPIで直接監視中です（Securityイベントログ読み取りのみ管理者権限が必要）"),
                Target: "Security EventLog (4625/4720/4732)",
                TechnicalDetails: Loc.T(
                    "By Windows design, reading the Security event channel (e.g. Event ID 4625 Failed Logon) directly requires Administrator privileges.\n*Note: Monitoring of local user accounts and Administrators group membership works in real time via NetAPI even with standard user privileges.",
                    "根据 Windows 安全机制，直接读取 Security 事件通道（如 ID: 4625 登录失败等）需要管理员权限。\n※注：本地用户列表及 Administrators 组成员变动的实时监控在普通用户权限下依然通过 NetAPI 正常工作。",
                    "Por diseño de Windows, leer directamente el canal de eventos Security (ej. ID 4625) requiere privilegios de Administrador.\n*Nota: El monitoreo de cuentas locales y del grupo Administrators funciona en tiempo real vía NetAPI incluso con permisos estándar.",
                    "Windows の仕様により、Security イベントチャネル (ID: 4625 ログオン失敗等) の直接読み取りには管理者権限が必要です。\n※なお、ローカルアカウント一覧および Administrators グループメンバーの増減監視は一般ユーザー権限のままでも NetAPI 経由でリアルタイム稼働しています。"),
                RecommendedAction: Loc.T(
                    "To also monitor failed logon history (ID:4625) for RDP brute-force detection, right-click AnzenSecurityWatcher.exe and select 'Run as administrator'.",
                    "如需同时监控 RDP 暴力破解等登录失败历史记录 (ID:4625)，请右键点击 AnzenSecurityWatcher.exe 并选择“以管理员身份运行”。",
                    "Si desea monitorear también el historial de inicios de sesión fallidos (ID:4625), haga clic derecho en AnzenSecurityWatcher.exe y seleccione 'Ejecutar como administrador'.",
                    "RDPブルートフォース等のログオン失敗履歴 (ID:4625) も監視したい場合は、AnzenSecurityWatcher.exe を右クリックして「管理者として実行」してください。")));
        }
        catch { }
    }
}

