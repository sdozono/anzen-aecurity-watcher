using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using AnzenSecurityWatcher.Models;

namespace AnzenSecurityWatcher.Services;

public class NetworkMonitorService
{
    private readonly GeoIpService _geoIpService;
    private readonly ConcurrentDictionary<int, (string Name, string Path, DateTime CachedAt)> _pidCache = new();

    // 外部通信を行うと特に注意すべきコマンド・スクリプト実行系プロセス (LOLBins)
    private static readonly HashSet<string> SuspiciousNetworkProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta",
        "rundll32", "regsvr32", "certutil", "bitsadmin", "msiexec", "scrcons"
    };

    // リモート管理・危険ポート番号
    private static readonly Dictionary<int, (string En, string Zh, string Es, string Ja)> SensitivePorts = new()
    {
        [21] = ("FTP (Unencrypted file transfer)", "FTP (未加密文件传输)", "FTP (Transferencia sin cifrar)", "FTP (非暗号化ファイル転送)"),
        [22] = ("SSH (Remote shell)", "SSH (远程 Shell)", "SSH (Shell remoto)", "SSH (リモートシェル)"),
        [23] = ("Telnet (Unencrypted remote control)", "Telnet (未加密远程控制)", "Telnet (Control remoto sin cifrar)", "Telnet (非暗号化遠隔操作)"),
        [445] = ("SMB (File sharing)", "SMB (文件共享)", "SMB (Compartición de archivos)", "SMB (ファイル共有)"),
        [1337] = ("Suspicious port (1337 / backdoor concern)", "可疑端口 (1337/后门隐患)", "Puerto sospechoso (1337/backdoor)", "不審ポート (1337/バックドア懸念)"),
        [3389] = ("RDP (Windows Remote Desktop)", "RDP (Windows 远程桌面)", "RDP (Escritorio remoto de Windows)", "RDP (Windowsリモートデスクトップ)"),
        [4444] = ("Suspicious port (4444 / reverse shell concern)", "可疑端口 (4444/反弹Shell隐患)", "Puerto sospechoso (4444/reverse shell)", "不審ポート (4444/リバースシェル懸念)"),
        [5900] = ("VNC (Screen share / remote control)", "VNC (屏幕共享/远程控制)", "VNC (Pantalla compartida/remoto)", "VNC (画面共有・遠隔操作)"),
        [5901] = ("VNC (Screen share / remote control)", "VNC (屏幕共享/远程控制)", "VNC (Pantalla compartida/remoto)", "VNC (画面共有・遠隔操作)"),
        [5938] = ("TeamViewer (Remote control)", "TeamViewer (远程控制)", "TeamViewer (Control remoto)", "TeamViewer (遠隔操作)"),
        [5985] = ("WinRM HTTP (Remote management)", "WinRM HTTP (远程管理)", "WinRM HTTP (Gestión remota)", "WinRM HTTP (遠隔管理)"),
        [5986] = ("WinRM HTTPS (Remote management)", "WinRM HTTPS (远程管理)", "WinRM HTTPS (Gestión remota)", "WinRM HTTPS (遠隔管理)"),
        [6568] = ("AnyDesk (Remote control)", "AnyDesk (远程控制)", "AnyDesk (Control remoto)", "AnyDesk (遠隔操作)"),
        [6667] = ("IRC (Botnet C2 concern)", "IRC (僵尸网络C2隐患)", "IRC (Riesgo Botnet C2)", "IRC (ボットネットC2懸念)"),
        [7070] = ("AnyDesk (Remote control)", "AnyDesk (远程控制)", "AnyDesk (Control remoto)", "AnyDesk (遠隔操作)"),
        [8080] = ("HTTP Proxy / Alt Web port", "HTTP 代理 / 备用Web端口", "Proxy HTTP / Puerto web alt.", "HTTP Proxy / 代替Webポート"),
        [31337] = ("Suspicious port (31337 / backdoor concern)", "可疑端口 (31337/后门隐患)", "Puerto sospechoso (31337/backdoor)", "不審ポート (31337/バックドア懸念)")
    };

    // UDP で特に注目すべきポート番号
    private static readonly Dictionary<int, string> SensitiveUdpPorts = new()
    {
        [69] = "TFTP",
        [161] = "SNMP",
        [162] = "SNMP Trap",
        [500] = "IKE/IPsec VPN",
        [1194] = "OpenVPN (UDP)",
        [1701] = "L2TP VPN",
        [3389] = "RDP Shortpath (UDP)",
        [3478] = "STUN/TURN (WebRTC P2P)",
        [4444] = "Suspicious UDP (4444)",
        [4500] = "IPsec NAT-T VPN",
        [5938] = "TeamViewer (UDP)",
        [6568] = "AnyDesk (UDP)",
        [7070] = "AnyDesk (UDP)",
        [51820] = "WireGuard VPN"
    };

    public GeoIpService GeoIp => _geoIpService;

    public NetworkMonitorService(GeoIpService geoIpService)
    {
        _geoIpService = geoIpService;
    }

    private readonly record struct RawTcpConnectionEntry(
        IPAddress LocalAddress,
        int LocalPort,
        IPAddress RemoteAddress,
        int RemotePort,
        string StateName,
        int ProcessId);

    private readonly record struct RawUdpEndpointEntry(
        IPAddress LocalAddress,
        int LocalPort,
        int ProcessId);

    public List<NetworkConnectionItem> ScanActiveConnections(
        bool includeLoopback = false,
        bool includeListening = false,
        bool includeUdp = true)
    {
        var rawTcp = NativeMethods.GetAllTcpConnections();
        var rawTcp6 = NativeMethods.GetAllTcp6Connections();
        var allTcp = new List<RawTcpConnectionEntry>(rawTcp.Count + rawTcp6.Count);

        foreach (var r in rawTcp)
            allTcp.Add(new RawTcpConnectionEntry(r.LocalAddress, r.LocalPort, r.RemoteAddress, r.RemotePort, r.StateName, r.ProcessId));
        foreach (var r in rawTcp6)
            allTcp.Add(new RawTcpConnectionEntry(r.LocalAddress, r.LocalPort, r.RemoteAddress, r.RemotePort, r.StateName, r.ProcessId));

        var items = new List<NetworkConnectionItem>(allTcp.Count + 64);

        foreach (var row in allTcp)
        {
            string state = row.StateName;
            if (!includeListening && state == "LISTEN")
                continue;

            string remoteIp = row.RemoteAddress.ToString();
            string localIp = row.LocalAddress.ToString();

            bool isLoopback = IPAddress.IsLoopback(row.LocalAddress) ||
                              IPAddress.IsLoopback(row.RemoteAddress) ||
                              localIp == "127.0.0.1" || localIp == "::1" ||
                              remoteIp == "127.0.0.1" || remoteIp == "::1";

            bool isUnspecified = remoteIp == "0.0.0.0" || remoteIp == "::" ||
                                 row.RemoteAddress.Equals(IPAddress.Any) ||
                                 row.RemoteAddress.Equals(IPAddress.IPv6Any);

            if (!includeLoopback && (isLoopback || isUnspecified))
                continue;

            var (procName, procPath) = ResolveProcessInfo(row.ProcessId);
            bool isWildcardRemote = IsWildcardAddress(remoteIp);
            var geo = isWildcardRemote
                ? new GeoIpInfo("LOCAL", Loc.T("Local Bind / Unspecified", "本地绑定/未指定", "Enlace local", "ローカル待受/未指定"), "📡", "Wildcard", "", true, false)
                : _geoIpService.GetOrResolve(remoteIp);

            var item = new NetworkConnectionItem
            {
                Protocol = "TCP",
                LocalAddress = localIp,
                LocalPort = row.LocalPort,
                RemoteAddress = remoteIp,
                RemotePort = row.RemotePort,
                IsWildcardEndpoint = isWildcardRemote,
                State = state,
                ProcessId = row.ProcessId,
                ProcessName = procName,
                ProcessPath = procPath,
                CountryCode = geo.CountryCode,
                CountryName = geo.CountryName,
                CountryFlag = geo.Flag,
                Organization = geo.Organization,
                City = geo.City
            };

            EvaluateRisk(item, geo);
            items.Add(item);
        }

        // #4 UDP 通信エンドポイントの取得と解析 (IPv4 + IPv6)
        if (includeUdp)
        {
            var rawUdp = NativeMethods.GetAllUdpEndpoints();
            var rawUdp6 = NativeMethods.GetAllUdp6Endpoints();
            var allUdp = new List<RawUdpEndpointEntry>(rawUdp.Count + rawUdp6.Count);

            foreach (var u in rawUdp)
                allUdp.Add(new RawUdpEndpointEntry(u.LocalAddress, u.LocalPort, u.ProcessId));
            foreach (var u in rawUdp6)
                allUdp.Add(new RawUdpEndpointEntry(u.LocalAddress, u.LocalPort, u.ProcessId));

            var seenUdpKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var u in allUdp)
            {
                string localIp = u.LocalAddress.ToString();
                bool isLoopback = IPAddress.IsLoopback(u.LocalAddress) || localIp == "127.0.0.1" || localIp == "::1";
                if (!includeLoopback && isLoopback)
                    continue;

                // 同一プロセス・同一ローカルアドレス・同一ローカルポートの重複バインド表示をまとめる
                string udpKey = $"{u.ProcessId}:{localIp}:{u.LocalPort}";
                if (!seenUdpKeys.Add(udpKey))
                    continue;

                var (procName, procPath) = ResolveProcessInfo(u.ProcessId);
                bool isSpecificBind = !IsWildcardAddress(localIp);
                var geo = isSpecificBind
                    ? _geoIpService.GetOrResolve(localIp)
                    : new GeoIpInfo("LOCAL", Loc.T("UDP Endpoint", "UDP 监听/收发", "Punto final UDP", "UDP待受/送受信"), "📡", "UDP Endpoint", "", true, false);

                var udpItem = new NetworkConnectionItem
                {
                    Protocol = "UDP",
                    LocalAddress = localIp,
                    LocalPort = u.LocalPort,
                    RemoteAddress = "*",
                    RemotePort = 0,
                    State = "UDP",
                    ProcessId = u.ProcessId,
                    ProcessName = procName,
                    ProcessPath = procPath,
                    CountryCode = geo.CountryCode,
                    CountryName = geo.CountryName,
                    CountryFlag = geo.Flag,
                    Organization = $"UDP :{u.LocalPort}",
                    City = ""
                };

                EvaluateUdpRisk(udpItem);
                items.Add(udpItem);
            }
        }

        return items
            .OrderByDescending(x => x.RiskLevel)
            .ThenBy(x => x.Protocol == "UDP" ? 1 : 0)
            .ThenBy(x => x.CountryCode == "LOCAL" || x.CountryCode == "LAN" ? 1 : 0)
            .ThenBy(x => x.CountryCode)
            .ThenBy(x => x.ProcessName)
            .ToList();
    }

    public static bool IsWildcardAddress(string addr)
        => string.IsNullOrWhiteSpace(addr) || addr == "0.0.0.0" || addr == "::" || addr == "*" || addr == "[::]";

    // 既知の CDN / 大手クラウド基盤 (組織名ベース)。CDN であることは「安全」の根拠にはしない
    private static readonly string[] KnownCdnKeywords =
    {
        "Akamai", "Cloudflare", "Fastly", "CloudFront", "Amazon", "Microsoft", "Azure",
        "Google", "Edgecast", "Limelight", "CDN77", "Verizon Digital Media", "StackPath"
    };

    public static bool IsKnownCdnOrg(string org)
        => !string.IsNullOrWhiteSpace(org) && KnownCdnKeywords.Any(k => org.Contains(k, StringComparison.OrdinalIgnoreCase));

    private static (SignatureStatus Status, string Signer) ResolveProcessSignature(NetworkConnectionItem item)
    {
        if (string.IsNullOrWhiteSpace(item.ProcessPath) || !item.ProcessPath.Contains('\\'))
            return (SignatureStatus.Unknown, "");
        var sig = SignatureHelper.CheckExtended(item.ProcessPath);
        return (sig.Status, sig.Signer);
    }

    public static void EvaluateUdpRisk(NetworkConnectionItem item)
    {
        if (ProcessMonitorService.CheckIsSelfProcess(item.ProcessId, item.ProcessName, item.ProcessPath))
        {
            item.RiskLevel = RiskLevel.Safe;
            item.Confidence = ConfidenceLevel.High;
            item.RiskReason = Loc.T(
                "🛡️ Self Process (Anzen Security Watcher)",
                "🛡️ 自身进程 (Anzen Security Watcher)",
                "🛡️ Proceso propio (Anzen Security Watcher)",
                "🛡️ 自己プロセス (Anzen Security Watcher)");
            return;
        }

        item.IsWildcardEndpoint = true; // UDP エンドポイントはリモートホストを持たない (ローカルバインド)
        var (sigStatus, signer) = ResolveProcessSignature(item);
        item.ProcessSigner = signer;
        item.ProcessSignatureStatus = sigStatus;
        bool signedTrusted = sigStatus == SignatureStatus.Signed &&
                             (PathHelper.IsWindowsLocation(item.ProcessPath) || PathHelper.IsProgramFilesLocation(item.ProcessPath));

        var reasons = new List<string>();
        var level = RiskLevel.Safe;
        var conf = ConfidenceLevel.High;

        if (SuspiciousNetworkProcesses.Contains(item.ProcessName))
        {
            level = RiskLevel.Medium;
            conf = ConfidenceLevel.Medium;
            reasons.Add(Loc.T(
                $"Command/Script process ({item.ProcessName}) opened UDP port {item.LocalPort}",
                $"命令/脚本进程 ({item.ProcessName}) 打开了 UDP 端口 {item.LocalPort}",
                $"Proceso de comando/script ({item.ProcessName}) abrió puerto UDP {item.LocalPort}",
                $"コマンド/スクリプト系プロセス ({item.ProcessName}) が UDP ポート {item.LocalPort} をオープン"));
        }

        if (SensitiveUdpPorts.TryGetValue(item.LocalPort, out string? udpDesc))
        {
            // 署名済みの標準/製品プロセスによる VPN/NAT-T 等は情報レベルに留める
            var portLevel = signedTrusted ? RiskLevel.Low : RiskLevel.Medium;
            if (level < portLevel) level = portLevel;
            reasons.Add(Loc.T(
                $"Local bind on notable UDP port ({item.LocalPort} - {udpDesc}); wildcard bind is not a remote host",
                $"本地绑定重点 UDP 端口 ({item.LocalPort} - {udpDesc})；通配符绑定不代表远程主机",
                $"Enlace local en puerto UDP notable ({item.LocalPort} - {udpDesc})",
                $"注目UDPポート ({item.LocalPort} - {udpDesc}) のローカル待受 (ワイルドカードはリモートホストではありません)"));
        }

        if (!string.IsNullOrEmpty(item.ProcessPath) && PathHelper.IsHighRiskTempLocation(item.ProcessPath))
        {
            if (level < RiskLevel.High) level = RiskLevel.High;
            reasons.Add(Loc.T(
                "Executable in Temp/Downloads folder using UDP port",
                "临时文件夹(Temp/Downloads)内的可执行文件正在使用 UDP 端口",
                "Ejecutable en carpeta Temp/Downloads usando puerto UDP",
                "一時フォルダ(Temp/Downloads)内の実行ファイルがUDPポートを使用"));
        }

        if (reasons.Count == 0)
        {
            item.RiskLevel = RiskLevel.Safe;
            item.Confidence = ConfidenceLevel.High;
            item.RiskReason = Loc.T(
                $"UDP Endpoint (Local {item.LocalAddress}:{item.LocalPort})",
                $"UDP 端点 (本地 {item.LocalAddress}:{item.LocalPort})",
                $"Punto final UDP (Local {item.LocalAddress}:{item.LocalPort})",
                $"UDP エンドポイント (Local {item.LocalAddress}:{item.LocalPort})");
        }
        else
        {
            item.RiskLevel = level;
            item.Confidence = conf;
            item.RiskReason = string.Join(" / ", reasons);
        }
    }

    public void EvaluateRisk(NetworkConnectionItem item, GeoIpInfo geo)
    {
        if (item.Protocol == "UDP")
        {
            EvaluateUdpRisk(item);
            return;
        }

        if (ProcessMonitorService.CheckIsSelfProcess(item.ProcessId, item.ProcessName, item.ProcessPath))
        {
            item.RiskLevel = RiskLevel.Safe;
            item.Confidence = ConfidenceLevel.High;
            item.RiskReason = Loc.T(
                "🛡️ Self Process (Anzen Security Watcher GeoIP lookup)",
                "🛡️ 生成此日志的自身程序 (Anzen Security Watcher GeoIP 查询)",
                "🛡️ Proceso propio (Consulta GeoIP de Anzen Security Watcher)",
                "🛡️ このログを生成した自分自身のプログラム (Anzen Security Watcher のGeoIP国名照会通信)");
            return;
        }

        // ワイルドカード / 未指定アドレスはリモートホストではない (GeoIP・外部通信判定の対象外)
        if (item.IsWildcardEndpoint || IsWildcardAddress(item.RemoteAddress))
        {
            item.IsWildcardEndpoint = true;
            item.RiskLevel = RiskLevel.Safe;
            item.Confidence = ConfidenceLevel.High;
            item.RiskReason = Loc.T(
                "Wildcard / unspecified address (local bind, not a remote host)",
                "通配符/未指定地址 (本地绑定，不是远程主机)",
                "Dirección comodín / no especificada (enlace local)",
                "ワイルドカード/未指定アドレス (ローカル待受でありリモートホストではありません)");
            return;
        }

        var (sigStatus, signer) = ResolveProcessSignature(item);
        item.ProcessSigner = signer;
        item.ProcessSignatureStatus = sigStatus;
        bool isSigned = sigStatus == SignatureStatus.Signed;
        bool isMsSigned = isSigned && SignatureHelper.IsMicrosoftSigner(signer);
        bool trustedLocation = PathHelper.IsWindowsLocation(item.ProcessPath) || PathHelper.IsProgramFilesLocation(item.ProcessPath);
        bool userWritable = PathHelper.IsUserWritableLocation(item.ProcessPath);
        bool isCdn = IsKnownCdnOrg(geo.Organization);
        item.IsKnownCdn = isCdn;

        var reasons = new List<string>();
        var level = RiskLevel.Safe;
        var conf = ConfidenceLevel.Medium;
        string countryName = GeoIpService.GetLocalizedCountryName(geo.CountryCode, geo.CountryName);

        // 評価の優先順位: 1.プロセス評判 2.署名 3.パス 4.ASN/組織 5.ドメイン 6.ポート/パターン ... 最後に国 (補助情報)

        // 1-3. プロセスの素性 (LOLBin / Temp配置 / 署名)
        if (!geo.IsPrivateOrLocal && SuspiciousNetworkProcesses.Contains(item.ProcessName))
        {
            level = isMsSigned && trustedLocation ? RiskLevel.High : RiskLevel.Critical;
            conf = ConfidenceLevel.Medium;
            reasons.Add(Loc.T(
                $"Command/Script process ({item.ProcessName}) communicating directly with external host ({countryName})",
                $"命令/脚本执行进程 ({item.ProcessName}) 正在直接与外部 ({countryName}) 通信",
                $"Proceso de comando/script ({item.ProcessName}) comunicándose con host externo ({countryName})",
                $"コマンド/スクリプト実行系プロセス ({item.ProcessName}) が外部 ({countryName}) と直接通信中"));
        }

        if (!geo.IsPrivateOrLocal && !string.IsNullOrEmpty(item.ProcessPath))
        {
            if (PathHelper.IsHighRiskTempLocation(item.ProcessPath))
            {
                // CDN宛であっても安全とは判定しない
                level = RiskLevel.High;
                conf = ConfidenceLevel.High;
                reasons.Add(Loc.T(
                    "External connection from executable in Temp/Downloads folder" + (isCdn ? " (CDN destination does not make this safe)" : ""),
                    "临时文件夹(Temp/Downloads)内的可执行文件发起外部通信" + (isCdn ? " (目标为 CDN 并不代表安全)" : ""),
                    "Conexión externa desde ejecutable en carpeta Temp/Downloads",
                    "一時フォルダ(Temp/Downloads)内の実行ファイルによる外部通信" + (isCdn ? " (通信先がCDNでも安全の根拠にはなりません)" : "")));
                if (sigStatus == SignatureStatus.Unsigned)
                    level = RiskLevel.Critical;
            }
            else if (userWritable && sigStatus == SignatureStatus.Unsigned)
            {
                if (level < RiskLevel.Medium) level = RiskLevel.Medium;
                reasons.Add(Loc.T(
                    "Unsigned executable in user-writable folder communicating externally",
                    "位于用户可写目录的未签名程序发起外部通信",
                    "Ejecutable sin firma en carpeta de usuario con conexión externa",
                    "ユーザー書き込み可能領域の未署名プログラムによる外部通信"));
            }
        }

        // 6. 注意すべきポートでの通信
        if (SensitivePorts.TryGetValue(item.RemotePort, out var remotePortDesc))
        {
            // 署名済みの信頼できる場所のプロセスによる 443/8080 等は高くしない
            var portLevel = (isSigned && trustedLocation) ? RiskLevel.Low : RiskLevel.Medium;
            if (item.RemotePort is 22 or 23 or 21 or 1337 or 4444 or 31337 or 6667)
                portLevel = (isSigned && trustedLocation) ? RiskLevel.Medium : RiskLevel.High;
            if (level < portLevel) level = portLevel;
            string pDesc = Loc.T(remotePortDesc.En, remotePortDesc.Zh, remotePortDesc.Es, remotePortDesc.Ja);
            reasons.Add(Loc.T(
                $"Sensitive port traffic (Remote:{item.RemotePort} - {pDesc})",
                $"敏感端口通信 (远程:{item.RemotePort} - {pDesc})",
                $"Tráfico en puerto sensible (Remoto:{item.RemotePort} - {pDesc})",
                $"警戒ポート通信 (Remote:{item.RemotePort} - {pDesc})"));
        }
        else if (SensitivePorts.TryGetValue(item.LocalPort, out var localPortDesc) && item.State == "ESTABLISHED")
        {
            var portLevel = (isSigned && trustedLocation) ? RiskLevel.Low : RiskLevel.Medium;
            if (level < portLevel) level = portLevel;
            string pDesc = Loc.T(localPortDesc.En, localPortDesc.Zh, localPortDesc.Es, localPortDesc.Ja);
            reasons.Add(Loc.T(
                $"Inbound connection on sensitive port (Local:{item.LocalPort} - {pDesc})",
                $"敏感端口入站连接 (本地:{item.LocalPort} - {pDesc})",
                $"Conexión entrante en puerto sensible (Local:{item.LocalPort} - {pDesc})",
                $"警戒ポート着信接続 (Local:{item.LocalPort} - {pDesc})"));
        }

        // 9. 国は補助情報のみ。単独では Informational 止まり。署名済み信頼プロセスなら無視
        if (geo.IsHighAttentionCountry && !(isSigned && trustedLocation))
        {
            if (level < RiskLevel.Low) level = RiskLevel.Low;
            reasons.Add(Loc.T(
                $"Auxiliary note: destination country {countryName} / {geo.CountryCode} (country alone carries very low weight)",
                $"辅助信息: 通信目标国家 {countryName} / {geo.CountryCode} (仅凭国家权重极低)",
                $"Nota auxiliar: país de destino {countryName} / {geo.CountryCode} (peso muy bajo)",
                $"補助情報: 通信先の国 {countryName} / {geo.CountryCode} (国のみでは重みは極めて低い)"));
        }

        if (reasons.Count == 0)
        {
            item.RiskLevel = RiskLevel.Safe;
            item.Confidence = ConfidenceLevel.High;
            if (geo.IsPrivateOrLocal)
                item.RiskReason = Loc.T("Local / LAN traffic", "本地/局域网通信", "Tráfico Local / LAN", "ローカル/LAN通信");
            else if (isCdn && isSigned && trustedLocation)
                item.RiskReason = Loc.T(
                    $"Signed process → known CDN/cloud infrastructure ({geo.Organization})",
                    $"已签名进程 → 已知 CDN/云基础设施 ({geo.Organization})",
                    $"Proceso firmado → CDN/nube conocida ({geo.Organization})",
                    $"署名済みプロセス → 既知のCDN/クラウド基盤 ({geo.Organization})");
            else
                item.RiskReason = Loc.T($"Normal external traffic ({geo.Organization})", $"正常外部通信 ({geo.Organization})", $"Tráfico externo normal ({geo.Organization})", $"通常の外部通信 ({geo.Organization})");
        }
        else
        {
            item.RiskLevel = level;
            item.Confidence = conf;
            item.RiskReason = string.Join(" / ", reasons);
        }
    }

    public (string Name, string Path) ResolveProcessInfo(int pid)
    {
        if (pid == 0) return ("System Idle", "");
        if (pid == 4) return ("System", "NT Kernel & System");

        if (_pidCache.TryGetValue(pid, out var cached) && (DateTime.Now - cached.CachedAt).TotalSeconds < 30)
        {
            return (cached.Name, cached.Path);
        }

        string name = $"PID:{pid}";
        string path = "";
        try
        {
            using var proc = Process.GetProcessById(pid);
            name = proc.ProcessName;
            try
            {
                path = proc.MainModule?.FileName ?? "";
            }
            catch
            {
                // 管理者権限プロセス等はパス取得不可の場合あり
            }
        }
        catch
        {
            // プロセスが既に終了している場合
        }

        _pidCache[pid] = (name, path, DateTime.Now);
        return (name, path);
    }
}

