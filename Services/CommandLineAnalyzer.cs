using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using AnzenSecurityWatcher.Models;

namespace AnzenSecurityWatcher.Services;

/// <summary>
/// コマンドライン解析エンジン
/// PowerShell の難読化 (-enc / IEX / DownloadString)、LOLBins の悪用 (certutil / mshta / regsvr32 等)、
/// ランサムウェア前兆コマンド (vssadmin delete shadows 等)、防御無効化コマンドなどを検知する。
/// </summary>
public static class CommandLineAnalyzer
{
    public record AnalysisResult(RiskLevel Risk, List<string> Reasons, string DecodedPayload)
    {
        public bool IsSuspicious => Risk >= RiskLevel.Medium;
        public string ReasonText => string.Join(" / ", Reasons);
    }

    private record Rule(
        Regex Pattern,
        RiskLevel Risk,
        string ReasonEn,
        string ReasonZh,
        string ReasonEs,
        string ReasonJa,
        string[]? OnlyFor = null)
    {
        public string LocalizedReason => Loc.T(ReasonEn, ReasonZh, ReasonEs, ReasonJa);
    }

    private static Regex R(string pattern) => new(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly string[] PowerShellHosts = { "powershell", "pwsh", "powershell_ise" };
    private static readonly string[] ShellNames = { "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "esentutl", "copy", "xcopy", "robocopy" };

    private static readonly List<Rule> Rules = new()
    {
        // ---- PowerShell 難読化・ダウンロード実行 ----
        new(R(@"(?:^|\s)[-/](?:e|ec|en[a-z]*)\s+[A-Za-z0-9+/=]{16,}"), RiskLevel.High,
            "Base64-encoded PowerShell command (-EncodedCommand)",
            "Base64 编码的 PowerShell 命令 (-EncodedCommand)",
            "Comando PowerShell codificado en Base64 (-EncodedCommand)",
            "Base64エンコードされたPowerShellコマンド (-EncodedCommand)",
            PowerShellHosts),
        new(R(@"(?:^|\s)[-/]w(?:indowstyle)?\s+h(?:idden)?\b"), RiskLevel.Medium,
            "Hidden window execution (-WindowStyle Hidden)",
            "隐藏窗口运行 (-WindowStyle Hidden)",
            "Ejecución con ventana oculta (-WindowStyle Hidden)",
            "ウィンドウ非表示で実行 (-WindowStyle Hidden)",
            PowerShellHosts),
        new(R(@"(?:^|\s)[-/](?:ep|exec|executionpolicy)\s+(?:bypass|unrestricted)"), RiskLevel.Medium,
            "Execution policy bypass (-ExecutionPolicy Bypass)",
            "绕过执行策略 (-ExecutionPolicy Bypass)",
            "Evasión de directiva de ejecución (-ExecutionPolicy Bypass)",
            "実行ポリシーの回避 (-ExecutionPolicy Bypass)",
            PowerShellHosts),
        new(R(@"(?:^|\s)[-/]nop(?:rofile)?\b.*(?:^|\s)[-/](?:w|windowstyle)\s+h"), RiskLevel.High,
            "-NoProfile + Hidden window combination (common in attack tools)",
            "-NoProfile + 隐藏窗口组合（常见于攻击工具）",
            "Combinación -NoProfile + ventana oculta (común en herramientas de ataque)",
            "-NoProfile + 非表示実行の組み合わせ（攻撃ツールの定番）",
            PowerShellHosts),
        new(R(@"\b(?:iex|invoke-expression)\b"), RiskLevel.High,
            "Dynamic code execution (Invoke-Expression / IEX)",
            "动态执行字符串代码 (Invoke-Expression / IEX)",
            "Ejecución dinámica de código (Invoke-Expression / IEX)",
            "文字列をコードとして実行 (Invoke-Expression / IEX)"),
        new(R(@"downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b\s+http|start-bitstransfer"), RiskLevel.High,
            "Internet download operation",
            "从互联网下载内容的操作",
            "Operación de descarga desde Internet",
            "インターネットからのダウンロード処理"),
        new(R(@"frombase64string|\[convert\]::|-bxor|\[char\]\s*\d+\s*\+|\[string\]::join|-join\s*\(|\.replace\(.{1,10}\)\.replace\("), RiskLevel.Medium,
            "String obfuscation / decoding routine",
            "字符串混淆或解码操作",
            "Rutina de ofuscación o decodificación de texto",
            "文字列の難読化・復号処理"),
        new(R(@"reflection\.assembly\]::load|\.invoke\(\)|virtualalloc|createthread|add-type\s+.*dllimport"), RiskLevel.Critical,
            "In-memory code loading/execution (suspected fileless attack)",
            "内存中加载/执行代码（疑似无文件攻击）",
            "Carga/ejecución de código en memoria (sospecha de ataque sin archivos)",
            "メモリ上でのコード読み込み・実行 (ファイルレス攻撃の疑い)"),
        new(R(@"amsiutils|amsiinitfailed|amsi\.dll"), RiskLevel.Critical,
            "AMSI (Antimalware Scan Interface) bypass attempt",
            "试图绕过 AMSI（反恶意软件扫描接口）",
            "Intento de evasión de AMSI (escaneo antimalware)",
            "AMSI (マルウェア対策スキャン) の回避"),

        // ---- 防御の無効化 ----
        new(R(@"set-mppreference\s+.*-disable|add-mppreference\s+.*-exclusion"), RiskLevel.Critical,
            "Disabling Microsoft Defender or adding exclusions",
            "禁用 Microsoft Defender 或添加排除项",
            "Desactivación de Microsoft Defender o adición de exclusiones",
            "Microsoft Defender の無効化 / 除外設定の追加"),
        new(R(@"netsh\s+(?:adv)?firewall\s+.*(?:state\s+off|disable|opmode\s+disable)"), RiskLevel.Critical,
            "Disabling Windows Firewall",
            "禁用 Windows 防火墙",
            "Desactivación del Firewall de Windows",
            "ファイアウォールの無効化"),
        new(R(@"reg(?:\.exe)?\s+add\s+.*(?:disableantispyware|disablerealtimemonitoring|enablelua\s+/t\s+reg_dword\s+/d\s+0)"), RiskLevel.Critical,
            "Disabling security features via registry",
            "通过注册表禁用安全功能",
            "Desactivación de funciones de seguridad mediante el registro",
            "レジストリ経由でのセキュリティ機能無効化"),
        new(R(@"wevtutil(?:\.exe)?\s+(?:cl|clear-log)|clear-eventlog"), RiskLevel.Critical,
            "Clearing Windows event logs (anti-forensics)",
            "清除事件日志（掩盖痕迹）",
            "Borrado de registros de eventos (ocultación de rastros)",
            "イベントログの消去 (痕跡隠蔽)"),

        // ---- ランサムウェア前兆 ----
        new(R(@"vssadmin(?:\.exe)?\s+delete\s+shadows|vssadmin(?:\.exe)?\s+resize\s+shadowstorage"), RiskLevel.Critical,
            "Deleting Volume Shadow Copies — typical ransomware precursor",
            "删除卷影副本（还原点）— 勒索软件典型前兆",
            "Eliminación de copias de sombra (VSS) — precursor típico de ransomware",
            "シャドウコピー(復元ポイント)の削除 — ランサムウェアの典型的前兆"),
        new(R(@"wmic(?:\.exe)?\s+shadowcopy\s+delete|win32_shadowcopy.*delete"), RiskLevel.Critical,
            "Deleting Shadow Copies via WMI — typical ransomware precursor",
            "通过 WMI 删除卷影副本 — 勒索软件典型前兆",
            "Eliminación de copias de sombra vía WMI — precursor típico de ransomware",
            "WMI経由のシャドウコピー削除 — ランサムウェアの典型的前兆"),
        new(R(@"wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)"), RiskLevel.Critical,
            "Deleting backup catalog (wbadmin)",
            "删除备份目录 (wbadmin)",
            "Eliminación del catálogo de copias de seguridad (wbadmin)",
            "バックアップカタログの削除"),
        new(R(@"bcdedit(?:\.exe)?\s+/set\s+.*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"), RiskLevel.Critical,
            "Disabling Windows Recovery Environment (bcdedit)",
            "禁用 Windows 恢复环境 (bcdedit)",
            "Desactivación del entorno de recuperación de Windows (bcdedit)",
            "Windows回復環境の無効化"),
        new(R(@"cipher(?:\.exe)?\s+/w:"), RiskLevel.High,
            "Wiping free disk space (cipher /w)",
            "擦除可用磁盘空间 (cipher /w)",
            "Borrado del espacio libre en disco (cipher /w)",
            "空き領域の完全消去 (cipher /w)"),

        // ---- LOLBins の悪用 ----
        new(R(@"certutil(?:\.exe)?\s+.*(?:-urlcache|-verifyctl|-decode|-decodehex)"), RiskLevel.High,
            "File download / decoding via certutil (LOLBin abuse)",
            "使用 certutil 下载或解码文件（LOLBin 滥用）",
            "Descarga / decodificación mediante certutil (abuso de LOLBin)",
            "certutil によるダウンロード / デコード (LOLBin悪用)"),
        new(R(@"bitsadmin(?:\.exe)?\s+.*(?:/transfer|/addfile|/setnotifycmdline)"), RiskLevel.High,
            "File transfer / command execution via bitsadmin",
            "使用 bitsadmin 传输文件或执行命令",
            "Transferencia de archivos / ejecución mediante bitsadmin",
            "bitsadmin によるファイル転送 / コマンド実行"),
        new(R(@"mshta(?:\.exe)?\s+.*(?:https?://|javascript:|vbscript:)"), RiskLevel.Critical,
            "Remote script execution via mshta",
            "使用 mshta 执行远程脚本",
            "Ejecución de script remoto mediante mshta",
            "mshta によるリモートスクリプト実行"),
        new(R(@"regsvr32(?:\.exe)?\s+.*/i:\s*https?://|regsvr32(?:\.exe)?\s+.*scrobj\.dll"), RiskLevel.Critical,
            "Remote scriptlet execution via regsvr32 (Squiblydoo)",
            "使用 regsvr32 执行远程脚本 (Squiblydoo)",
            "Ejecución de script remoto mediante regsvr32 (Squiblydoo)",
            "regsvr32 によるリモートスクリプト実行 (Squiblydoo)"),
        new(R(@"rundll32(?:\.exe)?\s+.*(?:javascript:|vbscript:|url\.dll,.*fileprotocolhandler|shell32\.dll,shellexec_rundll|advpack\.dll,.*launchinf|pcwutl\.dll)"), RiskLevel.High,
            "Suspicious indirect execution via rundll32",
            "通过 rundll32 进行可疑调用执行",
            "Ejecución indirecta sospechosa mediante rundll32",
            "rundll32 経由の不審な実行"),
        new(R(@"rundll32(?:\.exe)?\s+[""']?[a-z]:\\(?:users|programdata|windows\\temp)\\[^,]+\.(?:dll|dat|tmp|png|jpg|txt)"), RiskLevel.High,
            "rundll32 loading DLL/file from user-writable folder",
            "rundll32 正在加载用户目录中的 DLL/文件",
            "rundll32 cargando DLL/archivo desde carpeta de usuario",
            "rundll32 がユーザー領域のDLLを読み込み"),
        new(R(@"msiexec(?:\.exe)?\s+.*/q.*https?://|msiexec(?:\.exe)?\s+.*https?://.*/q"), RiskLevel.High,
            "Silent remote package installation via msiexec",
            "使用 msiexec 静默安装远程软件包",
            "Instalación silenciosa de paquete remoto mediante msiexec",
            "msiexec によるリモートパッケージのサイレントインストール"),
        new(R(@"wmic(?:\.exe)?\s+.*process\s+call\s+create"), RiskLevel.High,
            "Process creation via WMIC",
            "通过 WMIC 创建进程",
            "Creación de procesos mediante WMIC",
            "WMIC によるプロセス生成"),
        new(R(@"wmic(?:\.exe)?\s+.*/node:"), RiskLevel.High,
            "Remote host operation via WMIC (/node:)",
            "通过 WMIC 操作远程主机 (/node:)",
            "Operación de host remoto mediante WMIC (/node:)",
            "WMIC によるリモートホスト操作"),
        new(R(@"(?:^|\\|\s)(?:cscript|wscript)(?:\.exe)?\s+.*\\(?:temp|downloads|appdata|users\\public)\\"), RiskLevel.High,
            "Executing script located in Temp/Downloads/AppData folder",
            "执行位于临时/下载/AppData 文件夹中的脚本",
            "Ejecución de script ubicado en carpeta Temp/Downloads/AppData",
            "一時フォルダ内スクリプトの実行"),
        new(R(@"(?:curl|wget)(?:\.exe)?\s+.*https?://.*\s-o\s"), RiskLevel.Medium,
            "Downloading and saving file via curl/wget",
            "使用 curl/wget 下载并保存文件",
            "Descarga y guardado de archivo mediante curl/wget",
            "curl/wget でファイルをダウンロード保存"),
        new(R(@"forfiles(?:\.exe)?\s+.*/c\s|pcalua(?:\.exe)?\s+.*-a\s|scriptrunner(?:\.exe)?\s+-appvscript"), RiskLevel.Medium,
            "Indirect command execution via LOLBin",
            "利用系统工具 (LOLBin) 间接执行命令",
            "Ejecución indirecta de comandos mediante LOLBin",
            "間接実行系 LOLBin の利用"),

        // ---- 永続化・権限変更 ----
        new(R(@"schtasks(?:\.exe)?\s+/create"), RiskLevel.Medium,
            "Creating a new scheduled task (schtasks /create)",
            "创建新的计划任务 (schtasks /create)",
            "Creación de nueva tarea programada (schtasks /create)",
            "スケジュールタスクの新規作成"),
        new(R(@"schtasks(?:\.exe)?\s+/create.*(?:/ru\s+system|/sc\s+(?:minute|onlogon|onstart))"), RiskLevel.High,
            "Creating SYSTEM / high-frequency / logon scheduled task",
            "创建 SYSTEM 权限 / 高频 / 登录时运行的计划任务",
            "Creación de tarea programada con permisos SYSTEM / alta frecuencia / inicio de sesión",
            "SYSTEM権限 / 高頻度 / ログオン時タスクの作成"),
        new(R(@"reg(?:\.exe)?\s+add\s+.*\\(?:currentversion\\run|currentversion\\runonce|winlogon|image file execution options)"), RiskLevel.High,
            "Writing to autostart registry key (Run / Winlogon / IFEO)",
            "写入自启动注册表项 (Run / Winlogon / IFEO)",
            "Escritura en clave de registro de autoinicio (Run / Winlogon / IFEO)",
            "自動起動レジストリ (Run / Winlogon / IFEO) への書き込み"),
        new(R(@"sc(?:\.exe)?\s+(?:create|config)\s+.*binpath\s*="), RiskLevel.High,
            "Creating service or modifying service binary path",
            "创建服务或修改服务可执行路径",
            "Creación de servicio o modificación de ruta binaria",
            "サービスの作成 / 実行パス変更"),
        new(R(@"net1?(?:\.exe)?\s+user\s+\S+\s+\S*\s*/add"), RiskLevel.Critical,
            "Creating a new local user account (net user /add)",
            "创建新的本地用户账户 (net user /add)",
            "Creación de nueva cuenta de usuario local (net user /add)",
            "ローカルユーザーアカウントの新規作成"),
        new(R(@"net1?(?:\.exe)?\s+localgroup\s+(?:administrators|remote desktop users)\s+\S+\s+/add"), RiskLevel.Critical,
            "Adding user to Administrators / Remote Desktop Users group",
            "将用户添加到管理员或远程桌面用户组",
            "Adición de usuario al grupo Administradores / Usuarios de escritorio remoto",
            "管理者 / リモートデスクトップグループへのユーザー追加"),
        new(R(@"(?:fDenyTSConnections\s+/t\s+reg_dword\s+/d\s+0)|enable-psremoting|winrm\s+quickconfig"), RiskLevel.High,
            "Enabling remote access (RDP / WinRM)",
            "启用远程访问 (RDP / WinRM)",
            "Activación de acceso remoto (RDP / WinRM)",
            "リモートアクセス (RDP / WinRM) の有効化"),

        // ---- 情報窃取 ----
        new(R(@"sekurlsa|mimikatz|lsadump|procdump.*lsass|comsvcs\.dll.*minidump|rundll32.*comsvcs"), RiskLevel.Critical,
            "Suspected credential dumping (Mimikatz / LSASS memory dump)",
            "疑似凭据转储（Mimikatz / LSASS 内存抓取）",
            "Sospecha de volcado de credenciales (Mimikatz / memoria LSASS)",
            "認証情報ダンプ (Mimikatz / LSASS メモリ取得) の疑い"),
        new(R(@"reg(?:\.exe)?\s+save\s+hklm\\(?:sam|system|security)"), RiskLevel.Critical,
            "Saving SAM / SYSTEM registry hives (password hash extraction)",
            "导出 SAM / SYSTEM 注册表配置单元（窃取密码哈希）",
            "Guardado de ramas SAM / SYSTEM del registro (extracción de hashes)",
            "SAM / SYSTEM ハイブの保存 (パスワードハッシュ窃取)"),
        new(R(@"vaultcmd|cmdkey\s+/list|\\login data|\\cookies|\\local state"), RiskLevel.High,
            "Accessing saved credentials or browser password stores",
            "访问已保存的凭据或浏览器密码库",
            "Acceso a credenciales guardadas o contraseñas del navegador",
            "保存済み資格情報・ブラウザパスワードへのアクセス",
            ShellNames),

        // ---- 難読化された cmd ----
        new(R(@"cmd(?:\.exe)?\s+/[cvk].*(?:\^.*){4,}"), RiskLevel.Medium,
            "Caret (^) command obfuscation in cmd.exe",
            "使用插入符 (^) 混淆 cmd 命令",
            "Ofuscación de comandos cmd mediante acento circunflejo (^)",
            "キャレット(^)による cmd 難読化"),
        new(R(@"cmd(?:\.exe)?\s+/[cvk].*%[a-z]+:~\d+,\d+%"), RiskLevel.High,
            "Environment variable substring obfuscation in cmd.exe",
            "使用环境变量子字符串切片混淆 cmd 命令",
            "Ofuscación de cmd mediante subcadenas de variables de entorno",
            "環境変数部分文字列による cmd 難読化"),
    };

    private static readonly HashSet<string> ShellProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
        "certutil", "bitsadmin", "wmic", "msiexec", "schtasks", "reg", "net", "net1", "sc", "bash", "wsl"
    };

    /// <summary>Office / ブラウザ / PDF リーダーなど、通常シェルを直接起動しない親プロセス</summary>
    private static readonly HashSet<string> DocumentApps = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword", "excel", "powerpnt", "outlook", "onenote", "mspub", "msaccess", "visio",
        "acrord32", "acrobat", "foxitreader", "foxitpdfreader", "sumatrapdf",
        "wordpad", "hwp", "eqnedt32", "teams", "ms-teams", "thunderbird"
    };

    private static readonly Regex Base64Arg = R(@"(?:^|\s)[-/](?:e|ec|en[a-z]*)\s+([A-Za-z0-9+/=]{16,})");
    private static readonly Regex LongBase64 = R(@"[A-Za-z0-9+/]{120,}={0,2}");
    private static readonly Regex UrlPattern = R(@"https?://[^\s'""]+");
    private static readonly Regex RawIpUrl = R(@"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}");

    public static AnalysisResult Analyze(string commandLine, string processName = "", string parentProcessName = "")
    {
        var reasons = new List<string>();
        var risk = RiskLevel.Safe;
        string decoded = "";

        if (string.IsNullOrWhiteSpace(commandLine))
            return new AnalysisResult(RiskLevel.Safe, reasons, "");

        string proc = Path.GetFileNameWithoutExtension(processName ?? "").ToLowerInvariant();
        if (string.IsNullOrEmpty(proc))
            proc = Path.GetFileNameWithoutExtension(PathHelper.ExtractExecutablePath(commandLine)).ToLowerInvariant();

        // Base64 エンコードコマンドを復号して、中身も同じルールで再評価する
        string analysisTarget = commandLine;
        var m = Base64Arg.Match(commandLine);
        if (m.Success && PowerShellHosts.Contains(proc))
        {
            decoded = TryDecodePowerShellBase64(m.Groups[1].Value);
            if (!string.IsNullOrEmpty(decoded))
                analysisTarget = commandLine + " " + decoded;
        }

        bool matchedDownloadOrRemote = false;
        foreach (var rule in Rules)
        {
            if (rule.OnlyFor != null && !rule.OnlyFor.Contains(proc)) continue;
            if (rule.Pattern.IsMatch(analysisTarget))
            {
                if (rule.Risk > risk) risk = rule.Risk;
                string rText = rule.LocalizedReason;
                if (!reasons.Contains(rText)) reasons.Add(rText);
                if (rule.ReasonEn.Contains("download", StringComparison.OrdinalIgnoreCase) ||
                    rule.ReasonEn.Contains("Remote", StringComparison.OrdinalIgnoreCase))
                {
                    matchedDownloadOrRemote = true;
                }
            }
        }

        // シェル系プロセスに長い Base64 塊が含まれている
        if (ShellProcesses.Contains(proc) && LongBase64.IsMatch(commandLine) && !reasons.Any(r => r.Contains("Base64")))
        {
            if (risk < RiskLevel.Medium) risk = RiskLevel.Medium;
            reasons.Add(Loc.T(
                "Command contains long Base64 string (suspected embedded payload)",
                "命令包含长 Base64 字符串（疑似嵌入载荷）",
                "El comando contiene una cadena Base64 larga (sospecha de carga oculta)",
                "長いBase64文字列を含むコマンド (埋め込みペイロードの疑い)"));
        }

        // シェル系プロセスが URL を引数に持つ
        if (ShellProcesses.Contains(proc) && UrlPattern.IsMatch(analysisTarget))
        {
            if (RawIpUrl.IsMatch(analysisTarget))
            {
                if (risk < RiskLevel.High) risk = RiskLevel.High;
                reasons.Add(Loc.T(
                    "Accessing URL with raw IP address",
                    "访问直接使用 IP 地址的 URL",
                    "Acceso a URL con dirección IP directa",
                    "IPアドレス直書きのURLへアクセス"));
            }
            else if (!matchedDownloadOrRemote)
            {
                if (risk < RiskLevel.Medium) risk = RiskLevel.Medium;
                reasons.Add(Loc.T(
                    "Command/script process arguments contain a URL",
                    "命令/脚本进程的参数中包含 URL",
                    "Los argumentos del proceso de comando/script contienen una URL",
                    "コマンド/スクリプト実行系プロセスの引数にURLを含む"));
            }
        }

        // 親子関係: Office / PDF / メーラーからシェルが起動された
        string parent = Path.GetFileNameWithoutExtension(parentProcessName ?? "").ToLowerInvariant();
        if (!string.IsNullOrEmpty(parent) && DocumentApps.Contains(parent) && ShellProcesses.Contains(proc))
        {
            if (risk < RiskLevel.High) risk = RiskLevel.High;
            reasons.Add(Loc.T(
                $"Shell ({processName}) spawned by document app ({parentProcessName}) — typical macro/exploit pattern",
                $"文档类应用 ({parentProcessName}) 启动了命令行外壳 ({processName}) — 宏病毒/漏洞利用典型特征",
                $"Shell ({processName}) iniciado desde aplicación de documentos ({parentProcessName}) — patrón típico de macro/exploit",
                $"文書系アプリ ({parentProcessName}) からシェル ({processName}) が起動 — マクロ/脆弱性悪用の典型パターン"));
        }

        return new AnalysisResult(risk, reasons, decoded);
    }

    public static string TryDecodePowerShellBase64(string b64)
    {
        try
        {
            string s = b64.Trim();
            int pad = s.Length % 4;
            if (pad > 0) s += new string('=', 4 - pad);
            byte[] bytes = Convert.FromBase64String(s);
            // PowerShell の -EncodedCommand は UTF-16LE
            string text = Encoding.Unicode.GetString(bytes);
            if (text.Count(c => c < 0x20 && c != '\r' && c != '\n' && c != '\t') > text.Length / 10)
                text = Encoding.UTF8.GetString(bytes);
            text = text.Replace("\0", "");
            return text.Length > 600 ? text[..600] + Loc.T(" ...(truncated)", " …(已截断)", " ...(truncado)", " …(省略)") : text;
        }
        catch
        {
            return "";
        }
    }

    /// <summary>表示用にコマンドラインを短縮する</summary>
    public static string Shorten(string cmd, int max = 260)
        => string.IsNullOrEmpty(cmd) ? "" : (cmd.Length <= max ? cmd : cmd[..max] + " …");

    private static readonly Regex TokenParamPattern = new(
        @"(?i)(?<prefix>--?(?:token|access[-_]?token|auth[-_]?token|api[-_]?key|secret|client[-_]?secret|password|passwd|pwd)|/(?:token|secret|password|pwd|apikey)|(?:token|access_token|auth_token|api_key|secret|password|pwd)\s*[:=])(?<delim>\s*[:= ]\s*)(?<quote>[""']?)(?<val>[^\s""'\r\n]+)(?<quote2>[""']?)",
        RegexOptions.Compiled);

    private static readonly Regex BearerPattern = new(
        @"(?i)(bearer\s+)([""']?)([A-Za-z0-9\-_\.=]+)([""']?)",
        RegexOptions.Compiled);

    private static readonly Regex KnownTokensPattern = new(
        @"(?i)\b(gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9\-]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-+/.=]{10,})\b",
        RegexOptions.Compiled);

    /// <summary>
    /// コマンドライン引数に含まれるトークン、APIキー、シークレット、パスワード等の機密情報を自動で伏せ字化（マスク）する。
    /// ログ共有時や外部AIへの送信時の機密情報漏洩を防止する。
    /// </summary>
    public static string MaskSensitiveArguments(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return "";

        string result = commandLine;

        // 1. パラメータ指定型 (例: --token secret123, -password "mypass", api_key=xyz)
        result = TokenParamPattern.Replace(result, m =>
        {
            string prefix = m.Groups["prefix"].Value;
            string delim = m.Groups["delim"].Value;
            string quote = m.Groups["quote"].Value;
            string val = m.Groups["val"].Value;
            string quote2 = m.Groups["quote2"].Value;

            if (val.Contains("***") || val.Contains("[REDACTED")) return m.Value;
            if (val.Length <= 2) return m.Value;

            return $"{prefix}{delim}{quote}***MASKED***{quote2}";
        });

        // 2. Bearer トークン (例: Bearer eyJ...)
        result = BearerPattern.Replace(result, m =>
        {
            string prefix = m.Groups[1].Value;
            string quote1 = m.Groups[2].Value;
            string val = m.Groups[3].Value;
            string quote2 = m.Groups[4].Value;
            if (val.Contains("***") || val.Contains("[REDACTED")) return m.Value;
            return $"{prefix}{quote1}***MASKED***{quote2}";
        });

        // 3. 既知のトークン形式（GitHub PAT, Slack, AWS AccessKey, JWT等）
        result = KnownTokensPattern.Replace(result, m =>
        {
            string val = m.Value;
            if (val.Contains("***")) return val;
            if (val.StartsWith("AKIA", StringComparison.OrdinalIgnoreCase))
                return val[..4] + "************";
            if (val.StartsWith("gh", StringComparison.OrdinalIgnoreCase))
                return val[..4] + "********************";
            if (val.StartsWith("xox", StringComparison.OrdinalIgnoreCase))
                return val[..4] + "********************";
            return "***MASKED_JWT***";
        });

        return result;
    }
}
