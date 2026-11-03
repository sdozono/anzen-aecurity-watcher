using System.Runtime.InteropServices;
using System.Text;

namespace AnzenSecurityWatcher.Services;

/// <summary>
/// システム防御エンジン用の Win32 / NT API 定義
/// （コマンドライン取得・親プロセス取得・クリップボード・ローカルアカウント列挙）
/// </summary>
public static class NativeSecurity
{
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const int ProcessBasicInformation = 0;
    private const int ProcessCommandLineInformation = 60;
    private const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr hProcess, out long creation, out long exit, out long kernel, out long user);

    [DllImport("ntdll.dll")]
    private static extern uint NtQueryInformationProcess(IntPtr hProcess, int infoClass, IntPtr info, int infoLength, out int returnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    public record ProcessIdentity(int Pid, string ImagePath, string CommandLine, int ParentPid, DateTime CreationTime);

    // ---------------- 超高速プロセススナップショット (Toolhelp32) ----------------
    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    public record FastProcessEntry(int Pid, int ParentPid, string ExeFile);

    /// <summary>
    /// Win32 CreateToolhelp32Snapshot を用い、0.3ms 未満の超低負荷で現在の全プロセス (PID, 親PID, Exe名) を取得する。
    /// 0.3秒程度で消える瞬間ターミナル（短命プロセス）を50ms周期で捕捉するために使用する。
    /// </summary>
    public static List<FastProcessEntry> GetFastProcessSnapshot()
    {
        var list = new List<FastProcessEntry>(256);
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == IntPtr.Zero || snap == INVALID_HANDLE_VALUE)
            return list;

        try
        {
            var entry = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (Process32FirstW(snap, ref entry))
            {
                do
                {
                    int pid = (int)entry.th32ProcessID;
                    if (pid > 4)
                    {
                        list.Add(new FastProcessEntry(pid, (int)entry.th32ParentProcessID, entry.szExeFile ?? ""));
                    }
                } while (Process32NextW(snap, ref entry));
            }
        }
        catch
        {
            // Ignore snapshot errors
        }
        finally
        {
            CloseHandle(snap);
        }
        return list;
    }

    /// <summary>
    /// 親プロセスのPID・名前・コマンドラインから、人間にとって分かりやすい起動元説明を生成する。
    /// （例: svchost.exe -s Schedule → タスクスケジューラ経由、WmiPrvSE → WMI経由 など）
    /// </summary>
    public static string DescribeParentOrigin(int parentPid, string parentName, string parentCommandLine)
    {
        if (parentPid <= 0) return Loc.T("Unknown", "未知", "Desconocido", "不明");
        string cleanName = string.IsNullOrWhiteSpace(parentName) ? $"PID:{parentPid}" : parentName;
        if (cleanName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            cleanName = cleanName[..^4];

        if (cleanName.Equals("svchost", StringComparison.OrdinalIgnoreCase))
        {
            string svcName = ExtractSvchostServiceName(parentCommandLine);
            if (svcName.Equals("Schedule", StringComparison.OrdinalIgnoreCase))
                return Loc.T(
                    $"⏰ Task Scheduler (svchost/Schedule, PID:{parentPid})",
                    $"⏰ 任务计划程序 (svchost/Schedule, PID:{parentPid})",
                    $"⏰ Programador de tareas (svchost/Schedule, PID:{parentPid})",
                    $"⏰ タスクスケジューラ (svchost/Schedule, PID:{parentPid})");
            if (svcName.Equals("DcomLaunch", StringComparison.OrdinalIgnoreCase))
                return Loc.T(
                    $"🧩 COM/WMI Launch (svchost/DcomLaunch, PID:{parentPid})",
                    $"🧩 COM/WMI 自动启动 (svchost/DcomLaunch, PID:{parentPid})",
                    $"🧩 Inicio COM/WMI (svchost/DcomLaunch, PID:{parentPid})",
                    $"🧩 COM/WMI自動起動 (svchost/DcomLaunch, PID:{parentPid})");
            if (svcName.Equals("Appinfo", StringComparison.OrdinalIgnoreCase))
                return Loc.T(
                    $"🛡️ UAC Elevation (svchost/Appinfo, PID:{parentPid})",
                    $"🛡️ UAC 管理员提权 (svchost/Appinfo, PID:{parentPid})",
                    $"🛡️ Elevación UAC (svchost/Appinfo, PID:{parentPid})",
                    $"🛡️ UAC管理者昇格 (svchost/Appinfo, PID:{parentPid})");
            if (!string.IsNullOrEmpty(svcName))
                return Loc.T(
                    $"⚙️ Windows Service:{svcName} (svchost, PID:{parentPid})",
                    $"⚙️ Windows 服务:{svcName} (svchost, PID:{parentPid})",
                    $"⚙️ Servicio de Windows:{svcName} (svchost, PID:{parentPid})",
                    $"⚙️ Windowsサービス:{svcName} (svchost, PID:{parentPid})");
            return Loc.T(
                $"⚙️ Windows Service Host (svchost, PID:{parentPid})",
                $"⚙️ Windows 服务宿主 (svchost, PID:{parentPid})",
                $"⚙️ Host de servicio de Windows (svchost, PID:{parentPid})",
                $"⚙️ Windowsサービスホスト (svchost, PID:{parentPid})");
        }

        if (cleanName.Equals("WmiPrvSE", StringComparison.OrdinalIgnoreCase))
            return Loc.T(
                $"👻 WMI Provider (WmiPrvSE, PID:{parentPid})",
                $"👻 WMI 提供程序 (WmiPrvSE, PID:{parentPid})",
                $"👻 Proveedor WMI (WmiPrvSE, PID:{parentPid})",
                $"👻 WMIプロバイダ (WmiPrvSE, PID:{parentPid})");
        if (cleanName.Equals("services", StringComparison.OrdinalIgnoreCase))
            return Loc.T(
                $"⚙️ Service Control Manager (services, PID:{parentPid})",
                $"⚙️ 服务控制管理器 (services, PID:{parentPid})",
                $"⚙️ Administrador de control de servicios (services, PID:{parentPid})",
                $"⚙️ サービス制御マネージャー (services, PID:{parentPid})");
        if (cleanName.Equals("explorer", StringComparison.OrdinalIgnoreCase))
            return Loc.T(
                $"🖥️ Explorer / User Launch (explorer, PID:{parentPid})",
                $"🖥️ 资源管理器/用户启动 (explorer, PID:{parentPid})",
                $"🖥️ Explorador / Inicio de usuario (explorer, PID:{parentPid})",
                $"🖥️ エクスプローラー/ユーザー起動 (explorer, PID:{parentPid})");
        if (cleanName.Equals("taskhostw", StringComparison.OrdinalIgnoreCase))
            return Loc.T(
                $"⏰ Background Task Host (taskhostw, PID:{parentPid})",
                $"⏰ 后台任务宿主 (taskhostw, PID:{parentPid})",
                $"⏰ Host de tareas en segundo plano (taskhostw, PID:{parentPid})",
                $"⏰ バックグラウンドタスクホスト (taskhostw, PID:{parentPid})");
        if (cleanName.Equals("sihost", StringComparison.OrdinalIgnoreCase))
            return Loc.T(
                $"🖥️ Shell Infrastructure Host (sihost, PID:{parentPid})",
                $"🖥️ 外壳基础设施宿主 (sihost, PID:{parentPid})",
                $"🖥️ Host de infraestructura de shell (sihost, PID:{parentPid})",
                $"🖥️ シェルインフラホスト (sihost, PID:{parentPid})");

        if (cleanName.Equals("runonce", StringComparison.OrdinalIgnoreCase))
        {
            bool isRun6432 = parentCommandLine.Contains("Run6432", StringComparison.OrdinalIgnoreCase);
            return isRun6432
                ? Loc.T(
                    $"🚀 32-bit Autostart Launcher (runonce/Run6432, PID:{parentPid})",
                    $"🚀 32位自启动启动器 (runonce/Run6432, PID:{parentPid})",
                    $"🚀 Autoinicio de 32 bits (runonce/Run6432, PID:{parentPid})",
                    $"🚀 32bit自動起動ランチャー (runonce/Run6432, PID:{parentPid})")
                : Loc.T(
                    $"🚀 Windows RunOnce Launcher (runonce, PID:{parentPid})",
                    $"🚀 Windows RunOnce 启动器 (runonce, PID:{parentPid})",
                    $"🚀 Lanzador Windows RunOnce (runonce, PID:{parentPid})",
                    $"🚀 Windows RunOnceランチャー (runonce, PID:{parentPid})");
        }

        return $"{cleanName} (PID:{parentPid})";
    }

    private static string ExtractSvchostServiceName(string cmdLine)
    {
        if (string.IsNullOrWhiteSpace(cmdLine)) return "";
        var parts = cmdLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < parts.Length - 1; i++)
        {
            if (parts[i].Equals("-s", StringComparison.OrdinalIgnoreCase) ||
                parts[i].Equals("/s", StringComparison.OrdinalIgnoreCase))
            {
                return parts[i + 1].Trim('"', '\'');
            }
        }
        return "";
    }

    /// <summary>
    /// PROCESS_QUERY_LIMITED_INFORMATION 権限だけでプロセスのパス・コマンドライン・親PID・起動時刻を取得する。
    /// （管理者権限で動くプロセスでも、同一ユーザーであれば多くの場合取得できる）
    /// </summary>
    public static ProcessIdentity? QueryProcessIdentity(int pid)
    {
        if (pid <= 4) return null;
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            string path = "";
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            if (QueryFullProcessImageName(h, 0, sb, ref size))
                path = sb.ToString();

            string cmd = QueryCommandLine(h);
            int parent = QueryParentPid(h);
            DateTime created = DateTime.MinValue;
            if (GetProcessTimes(h, out long c, out _, out _, out _) && c > 0)
            {
                try { created = DateTime.FromFileTime(c); } catch { }
            }
            return new ProcessIdentity(pid, path, cmd, parent, created);
        }
        catch
        {
            return null;
        }
        finally
        {
            CloseHandle(h);
        }
    }

    public record ProcessChainNode(int Pid, string Name, string CommandLine, DateTime CreationTime, bool IsAlive);

    /// <summary>
    /// 指定PID（通常は新規プロセスの親）から祖先方向へ最大 maxDepth 世代のプロセスチェーンを取得する。
    /// 先頭が起点PID、以降が祖父・曾祖父…の順。PID再利用による誤連結を防ぐため、
    /// 「親の起動時刻 ≦ 子の起動時刻」を満たさない場合はそこで打ち切る。
    /// 親が既に終了している場合は (exited) ノードを追加して終了する。
    /// </summary>
    public static List<ProcessChainNode> QueryAncestorChain(
        int startPid,
        DateTime childCreationTime,
        IReadOnlyDictionary<int, string>? snapshotNames = null,
        int maxDepth = 5)
    {
        var chain = new List<ProcessChainNode>();
        var visited = new HashSet<int>();
        int pid = startPid;
        DateTime limit = childCreationTime;

        for (int depth = 0; depth < maxDepth && pid > 4 && visited.Add(pid); depth++)
        {
            var id = QueryProcessIdentity(pid);
            string snapName = "";
            snapshotNames?.TryGetValue(pid, out snapName!);

            if (id == null)
            {
                string fallback = !string.IsNullOrEmpty(snapName) ? snapName : "(exited/inaccessible)";
                chain.Add(new ProcessChainNode(pid, fallback, "", DateTime.MinValue, false));
                break;
            }

            // PID再利用チェック（親が子より後に作られていたら別プロセス）
            if (id.CreationTime > DateTime.MinValue && limit > DateTime.MinValue && id.CreationTime > limit)
            {
                chain.Add(new ProcessChainNode(pid, "(exited; PID reused)", "", DateTime.MinValue, false));
                break;
            }

            string name = !string.IsNullOrEmpty(id.ImagePath)
                ? System.IO.Path.GetFileNameWithoutExtension(id.ImagePath)
                : snapName;
            chain.Add(new ProcessChainNode(pid, name, id.CommandLine, id.CreationTime, true));

            if (id.CreationTime > DateTime.MinValue) limit = id.CreationTime;
            pid = id.ParentPid;
        }
        return chain;
    }

    /// <summary>祖先チェーンから「古い祖先 ➔ ... ➔ 親 ➔ 自分」形式の1行サマリと、コマンドライン・開始時刻付き詳細（3〜5世代）を作る。</summary>
    public static (string Summary, string Detail) FormatProcessTree(
        IReadOnlyList<ProcessChainNode> chain, string selfName, int selfPid, string selfCmd, DateTime selfCreationTime = default)
    {
        var ordered = chain.Reverse().ToList();
        var sum = new StringBuilder();
        var det = new StringBuilder();
        int indent = 0;

        for (int i = 0; i < ordered.Count; i++)
        {
            var n = ordered[i];
            int chainIdx = chain.Count - 1 - i; // 0=親, 1=祖父, 2=曾祖父...

            string genLabel = chainIdx switch
            {
                0 => Loc.T("Parent (1st Gen)", "父进程 (第1代)", "Padre (1ª Gen)", "親 (第1世代)"),
                1 => Loc.T("Grandparent (2nd Gen)", "祖父进程 (第2代)", "Abuelo (2ª Gen)", "祖父 (第2世代)"),
                2 => Loc.T("Great-grandparent (3rd Gen)", "曾祖父进程 (第3代)", "Bisabuelo (3ª Gen)", "曾祖父 (第3世代)"),
                3 => Loc.T("4th Gen Ancestor", "高祖父进程 (第4代)", "Tatarabuelo (4ª Gen)", "高祖父 (第4世代)"),
                _ => Loc.T($"Ancestor ({chainIdx + 1}th Gen)", $"祖先进程 (第{chainIdx + 1}代)", $"Ancestro ({chainIdx + 1}ª Gen)", $"祖先 (第{chainIdx + 1}世代)")
            };

            string genShort = chainIdx switch
            {
                0 => Loc.T("Parent", "父", "Padre", "親"),
                1 => Loc.T("Grandparent", "祖父", "Abuelo", "祖父"),
                2 => Loc.T("Great-gp", "曾祖父", "Bisabuelo", "曾祖父"),
                _ => Loc.T($"Anc{chainIdx + 1}", $"祖{chainIdx + 1}", $"Anc{chainIdx + 1}", $"祖{chainIdx + 1}")
            };

            if (sum.Length > 0) sum.Append(" ➔ ");
            sum.Append($"{genShort}:{n.Name}({n.Pid})");

            string timeStr = n.CreationTime > DateTime.MinValue ? $" [開始: {n.CreationTime:HH:mm:ss.fff}]" : "";
            string statusStr = n.IsAlive ? "" : " [終了済]";
            det.AppendLine($"{new string(' ', indent * 2)}└ [{genLabel}] {n.Name} (PID:{n.Pid}){statusStr}{timeStr}");
            if (!string.IsNullOrWhiteSpace(n.CommandLine))
            {
                det.AppendLine($"{new string(' ', (indent + 1) * 2)}CmdLine: {Trunc(n.CommandLine, 500)}");
            }
            indent++;
        }

        string selfShort = Loc.T("Target", "自身", "Objetivo", "対象");
        string selfLabel = Loc.T("Target (Self)", "目标进程 (自身)", "Objetivo (Propio)", "対象 (自身)");
        if (sum.Length > 0) sum.Append(" ➔ ");
        sum.Append($"{selfShort}:{selfName}({selfPid})");

        string selfTimeStr = selfCreationTime > DateTime.MinValue ? $" [開始: {selfCreationTime:HH:mm:ss.fff}]" : "";
        det.AppendLine($"{new string(' ', indent * 2)}└ [{selfLabel}] {selfName} (PID:{selfPid}){selfTimeStr}");
        if (!string.IsNullOrWhiteSpace(selfCmd))
        {
            det.AppendLine($"{new string(' ', (indent + 1) * 2)}CmdLine: {Trunc(selfCmd, 500)}");
        }

        return (sum.ToString(), det.ToString().TrimEnd());
    }

    private static string Trunc(string s, int max) => s.Length <= max ? s : s[..max] + " …";

    public static string QueryProcessImagePath(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return "";
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : "";
        }
        finally
        {
            CloseHandle(h);
        }
    }

    private static string QueryCommandLine(IntPtr h)
    {
        int len = 1024;
        for (int attempt = 0; attempt < 3; attempt++)
        {
            IntPtr buf = Marshal.AllocHGlobal(len);
            try
            {
                uint status = NtQueryInformationProcess(h, ProcessCommandLineInformation, buf, len, out int ret);
                if (status == STATUS_INFO_LENGTH_MISMATCH && ret > len)
                {
                    len = ret;
                    continue;
                }
                if (status != 0) return "";

                // 先頭に UNICODE_STRING { USHORT Length; USHORT MaxLength; PWSTR Buffer; } が入る
                ushort byteLen = (ushort)Marshal.ReadInt16(buf);
                IntPtr strPtr = Marshal.ReadIntPtr(buf, IntPtr.Size == 8 ? 8 : 4);
                if (byteLen == 0 || strPtr == IntPtr.Zero) return "";
                return Marshal.PtrToStringUni(strPtr, byteLen / 2) ?? "";
            }
            catch
            {
                return "";
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        return "";
    }

    private static int QueryParentPid(IntPtr h)
    {
        int size = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            if (NtQueryInformationProcess(h, ProcessBasicInformation, buf, size, out _) != 0) return 0;
            var pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(buf);
            return (int)pbi.InheritedFromUniqueProcessId.ToInt64();
        }
        catch
        {
            return 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    // ---------------- クリップボード ----------------
    public const int WM_CLIPBOARDUPDATE = 0x031D;
    public const int WM_DEVICECHANGE = 0x0219;

    [DllImport("user32.dll")]
    public static extern IntPtr GetOpenClipboardWindow();

    [DllImport("user32.dll")]
    public static extern IntPtr GetClipboardOwner();

    [DllImport("user32.dll")]
    public static extern uint GetClipboardSequenceNumber();

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool AddClipboardFormatListener(IntPtr hwnd);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool RemoveClipboardFormatListener(IntPtr hwnd);

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);

    public static int GetWindowPid(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero) return 0;
        GetWindowThreadProcessId(hwnd, out uint pid);
        return (int)pid;
    }

    // ---------------- ローカルアカウント (netapi32) ----------------
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(string? server, string group, int level,
        out IntPtr buf, int prefMaxLen, out int entriesRead, out int totalEntries, IntPtr resumeHandle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserEnum(string? server, int level, int filter,
        out IntPtr buf, int prefMaxLen, out int entriesRead, out int totalEntries, ref int resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buf);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LOCALGROUP_MEMBERS_INFO_3
    {
        public string lgrmi3_domainandname;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct USER_INFO_1
    {
        public string usri1_name;
        public string usri1_password;
        public int usri1_password_age;
        public int usri1_priv;
        public string usri1_home_dir;
        public string usri1_comment;
        public int usri1_flags;
        public string usri1_script_path;
    }

    public const int UF_ACCOUNTDISABLE = 0x0002;
    public const int USER_PRIV_ADMIN = 2;

    public record LocalUserInfo(string Name, bool IsDisabled, bool IsAdminPriv, int PasswordAgeDays, string Comment);

    public static List<string>? GetLocalGroupMembers(string groupName)
    {
        int ret = NetLocalGroupGetMembers(null, groupName, 3, out IntPtr buf, -1, out int read, out _, IntPtr.Zero);
        if (ret != 0) return null;
        var list = new List<string>();
        try
        {
            int sz = Marshal.SizeOf<LOCALGROUP_MEMBERS_INFO_3>();
            for (int i = 0; i < read; i++)
            {
                var m = Marshal.PtrToStructure<LOCALGROUP_MEMBERS_INFO_3>(IntPtr.Add(buf, i * sz));
                if (!string.IsNullOrWhiteSpace(m.lgrmi3_domainandname))
                    list.Add(m.lgrmi3_domainandname);
            }
        }
        finally
        {
            NetApiBufferFree(buf);
        }
        return list;
    }

    public static List<LocalUserInfo>? GetLocalUsers()
    {
        int resume = 0;
        const int FILTER_NORMAL_ACCOUNT = 0x0002;
        int ret = NetUserEnum(null, 1, FILTER_NORMAL_ACCOUNT, out IntPtr buf, -1, out int read, out _, ref resume);
        if (ret != 0 && ret != 234) return null;
        var list = new List<LocalUserInfo>();
        try
        {
            int sz = Marshal.SizeOf<USER_INFO_1>();
            for (int i = 0; i < read; i++)
            {
                var u = Marshal.PtrToStructure<USER_INFO_1>(IntPtr.Add(buf, i * sz));
                list.Add(new LocalUserInfo(
                    u.usri1_name ?? "",
                    (u.usri1_flags & UF_ACCOUNTDISABLE) != 0,
                    u.usri1_priv == USER_PRIV_ADMIN,
                    u.usri1_password_age / 86400,
                    u.usri1_comment ?? ""));
            }
        }
        finally
        {
            NetApiBufferFree(buf);
        }
        return list;
    }
}
