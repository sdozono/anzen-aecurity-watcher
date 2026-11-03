using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace AnzenSecurityWatcher.Services;

public static class NativeMethods
{
    public const int AF_INET = 2;
    public const int AF_INET6 = 23;
    public const int TCP_TABLE_OWNER_PID_ALL = 5;
    public const int UDP_TABLE_OWNER_PID = 1;
    public const int SM_REMOTESESSION = 0x1000;
    public const uint NO_ERROR = 0;
    public const uint ERROR_INSUFFICIENT_BUFFER = 122;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        int tblClass,
        uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        int tblClass,
        uint reserved = 0);

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;

        public IPAddress LocalAddress => new(dwLocalAddr);
        public IPAddress RemoteAddress => new(dwRemoteAddr);
        public int LocalPort => (ushort)IPAddress.NetworkToHostOrder((short)dwLocalPort);
        public int RemotePort => (ushort)IPAddress.NetworkToHostOrder((short)dwRemotePort);
        public int ProcessId => (int)dwOwningPid;
        public string StateName => dwState switch
        {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => $"UNKNOWN({dwState})"
        };
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPROW_OWNER_PID
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwOwningPid;

        public IPAddress LocalAddress => new(dwLocalAddr);
        public int LocalPort => (ushort)IPAddress.NetworkToHostOrder((short)dwLocalPort);
        public int ProcessId => (int)dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucLocalAddr;
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucRemoteAddr;
        public uint dwRemoteScopeId;
        public uint dwRemotePort;
        public uint dwState;
        public uint dwOwningPid;

        public IPAddress LocalAddress => ucLocalAddr != null
            ? (dwLocalScopeId == 0 ? new IPAddress(ucLocalAddr) : new IPAddress(ucLocalAddr, dwLocalScopeId))
            : IPAddress.IPv6None;
        public IPAddress RemoteAddress => ucRemoteAddr != null
            ? (dwRemoteScopeId == 0 ? new IPAddress(ucRemoteAddr) : new IPAddress(ucRemoteAddr, dwRemoteScopeId))
            : IPAddress.IPv6None;
        public int LocalPort => (ushort)IPAddress.NetworkToHostOrder((short)dwLocalPort);
        public int RemotePort => (ushort)IPAddress.NetworkToHostOrder((short)dwRemotePort);
        public int ProcessId => (int)dwOwningPid;
        public string StateName => dwState switch
        {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => $"UNKNOWN({dwState})"
        };
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucLocalAddr;
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        public uint dwOwningPid;

        public IPAddress LocalAddress => ucLocalAddr != null
            ? (dwLocalScopeId == 0 ? new IPAddress(ucLocalAddr) : new IPAddress(ucLocalAddr, dwLocalScopeId))
            : IPAddress.IPv6None;
        public int LocalPort => (ushort)IPAddress.NetworkToHostOrder((short)dwLocalPort);
        public int ProcessId => (int)dwOwningPid;
    }

    public static List<MIB_TCPROW_OWNER_PID> GetAllTcpConnections()
    {
        var result = new List<MIB_TCPROW_OWNER_PID>();
        int bufferSize = 0;
        uint ret = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        if (bufferSize <= 0) return result;

        IntPtr tcpTablePtr = IntPtr.Zero;
        try
        {
            const int maxRetries = 5;
            int retries = 0;
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            while ((ret == ERROR_INSUFFICIENT_BUFFER || tcpTablePtr == IntPtr.Zero) && retries++ < maxRetries)
            {
                if (tcpTablePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(tcpTablePtr);
                    tcpTablePtr = IntPtr.Zero;
                }

                // 接続急増時のバッファ不足を防ぐためマージン（パディング）を付与
                int allocatedSize = bufferSize + (rowSize * 8);
                tcpTablePtr = Marshal.AllocHGlobal(allocatedSize);
                int outBufLen = allocatedSize;

                ret = GetExtendedTcpTable(tcpTablePtr, ref outBufLen, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
                if (ret == NO_ERROR)
                {
                    break;
                }

                bufferSize = outBufLen;
            }

            if (ret != NO_ERROR || tcpTablePtr == IntPtr.Zero) return result;

            int numEntries = Marshal.ReadInt32(tcpTablePtr);
            IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4);

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                result.Add(row);
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            if (tcpTablePtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }
        }
        return result;
    }

    public static List<MIB_UDPROW_OWNER_PID> GetAllUdpEndpoints()
    {
        var result = new List<MIB_UDPROW_OWNER_PID>();
        int bufferSize = 0;
        uint ret = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, UDP_TABLE_OWNER_PID);
        if (bufferSize <= 0) return result;

        IntPtr udpTablePtr = IntPtr.Zero;
        try
        {
            const int maxRetries = 5;
            int retries = 0;
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

            while ((ret == ERROR_INSUFFICIENT_BUFFER || udpTablePtr == IntPtr.Zero) && retries++ < maxRetries)
            {
                if (udpTablePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(udpTablePtr);
                    udpTablePtr = IntPtr.Zero;
                }

                // エンドポイント急増時のバッファ不足を防ぐためマージン（パディング）を付与
                int allocatedSize = bufferSize + (rowSize * 8);
                udpTablePtr = Marshal.AllocHGlobal(allocatedSize);
                int outBufLen = allocatedSize;

                ret = GetExtendedUdpTable(udpTablePtr, ref outBufLen, true, AF_INET, UDP_TABLE_OWNER_PID);
                if (ret == NO_ERROR)
                {
                    break;
                }

                bufferSize = outBufLen;
            }

            if (ret != NO_ERROR || udpTablePtr == IntPtr.Zero) return result;

            int numEntries = Marshal.ReadInt32(udpTablePtr);
            IntPtr rowPtr = IntPtr.Add(udpTablePtr, 4);

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                result.Add(row);
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            if (udpTablePtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(udpTablePtr);
            }
        }
        return result;
    }

    public static List<MIB_TCP6ROW_OWNER_PID> GetAllTcp6Connections()
    {
        var result = new List<MIB_TCP6ROW_OWNER_PID>();
        int bufferSize = 0;
        uint ret = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL);
        if (bufferSize <= 0) return result;

        IntPtr tcpTablePtr = IntPtr.Zero;
        try
        {
            const int maxRetries = 5;
            int retries = 0;
            int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();

            while ((ret == ERROR_INSUFFICIENT_BUFFER || tcpTablePtr == IntPtr.Zero) && retries++ < maxRetries)
            {
                if (tcpTablePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(tcpTablePtr);
                    tcpTablePtr = IntPtr.Zero;
                }

                // 接続急増時のバッファ不足を防ぐためマージン（パディング）を付与
                int allocatedSize = bufferSize + (rowSize * 8);
                tcpTablePtr = Marshal.AllocHGlobal(allocatedSize);
                int outBufLen = allocatedSize;

                ret = GetExtendedTcpTable(tcpTablePtr, ref outBufLen, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL);
                if (ret == NO_ERROR)
                {
                    break;
                }

                bufferSize = outBufLen;
            }

            if (ret != NO_ERROR || tcpTablePtr == IntPtr.Zero) return result;

            int numEntries = Marshal.ReadInt32(tcpTablePtr);
            IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4);

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                result.Add(row);
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        catch
        {
            // IPv6スタックが無効な環境やアンマネージド領域読み取り時の例外を安全に吸収
        }
        finally
        {
            if (tcpTablePtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }
        }
        return result;
    }

    public static List<MIB_UDP6ROW_OWNER_PID> GetAllUdp6Endpoints()
    {
        var result = new List<MIB_UDP6ROW_OWNER_PID>();
        int bufferSize = 0;
        uint ret = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, AF_INET6, UDP_TABLE_OWNER_PID);
        if (bufferSize <= 0) return result;

        IntPtr udpTablePtr = IntPtr.Zero;
        try
        {
            const int maxRetries = 5;
            int retries = 0;
            int rowSize = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();

            while ((ret == ERROR_INSUFFICIENT_BUFFER || udpTablePtr == IntPtr.Zero) && retries++ < maxRetries)
            {
                if (udpTablePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(udpTablePtr);
                    udpTablePtr = IntPtr.Zero;
                }

                // エンドポイント急増時のバッファ不足を防ぐためマージン（パディング）を付与
                int allocatedSize = bufferSize + (rowSize * 8);
                udpTablePtr = Marshal.AllocHGlobal(allocatedSize);
                int outBufLen = allocatedSize;

                ret = GetExtendedUdpTable(udpTablePtr, ref outBufLen, true, AF_INET6, UDP_TABLE_OWNER_PID);
                if (ret == NO_ERROR)
                {
                    break;
                }

                bufferSize = outBufLen;
            }

            if (ret != NO_ERROR || udpTablePtr == IntPtr.Zero) return result;

            int numEntries = Marshal.ReadInt32(udpTablePtr);
            IntPtr rowPtr = IntPtr.Add(udpTablePtr, 4);

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(rowPtr);
                result.Add(row);
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        catch
        {
            // IPv6スタックが無効な環境やアンマネージド領域読み取り時の例外を安全に吸収
        }
        finally
        {
            if (udpTablePtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(udpTablePtr);
            }
        }
        return result;
    }

    // --- WTS (Windows Terminal Services / RDP) ---
    public static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

    public enum WTS_CONNECTSTATE_CLASS
    {
        WTSActive,
        WTSConnected,
        WTSConnectQuery,
        WTSShadow,
        WTSDisconnected,
        WTSIdle,
        WTSListen,
        WTSReset,
        WTSDown,
        WTSInit
    }

    public enum WTS_INFO_CLASS
    {
        WTSUserName = 5,
        WTSWinStationName = 6,
        WTSClientName = 10,
        WTSClientAddress = 14,
        WTSClientProtocolType = 16
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WTS_SESSION_INFO
    {
        public int SessionID;
        [MarshalAs(UnmanagedType.LPStr)]
        public string pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSEnumerateSessions(
        IntPtr hServer,
        int Reserved,
        int Version,
        out IntPtr ppSessionInfo,
        out int pCount);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSQuerySessionInformation(
        IntPtr hServer,
        int sessionId,
        WTS_INFO_CLASS wtsInfoClass,
        out IntPtr ppBuffer,
        out int pBytesReturned);

    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr pMemory);

    public static bool HasActiveRdpSession(out string sessionDetails)
    {
        sessionDetails = "";
        try
        {
            if (GetSystemMetrics(SM_REMOTESESSION) != 0)
            {
                sessionDetails = Loc.T(
                    "Detected current session is a Remote Desktop connection via GetSystemMetrics(SM_REMOTESESSION)",
                    "通过 GetSystemMetrics(SM_REMOTESESSION) 检测到当前会话为远程桌面连接",
                    "Se detectó que la sesión actual es una conexión de Escritorio Remoto mediante GetSystemMetrics(SM_REMOTESESSION)",
                    "GetSystemMetrics(SM_REMOTESESSION) により現在のセッションがリモートデスクトップ接続であることを検知");
                return true;
            }

            if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, out IntPtr pSessionInfo, out int count))
            {
                try
                {
                    int dataSize = Marshal.SizeOf<WTS_SESSION_INFO>();
                    IntPtr current = pSessionInfo;
                    for (int i = 0; i < count; i++)
                    {
                        var si = Marshal.PtrToStructure<WTS_SESSION_INFO>(current);
                        current = IntPtr.Add(current, dataSize);

                        if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive ||
                            si.State == WTS_CONNECTSTATE_CLASS.WTSShadow)
                        {
                            if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, si.SessionID,
                                WTS_INFO_CLASS.WTSClientProtocolType, out IntPtr pProto, out int bytes) && bytes >= 2)
                            {
                                short proto = Marshal.ReadInt16(pProto);
                                WTSFreeMemory(pProto);
                                // proto == 2 means RDP protocol
                                if (proto == 2 || si.State == WTS_CONNECTSTATE_CLASS.WTSShadow)
                                {
                                    sessionDetails = Loc.T(
                                        $"Active RDP session detected (SessionID={si.SessionID}, Station={si.pWinStationName}, State={si.State})",
                                        $"检测到活动 RDP 会话 (SessionID={si.SessionID}, Station={si.pWinStationName}, State={si.State})",
                                        $"Sesión RDP activa detectada (SessionID={si.SessionID}, Station={si.pWinStationName}, State={si.State})",
                                        $"アクティブなRDPセッション検知 (SessionID={si.SessionID}, Station={si.pWinStationName}, State={si.State})");
                                    return true;
                                }
                            }
                        }
                    }
                }
                finally
                {
                    WTSFreeMemory(pSessionInfo);
                }
            }
        }
        catch
        {
            // Ignore WTS query errors on restricted systems
        }
        return false;
    }

    // --- User32 Window Enumeration for Screen Share Overlay Detection ---
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern int GetSystemMetrics(int nIndex);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc enumProc, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    public record WindowSnapshot(IntPtr Handle, int ProcessId, string Title, string ClassName, bool IsVisible);

    public static List<WindowSnapshot> GetTopLevelWindows()
    {
        var list = new List<WindowSnapshot>();
        try
        {
            EnumWindows((hWnd, lParam) =>
            {
                bool visible = IsWindowVisible(hWnd);
                if (!visible) return true;

                GetWindowThreadProcessId(hWnd, out uint pid);
                var titleSb = new StringBuilder(256);
                GetWindowText(hWnd, titleSb, titleSb.Capacity);

                var classSb = new StringBuilder(256);
                GetClassName(hWnd, classSb, classSb.Capacity);

                string title = titleSb.ToString();
                string cls = classSb.ToString();
                if (!string.IsNullOrWhiteSpace(title) || !string.IsNullOrWhiteSpace(cls))
                {
                    list.Add(new WindowSnapshot(hWnd, (int)pid, title, cls, visible));
                }
                return true;
            }, IntPtr.Zero);
        }
        catch
        {
            // Ignore window enumeration exceptions
        }
        return list;
    }
}
