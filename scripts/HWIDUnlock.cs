// HWIDUnlock.cs —— 单文件卡密服务端接管器
//   自动提权 → 劫持 111.229.48.214 到本机 → 起 TCP/UDP 假服务器（多端口）
//   → 自动拉起同目录的 HWIDMaster-0902.exe → 抓包 + 按模式回包 → 退出时清理
// 用 .NET Framework csc 编译（Windows 自带），无第三方依赖。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

static class HWIDUnlock
{
    // ---- UI 自动化（外部操作它的窗口：填卡密 → 启用按钮 → 点登录 → 读弹窗）
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern bool EnumWindows(EnumProc cb, IntPtr p);
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern bool IsWindowEnabled(IntPtr h);
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern bool EnableWindow(IntPtr h, bool enable);
    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr wp, string lp);
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern IntPtr SendMessageA(IntPtr h, uint msg, IntPtr wp, IntPtr lp);
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern bool IsWindowVisible(IntPtr h);
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern bool GetWindowRect(IntPtr h, out RECT r);
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern bool PostMessageW(IntPtr h, uint msg, IntPtr wp, IntPtr lp);

    public struct RECT { public int L, T, R, B; }
    public delegate bool EnumProc(IntPtr h, IntPtr p);

    const uint BM_CLICK = 0x00F5;
    const uint WM_SETTEXT = 0x000C;

    static string ClsOf(IntPtr h) { var sb = new StringBuilder(256); GetClassNameW(h, sb, 256); return sb.ToString(); }
    static string TxtOf(IntPtr h) { var sb = new StringBuilder(512); GetWindowTextW(h, sb, 512); return sb.ToString(); }

    static void UiAutomate(int pid, string cardKey)
    {
        Log("=== UI 自动化开始（进程 " + pid + "）===");
        for (int round = 1; round <= 3; round++)
        {
            Thread.Sleep(1500);
            var tops = new List<IntPtr>();
            EnumWindows(delegate (IntPtr h, IntPtr p)
            {
                uint op; GetWindowThreadProcessId(h, out op);
                if (op == (uint)pid && IsWindowVisible(h)) tops.Add(h);
                return true;
            }, IntPtr.Zero);

            Log("第 " + round + " 轮：发现可见顶层窗口 " + tops.Count + " 个");
            foreach (IntPtr top in tops)
                Log("  顶层 [" + ClsOf(top) + "] 标题='" + TxtOf(top) + "'");

            var edits = new List<IntPtr>();
            var buttons = new List<IntPtr>();
            var others = new List<IntPtr>();
            foreach (IntPtr top in tops)
            {
                EnumChildWindows(top, delegate (IntPtr c, IntPtr p)
                {
                    string cls = ClsOf(c);
                    if (cls.StartsWith("Edit")) edits.Add(c);
                    else if (cls.StartsWith("Button")) buttons.Add(c);
                    else others.Add(c);
                    return true;
                }, IntPtr.Zero);
            }
            Log("  子控件：Edit " + edits.Count + " 个, Button " + buttons.Count + " 个, 其它 " + others.Count + " 个");

            foreach (IntPtr e in edits)
                Log("    Edit  '" + TxtOf(e) + "' en=" + IsWindowEnabled(e));
            foreach (IntPtr b in buttons)
            {
                RECT r; GetWindowRect(b, out r);
                Log("    Button '" + TxtOf(b) + "' en=" + IsWindowEnabled(b)
                    + " rect=" + (r.R - r.L) + "x" + (r.B - r.T));
            }

            // 1) 填卡密
            if (edits.Count > 0)
            {
                foreach (IntPtr e in edits)
                {
                    SendMessageW(e, WM_SETTEXT, IntPtr.Zero, cardKey);
                    Log("    → 已把卡密写入 Edit: " + cardKey);
                }
            }
            else Log("    [!] 没找到输入框");

            // 2) 启用并点击按钮
            if (buttons.Count > 0)
            {
                IntPtr target = IntPtr.Zero;
                int best = -1;
                foreach (IntPtr b in buttons)
                {
                    string t = TxtOf(b);
                    RECT r; GetWindowRect(b, out r);
                    int area = (r.R - r.L) * (r.B - r.T);
                    bool looksLogin = t.Contains("登") || t.Contains("录") || t.ToLower().Contains("login");
                    if (looksLogin) { target = b; Log("    选中按钮（文字含'登/录'）: '" + t + "'"); break; }
                    if (area > best) { best = area; target = b; }
                }
                foreach (IntPtr b in buttons)
                {
                    if (!IsWindowEnabled(b) && EnableWindow(b, true))
                        Log("    → 已强制启用按钮 '" + TxtOf(b) + "'");
                }
                if (target != IntPtr.Zero)
                {
                    Log("    → 发送 BM_CLICK 到 '" + TxtOf(target) + "'");
                    SendMessageA(target, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
                    Thread.Sleep(1200);
                }
            }
            else Log("    [!] 没找到按钮");

            // 3) 读弹窗
            var dialogs = new List<string>();
            EnumWindows(delegate (IntPtr h, IntPtr p)
            {
                uint op; GetWindowThreadProcessId(h, out op);
                if (op == (uint)pid && IsWindowVisible(h))
                {
                    string cls = ClsOf(h);
                    if (cls == "#32770" || cls.StartsWith("Window"))
                    {
                        var kids = new List<string>();
                        EnumChildWindows(h, delegate (IntPtr c, IntPtr p2)
                        {
                            string t = TxtOf(c);
                            if (t.Length > 0) kids.Add(t);
                            return true;
                        }, IntPtr.Zero);
                        if (kids.Count > 0) dialogs.Add("[" + cls + "] " + string.Join(" | ", kids.ToArray()));
                    }
                }
                return true;
            }, IntPtr.Zero);
            foreach (string d in dialogs) Log("  ★ 弹窗内容: " + d);
        }
        Log("=== UI 自动化结束 ===");
    }

    // ---- 全内存转储（写 app.dmp + gzip 成 app.dmp.gz，方便发给分析方）
    [System.Runtime.InteropServices.DllImport("dbghelp.dll", SetLastError = true)]
    static extern bool MiniDumpWriteDump(IntPtr hProcess, int processId, IntPtr hFile,
        int dumpType, IntPtr exceptionParam, IntPtr userStreamParam, IntPtr callbackParam);

    const int MiniDumpWithFullMemory = 0x2;
    const int MiniDumpWithHandleData = 0x4;
    const int MiniDumpWithFullMemoryInfo = 0x8;
    const int MiniDumpWithThreadInfo = 0x1000;

    static string OutDir = "";

    static void DumpChild(int pid)
    {
        string dmp = Path.Combine(OutDir, "app.dmp");
        string gz = Path.Combine(OutDir, "app.dmp.gz");
        try
        {
            IntPtr hp = IntPtr.Zero;
            try { hp = Process.GetProcessById(pid).Handle; } catch { }
            if (hp == IntPtr.Zero) { Log("[!] 拿不到进程句柄，跳过转储"); return; }
            IntPtr hf = CreateFileW(dmp, 0x40000000, 0, IntPtr.Zero, 2, 0x80, IntPtr.Zero);
            if (hf == IntPtr.Zero || hf.ToInt64() == -1) { Log("[!] 建 dump 文件失败"); return; }
            Log("正在转储目标进程内存 → " + dmp + " ...");
            bool ok = MiniDumpWriteDump(hp, pid, hf, MiniDumpWithFullMemory | MiniDumpWithHandleData
                | MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            CloseHandle(hf);
            if (!ok) { Log("[!] MiniDumpWriteDump 失败 err=" + System.Runtime.InteropServices.Marshal.GetLastWin32Error()); return; }
            long sz = new FileInfo(dmp).Length;
            Log("转储完成: " + (sz / 1048576) + " MB → 压缩中...");
            using (var inFs = File.OpenRead(dmp))
            using (var outFs = File.Create(gz))
            using (var gzs = new System.IO.Compression.GZipStream(outFs, System.IO.Compression.CompressionMode.Compress))
                inFs.CopyTo(gzs);
            Log("已压缩: " + gz + "  (" + (new FileInfo(gz).Length / 1048576) + " MB)");
            try { File.Delete(dmp); Log("已删除未压缩的 app.dmp（保留 .gz）"); } catch { }
            Log(">>> 把 app.dmp.gz 发回给分析方即可 <<<");
        }
        catch (Exception e) { Log("[!] 转储异常: " + e.Message); }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    // ---- 内嵌载荷：单文件模式下，把原程序从自身资源释放到临时目录再拉起
    const string PAYLOAD_RES = "PAYLOAD";

    static string ExtractPayload()
    {
        try
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            Stream st = asm.GetManifestResourceStream(PAYLOAD_RES);
            if (st == null) return null;
            string dir = Path.Combine(Path.GetTempPath(), "HWIDMaster_payload");
            Directory.CreateDirectory(dir);
            string f = Path.Combine(dir, "HWIDMaster-0902.exe");
            long want = st.Length;
            if (File.Exists(f) && new FileInfo(f).Length == want) { Log("内嵌载荷已存在，直接复用: " + f); return f; }
            Log("正在释放内嵌原程序（" + (want / 1048576) + " MB）...");
            using (var fs = new FileStream(f, FileMode.Create, FileAccess.Write))
            {
                byte[] buf = new byte[1 << 16];
                int n, done = 0;
                while ((n = st.Read(buf, 0, buf.Length)) > 0)
                {
                    fs.Write(buf, 0, n);
                    done += n;
                }
            }
            Log("已释放到: " + f);
            return f;
        }
        catch (Exception e)
        {
            Log("[!] 释放内嵌载荷失败: " + e.Message);
            return null;
        }
    }

    // ---- 枚举系统 TCP 连接（用来动态发现"它连的哪个端口"）
    [System.Runtime.InteropServices.DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder,
        int ulAf, int tableClass, uint reserved);

    const int AF_INET = 2;
    const int TCP_TABLE_OWNER_PID_ALL = 5;

    public class ConnRow
    {
        public int Pid;
        public string RemoteIp;
        public int RemotePort;
        public int State;
        public override string ToString()
        {
            return RemoteIp + ":" + RemotePort + " 状态=" + StateName(State);
        }
        public static string StateName(int st)
        {
            switch (st)
            {
                case 1: return "ESTABLISHED";
                case 2: return "SYN_SENT";
                case 3: return "SYN_RCVD";
                case 4: return "FIN_WAIT1";
                case 5: return "FIN_WAIT2";
                case 6: return "TIME_WAIT";
                case 7: return "CLOSE";
                case 8: return "CLOSE_WAIT";
                case 9: return "LAST_ACK";
                case 10: return "LISTEN";
                case 11: return "CLOSING";
                default: return st.ToString();
            }
        }
    }

    static List<ConnRow> SniffAllConns()
    {
        var res = new List<ConnRow>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 0) return res;
        IntPtr buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                return res;
            int rows = System.Runtime.InteropServices.Marshal.ReadInt32(buf);
            for (int i = 0; i < rows; i++)
            {
                IntPtr p = new IntPtr(buf.ToInt64() + 4 + i * 24);
                uint state = (uint)System.Runtime.InteropServices.Marshal.ReadInt32(p, 0);
                uint remote = (uint)System.Runtime.InteropServices.Marshal.ReadInt32(p, 12);
                uint rportRaw = (uint)System.Runtime.InteropServices.Marshal.ReadInt32(p, 16);
                int pid = System.Runtime.InteropServices.Marshal.ReadInt32(p, 20);
                int rport = ((int)(rportRaw & 0xFFFF) & 0xFF) << 8 | ((int)(rportRaw & 0xFFFF) >> 8) & 0xFF;
                var r = new ConnRow();
                r.Pid = pid;
                r.State = (int)state;
                r.RemotePort = rport;
                try { r.RemoteIp = new IPAddress(remote).ToString(); } catch { r.RemoteIp = "0.0.0.0"; }
                res.Add(r);
            }
        }
        catch { }
        finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(buf); }
        return res;
    }

    // 返回 List<int> 目标端口（所有连向 ServerIp 的连接，含 SYN_SENT）
    static List<int> SniffTargetPorts()
    {
        var res = new List<int>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 0) return res;
        IntPtr buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                return res;
            int rows = System.Runtime.InteropServices.Marshal.ReadInt32(buf);
            int rowSize = 24;
            long target = IPAddress.Parse(ServerIp).Address;
            for (int i = 0; i < rows; i++)
            {
                IntPtr p = new IntPtr(buf.ToInt64() + 4 + i * rowSize);
                uint remote = (uint)System.Runtime.InteropServices.Marshal.ReadInt32(p, 12);
                int remotePort = (int)(((uint)System.Runtime.InteropServices.Marshal.ReadInt32(p, 16) & 0xFFFF));
                remotePort = ((remotePort & 0xFF) << 8) | ((remotePort >> 8) & 0xFF);   // 网络序
                if (remote == (uint)target) res.Add(remotePort);
            }
        }
        catch { }
        finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(buf); }
        return res;
    }

    const string DEFAULT_SERVER_IP = "111.229.48.214";
    static readonly Encoding GBK = Encoding.GetEncoding(936);
    static string LogPath;
    static readonly object LogLock = new object();
    static string Mode = "right";
    static string ServerIp = DEFAULT_SERVER_IP;
    static readonly List<int> Ports = new List<int>();
    static bool Launch = true;
    static bool KeepAlias = false;
    static readonly HashSet<int> BoundTcp = new HashSet<int>();
    static readonly HashSet<int> BoundUdp = new HashSet<int>();
    static readonly HashSet<int> SeenPorts = new HashSet<int>();
    static string Reply = "";
    static volatile bool AliasOk = false;
    static int ExitAfter = 0;

    static void Log(string s)
    {
        string line = string.Format("[{0:HH:mm:ss.fff}] {1}", DateTime.Now, s);
        Console.WriteLine(line);
        try { lock (LogLock) { File.AppendAllText(LogPath, line + Environment.NewLine, GBK); } }
        catch { }
    }

    static bool IsAdmin()
    {
        try
        {
            var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            var p = new System.Security.Principal.WindowsPrincipal(id);
            return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    static void RelaunchElevated()
    {
        try
        {
            var psi = new ProcessStartInfo();
            psi.FileName = Process.GetCurrentProcess().MainModule.FileName;
            psi.Arguments = JoinArgs(Environment.GetCommandLineArgs(), 1);
            psi.Verb = "runas";
            psi.UseShellExecute = true;
            Process.Start(psi);
        }
        catch (Exception e)
        {
            Console.WriteLine("[!] 提权失败: " + e.Message);
            Console.WriteLine("    请右键本程序 → 以管理员身份运行");
            Console.WriteLine("按任意键退出...");
            Console.ReadKey();
        }
    }

    static string JoinArgs(string[] argv, int from)
    {
        var sb = new StringBuilder();
        for (int i = from; i < argv.Length; i++)
        {
            if (argv[i].IndexOf(' ') >= 0) sb.Append('"').Append(argv[i]).Append('"');
            else sb.Append(argv[i]);
            if (i < argv.Length - 1) sb.Append(' ');
        }
        return sb.ToString();
    }

    static void ParseArgs(string[] argv)
    {
        for (int i = 1; i < argv.Length; i++)
        {
            string a = argv[i].ToLowerInvariant().Trim('"', '\'');
            if (a == "--mode" && i + 1 < argv.Length) Mode = argv[++i].ToLowerInvariant();
            else if (a == "--ip" && i + 1 < argv.Length) ServerIp = argv[++i];
            else if (a == "--ports" && i + 1 < argv.Length)
            {
                foreach (string s in argv[++i].Split(','))
                {
                    int v;
                    if (int.TryParse(s.Trim(), out v)) Ports.Add(v);
                }
            }
            else if (a == "--no-launch") Launch = false;
            else if (a == "--keep-alias") KeepAlias = true;
            else if (a == "--exit-after" && i + 1 < argv.Length) int.TryParse(argv[++i], out ExitAfter);
            else if (a == "--extract-only") Launch = false;
        }
        if (Ports.Count == 0)
        {
            // 常见网络验证/Web 端口
            int[] def = new int[] { 80, 443, 8080, 8888, 9000, 9090, 9999, 5211, 27112, 3389, 10086, 12345, 3000, 4000, 5000, 6060, 7000, 7001, 8001, 8443 };
            Ports.AddRange(def);
            // 再扫一批常用自定义端口段（覆盖"随机但固定"的服务端端口）
            int[][] ranges = new int[][] {
                new int[] { 8000, 8080 }, new int[] { 8800, 8880 },
                new int[] { 9000, 9060 }, new int[] { 10000, 10060 },
                new int[] { 27000, 27120 }, new int[] { 5000, 5100 }
            };
            foreach (int[] rg in ranges)
                for (int p = rg[0]; p <= rg[1]; p++)
                    if (!Ports.Contains(p)) Ports.Add(p);
        }
    }

    // 每次连接换一种应答格式，让客户端"自己帮我们测"哪一种是它要的
    static int StrategyIdx = -1;
    static readonly object StrategyLock = new object();

    static byte[] NextReply(byte[] req, int port)
    {
        int idx;
        lock (StrategyLock) { StrategyIdx++; idx = StrategyIdx; }
        string name;
        byte[] body;
        if (req != null && req.Length >= 5)
        {
            byte[] payload = new byte[req.Length - 5];
            Buffer.BlockCopy(req, 5, payload, 0, payload.Length);
            int len = req.Length;
            switch (idx % 6)
            {
                case 0:   // 类型改 0x02 + 回显原密文（最常见的"应答=同构帧"）
                    name = "S1 帧[02]+回显密文";
                    body = Frame(0x02, payload);
                    break;
                case 1:   // 类型 0x02 + 全零
                    name = "S2 帧[02]+零填充";
                    body = Frame(0x02, new byte[payload.Length]);
                    break;
                case 2:   // 类型 0x02 + 明文成功串
                    name = "S3 帧[02]+明文Right";
                    body = Frame(0x02, GBK.GetBytes("Right,初始化成功!"));
                    break;
                case 3:   // 类型 0x01 + 回显（原类型回显）
                    name = "S4 帧[01]+回显密文";
                    body = Frame(0x01, payload);
                    break;
                case 4:   // 原包整包回显
                    name = "S5 整包回显";
                    body = req;
                    break;
                default:  // 纯明文成功串
                    name = "S6 纯明文Right";
                    body = GBK.GetBytes("Right,初始化成功!");
                    break;
            }
        }
        else
        {
            name = "S0 纯明文Right";
            body = GBK.GetBytes("Right,初始化成功!");
        }
        Log("  使用应答策略: " + name + "  (" + body.Length + " 字节)");
        return body;
    }

    static byte[] Frame(byte type, byte[] payload)
    {
        byte[] f = new byte[5 + payload.Length];
        f[0] = type;
        int L = f.Length;
        f[1] = (byte)(L & 0xFF); f[2] = (byte)((L >> 8) & 0xFF);
        f[3] = (byte)((L >> 16) & 0xFF); f[4] = (byte)((L >> 24) & 0xFF);
        Buffer.BlockCopy(payload, 0, f, 5, payload.Length);
        return f;
    }

    static string ReplyFor(string mode)
    {
        switch (mode)
        {
            case "log": return "";
            case "right": return "Right,初始化成功!";
            case "right2": return "Right,天才少年,我已经准备好了，你准备好了吗!";
            case "version": return "Right,初始化成功,当前版本不是最新版，不可以登陆!";
            case "ok": return "1";
            case "json": return "{\"code\":200,\"msg\":\"Right,初始化成功!\",\"expire\":\"2099-12-31 23:59:59\",\"point\":999999,\"vip\":9,\"level\":9,\"days\":99999}";
            default: return "Right,初始化成功!";
        }
    }

    static string Hex(byte[] b, int n)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < Math.Min(n, b.Length); i++) sb.Append(b[i].ToString("x2"));
        return sb.ToString();
    }

    static string Ascii(byte[] b, int n)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < Math.Min(n, b.Length); i++)
        {
            byte c = b[i];
            sb.Append(c >= 32 && c < 127 ? (char)c : '.');
        }
        return sb.ToString();
    }

    static void HandleTcp(TcpClient client, int port, string reply)
    {
        string remote = "?";
        try
        {
            remote = client.Client.RemoteEndPoint.ToString();
            client.ReceiveTimeout = 5000;
            NetworkStream st = client.GetStream();
            var ms = new MemoryStream();
            byte[] buf = new byte[8192];
            int total = 0;
            while (true)
            {
                int n = 0;
                try { n = st.Read(buf, 0, buf.Length); }
                catch { break; }
                if (n <= 0) break;
                ms.Write(buf, 0, n);
                total += n;
                if (total > 65536) break;
                if (!st.DataAvailable) break;
            }
            byte[] data = ms.ToArray();
            Log(string.Format("端口 {0} 收到 {1} 字节  来自 {2}", port, data.Length, remote));
            if (data.Length > 0)
            {
                Log("  HEX  : " + Hex(data, 512));
                Log("  ASCII: " + Ascii(data, 512));
                try { Log("  GBK  : " + GBK.GetString(data)); } catch { }
            }

            if (data.Length > 0 && data[0] == 0x16)
            {
                Log("  !!! 这是 TLS(HTTPS) 握手包 —— 明文回包不可能被接受");
                Log("      说明它走的是加密通道，需要改成客户端补丁方案（把判定改掉，而不是冒充服务器）");
            }

            bool http = false;
            if (data.Length >= 4)
            {
                string head = Encoding.ASCII.GetString(data, 0, 4);
                if (head.StartsWith("GET ") || head.StartsWith("POST") || head.StartsWith("HEAD") || head.StartsWith("PUT ")) http = true;
            }

            if (reply.Length > 0)
            {
                byte[] outb = NextReply(data, port);
                if (http)
                {
                    string h = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " + outb.Length + "\r\nConnection: close\r\n\r\n";
                    byte[] hb = Encoding.ASCII.GetBytes(h);
                    byte[] tmp = new byte[hb.Length + outb.Length];
                    Buffer.BlockCopy(hb, 0, tmp, 0, hb.Length);
                    Buffer.BlockCopy(outb, 0, tmp, hb.Length, outb.Length);
                    outb = tmp;
                }
                try
                {
                    st.Write(outb, 0, outb.Length);
                    st.Flush();
                    Log("  → 已发送应答 " + outb.Length + " 字节: " + Hex(outb, 64));
                }
                catch (Exception e) { Log("  → 回包失败: " + e.Message); }
            }
            else Log("  → log 模式，不回包");
        }
        catch (Exception e) { Log("端口 " + port + " 处理异常: " + e.Message); }
        finally { try { client.Close(); } catch { } }
    }

    static void TcpLoop(int port, string reply)
    {
        TcpListener l = null;
        // 先试全接口（最强：任何目标地址都落到我们这里）
        try
        {
            l = new TcpListener(IPAddress.Any, port);
            l.Start(64);
            lock (BoundTcp) BoundTcp.Add(port);
            Log("TCP 监听 0.0.0.0:" + port);
        }
        catch (Exception)
        {
            try
            {
                l = new TcpListener(IPAddress.Parse(ServerIp), port);
                l.Start(64);
                lock (BoundTcp) BoundTcp.Add(port);
                Log("TCP 监听 " + ServerIp + ":" + port);
            }
            catch (Exception e2) { Log("TCP 端口 " + port + " 跳过: " + e2.Message); return; }
        }
        while (true)
        {
            try
            {
                TcpClient c = l.AcceptTcpClient();
                ThreadPool.QueueUserWorkItem(delegate (object o) { HandleTcp((TcpClient)o, port, reply); }, c);
            }
            catch { Thread.Sleep(100); }
        }
    }

    static void UdpLoop(int port, string reply)
    {
        try
        {
            UdpClient u;
            try
            {
                u = new UdpClient(new IPEndPoint(IPAddress.Any, port));
                Log("UDP 监听 0.0.0.0:" + port);
            }
            catch
            {
                u = new UdpClient(new IPEndPoint(IPAddress.Parse(ServerIp), port));
                Log("UDP 监听 " + ServerIp + ":" + port);
            }
            lock (BoundUdp) BoundUdp.Add(port);
            var ep = new IPEndPoint(IPAddress.Any, 0);
            while (true)
            {
                byte[] d = u.Receive(ref ep);
                Log(string.Format("UDP 端口 {0} 收到 {1} 字节  来自 {2}", port, d.Length, ep));
                Log("  HEX  : " + Hex(d, 256));
                if (reply.Length > 0)
                {
                    byte[] b = GBK.GetBytes(reply);
                    try { u.Send(b, b.Length, ep); Log("  → 已回包 UDP: " + reply); } catch { }
                }
            }
        }
        catch (Exception e) { Log("UDP 端口 " + port + " 跳过: " + e.Message); }
    }

    static int RunNetsh(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("netsh", args);
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.CreateNoWindow = true;
            var p = Process.Start(psi);
            p.WaitForExit(8000);
            return p.ExitCode;
        }
        catch { return -1; }
    }

    static string FindLoopback()
    {
        try
        {
            var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"(Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'Loopback' -or $_.Name -match 'Loopback' } | Select-Object -First 1).Name\"");
            psi.UseShellExecute = false; psi.RedirectStandardOutput = true; psi.CreateNoWindow = true;
            var p = Process.Start(psi);
            string s = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit(8000);
            if (s.Length > 0) return s;
        }
        catch { }
        return "Loopback Pseudo-Interface 1";
    }

    static void AddAlias()
    {
        string ifName = FindLoopback();
        Log("回环网卡: " + ifName);
        RunNetsh(string.Format("interface ipv4 add address name=\"{0}\" address={1} mask=255.255.255.255", ifName, ServerIp));
        // 验证是否真的绑上了：尝试绑定该 IP 的临时端口
        try
        {
            var probe = new TcpListener(IPAddress.Parse(ServerIp), 0);
            probe.Start(); probe.Stop();
            AliasOk = true;
            Log("劫持状态: 成功（" + ServerIp + " 已在本机）");
        }
        catch
        {
            AliasOk = false;
            Log("[!] 劫持状态: 失败 —— 程序会连到真服务器，登录会卡住/失败");
            Log("    请确认是以管理员身份运行；或手动执行 1_redirect_ip.ps1");
        }
    }

    static void DelAlias()
    {
        if (KeepAlias) { Log("按 --keep-alias 保留劫持，未清理"); return; }
        string ifName = FindLoopback();
        RunNetsh(string.Format("interface ipv4 delete address name=\"{0}\" address={1}", ifName, ServerIp));
        Log("已还原 IP 劫持");
    }

    static int ChildPid = 0;
    static readonly HashSet<string> SeenEndpoints = new HashSet<string>();
    static readonly HashSet<string> AliasedIps = new HashSet<string>();

    static void PortSniffer()
    {
        int tick = 0;
        while (true)
        {
            try
            {
                // (a) 打印目标进程的所有对外连接（这是定位"它到底连谁"的关键）
                if (ChildPid != 0)
                {
                    foreach (ConnRow r in SniffAllConns())
                    {
                        if (r.Pid != ChildPid) continue;
                        if (r.RemoteIp == "0.0.0.0" || r.RemoteIp.StartsWith("127.") || r.RemoteIp == "::") continue;
                        string key = r.ToString();
                        bool isNew = false;
                        lock (SeenEndpoints) { if (!SeenEndpoints.Contains(key)) { SeenEndpoints.Add(key); isNew = true; } }
                        if (isNew)
                        {
                            Log("*** 目标程序对外连接: " + key);
                            if (r.RemoteIp != ServerIp && !r.RemoteIp.StartsWith("10.") && !r.RemoteIp.StartsWith("192.168.") && !r.RemoteIp.StartsWith("172."))
                            {
                                Log("    ↑ 注意：这不是我们劫持的 " + ServerIp + " —— 说明它连了别的服务器");
                                if (AliasedIps.Add(r.RemoteIp))
                                {
                                    Log("    自动把这个 IP 也劫持到本机: " + r.RemoteIp);
                                    string ifName = FindLoopback();
                                    RunNetsh(string.Format("interface ipv4 add address name=\"{0}\" address={1} mask=255.255.255.255", ifName, r.RemoteIp));
                                }
                            }
                        }
                    }
                }

                List<int> ports = SniffTargetPorts();
                foreach (int p in ports)
                {
                    bool isNew = false;
                    lock (SeenPorts) { if (!SeenPorts.Contains(p)) { SeenPorts.Add(p); isNew = true; } }
                    if (isNew)
                        Log("*** 检测到程序连接 " + ServerIp + ":" + p + "  ← 目标端口就是这个！");
                    bool needTcp, needUdp;
                    lock (BoundTcp) needTcp = !BoundTcp.Contains(p);
                    lock (BoundUdp) needUdp = !BoundUdp.Contains(p);
                    if (needTcp)
                    {
                        int cp = p;
                        Log(">>> 立刻在端口 " + p + " 上补开 TCP 监听");
                        var t = new Thread(delegate () { TcpLoop(cp, Reply); });
                        t.IsBackground = true; t.Start();
                    }
                    if (needUdp)
                    {
                        int cp = p;
                        var u = new Thread(delegate () { UdpLoop(cp, Reply); });
                        u.IsBackground = true; u.Start();
                    }
                }
                if (tick % 25 == 0)
                {
                    int nb, se;
                    lock (BoundTcp) nb = BoundTcp.Count;
                    lock (SeenEndpoints) se = SeenEndpoints.Count;
                    Log("[心跳] 已监听 TCP 端口 " + nb + " 个；已捕获目标外连 " + se + " 条；劫持="
                        + (AliasOk ? "成功" : "失败"));
                }
                if (tick % 75 == 0 && !AliasOk)
                    Log("[i] 仍在等待；当前未检测到任何到 " + ServerIp + " 的连接"
                        + "（如果程序已经" + "点了登录" + "，说明它连的是别处或本地就拦住了）");
            }
            catch { }
            tick++;
            Thread.Sleep(200);
        }
    }

    static void Main(string[] argv)
    {
        LogPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "capture.log");
        Console.OutputEncoding = GBK;
        Console.WriteLine("============================================================");
        Console.WriteLine("  HWIDUnlock —— 卡密服务端接管器（单文件版）");
        Console.WriteLine("  目标服务器: 111.229.48.214   握手成功串: Right,初始化成功!");
        Console.WriteLine("============================================================");

        ParseArgs(argv);
        Log("argv = " + string.Join(" ", argv));

        if (!IsAdmin())
        {
            Console.WriteLine("[i] 需要管理员权限，正在请求提权...");
            RelaunchElevated();
            return;
        }

        Log("模式=" + Mode + "  端口=" + string.Join(",", Ports.ConvertAll(delegate (int x) { return x.ToString(); }).ToArray())
            + "  自动拉起=" + Launch);

        AddAlias();

        string reply = ReplyFor(Mode);
        Reply = reply;
        if (reply.Length > 0) Log("回包内容: " + reply);
        else Log("log 模式：只抓包不回包");

        foreach (int p in Ports)
        {
            int cp = p;
            var t = new Thread(delegate () { TcpLoop(cp, reply); });
            t.IsBackground = true; t.Start();
            if (p == 80 || p == 8080 || p == 8888 || p == 9000 || p == 9999 || p == 27112)
            {
                var u = new Thread(delegate () { UdpLoop(cp, reply); });
                u.IsBackground = true; u.Start();
            }
        }

        if (!Launch)
        {
            string p = ExtractPayload();
            if (p != null) Log("内嵌载荷检查完成（自检模式，不启动）");
        }

        var sniffer = new Thread(delegate () { PortSniffer(); });
        sniffer.IsBackground = true;
        sniffer.Start();
        Log("端口哨兵已启动：它连任何端口，我会立刻在那个端口补开监听");

        Thread.Sleep(600);

        if (Launch)
        {
            string dir = AppDomain.CurrentDomain.BaseDirectory;
            string target = null;
            string[] cand = new string[] { "HWIDMaster-0902.exe", "HWIDMaster.exe" };
            foreach (string c in cand)
            {
                string f = Path.Combine(dir, c);
                if (File.Exists(f)) { target = f; break; }
            }
            if (target == null)
            {
                // 单文件模式：从自身资源释放
                target = ExtractPayload();
            }
            if (target == null)
            {
                foreach (string f in Directory.GetFiles(dir, "*.exe"))
                {
                    if (Path.GetFileName(f).ToLowerInvariant() == Path.GetFileName(Process.GetCurrentProcess().MainModule.FileName).ToLowerInvariant()) continue;
                    target = f; break;
                }
            }
            if (target != null)
            {
                try
                {
                    var pi = new ProcessStartInfo(target);
                    pi.WorkingDirectory = Path.GetDirectoryName(target);
                    pi.UseShellExecute = false;
                    var proc = Process.Start(pi);
                    ChildPid = proc.Id;
                    Log("已拉起目标程序: " + Path.GetFileName(target) + "  PID=" + proc.Id);
                    string myDir = AppDomain.CurrentDomain.BaseDirectory;
                    OutDir = myDir;
                    try { File.WriteAllText(Path.Combine(myDir, ".wtest"), "x"); File.Delete(Path.Combine(myDir, ".wtest")); }
                    catch { OutDir = Path.GetTempPath(); }
                    string uiKey = "AAAAAAAAAAAAAAAA";
                    var ui = new Thread(delegate ()
                    {
                        Thread.Sleep(5000);
                        try { UiAutomate(ChildPid, uiKey); } catch (Exception e) { Log("[!] UI 自动化异常: " + e.Message); }
                    });
                    ui.IsBackground = true; ui.Start();

                    var dumper = new Thread(delegate ()
                    {
                        Thread.Sleep(12000);
                        DumpChild(ChildPid);
                    });
                    dumper.IsBackground = true; dumper.Start();

                    var watcher = new Thread(delegate ()
                    {
                        try
                        {
                            proc.WaitForExit();
                            Log("[!] 目标程序已退出，退出码=" + proc.ExitCode + " (" + proc.ExitCode.ToString("x") + ")");
                        }
                        catch { }
                    });
                    watcher.IsBackground = true; watcher.Start();
                }
                catch (Exception e) { Log("拉起目标失败: " + e.Message); }
            }
            else Log("[!] 没找到目标 exe（把 HWIDMaster-0902.exe 放在本程序同一目录）");
        }

        Log("");
        Log(">>> 现在在程序里随便输入一个卡密，点登录；本窗口会显示它发出的数据");
        Log(">>> Ctrl+C 结束（会自动还原劫持）");
        Log("");

        if (ExitAfter > 0)
        {
            Thread.Sleep(ExitAfter * 1000);
            Log("--exit-after 到期，退出");
        }
        else
        {
            try
            {
                while (true) Thread.Sleep(500);
            }
            catch { }
        }
        DelAlias();
    }
}
