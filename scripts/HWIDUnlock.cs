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
    const string DEFAULT_SERVER_IP = "111.229.48.214";
    static readonly Encoding GBK = Encoding.GetEncoding(936);
    static string LogPath;
    static readonly object LogLock = new object();
    static string Mode = "right";
    static string ServerIp = DEFAULT_SERVER_IP;
    static readonly List<int> Ports = new List<int>();
    static bool Launch = true;
    static bool KeepAlias = false;
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
        }
        if (Ports.Count == 0)
        {
            // 常见网络验证端口 + 常见 Web 端口
            int[] def = new int[] { 80, 443, 8080, 8888, 9000, 9090, 9999, 5211, 27112, 3389, 10086, 12345 };
            Ports.AddRange(def);
        }
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

            bool http = false;
            if (data.Length >= 4)
            {
                string head = Encoding.ASCII.GetString(data, 0, 4);
                if (head.StartsWith("GET ") || head.StartsWith("POST") || head.StartsWith("HEAD") || head.StartsWith("PUT ")) http = true;
            }

            if (reply.Length > 0)
            {
                byte[] body = GBK.GetBytes(reply);
                byte[] outb;
                if (http)
                {
                    string h = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=gbk\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n";
                    byte[] hb = Encoding.ASCII.GetBytes(h);
                    outb = new byte[hb.Length + body.Length];
                    Buffer.BlockCopy(hb, 0, outb, 0, hb.Length);
                    Buffer.BlockCopy(body, 0, outb, hb.Length, body.Length);
                }
                else outb = body;
                try
                {
                    st.Write(outb, 0, outb.Length);
                    st.Flush();
                    Log("  → 已回包(" + (http ? "HTTP" : "RAW") + "): " + reply);
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
        try
        {
            l = new TcpListener(IPAddress.Parse(ServerIp), port);
            l.Start(16);
            Log("TCP 监听 " + ServerIp + ":" + port);
        }
        catch (Exception)
        {
            try
            {
                l = new TcpListener(IPAddress.Any, port);
                l.Start(16);
                Log("TCP 监听 0.0.0.0:" + port + "（" + ServerIp + " 未绑定成功，可能是劫持没做）");
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
            var u = new UdpClient(new IPEndPoint(IPAddress.Parse(ServerIp), port));
            Log("UDP 监听 " + ServerIp + ":" + port);
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
        Log("已尝试把 " + ServerIp + " 绑到本机（若已存在会报重复，忽略）");
    }

    static void DelAlias()
    {
        if (KeepAlias) { Log("按 --keep-alias 保留劫持，未清理"); return; }
        string ifName = FindLoopback();
        RunNetsh(string.Format("interface ipv4 delete address name=\"{0}\" address={1}", ifName, ServerIp));
        Log("已还原 IP 劫持");
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
                    Log("已拉起目标程序: " + Path.GetFileName(target) + "  PID=" + proc.Id);
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
