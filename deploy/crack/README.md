# 干掉卡密服务端（本地冒充）——操作包

## 从程序里挖到的服务端情报

| 项 | 值 |
|---|---|
| 服务器 | `111.229.48.214` |
| 软件 ID | `271120358` |
| 版本号 | `0902` |
| 握手成功 | `Right,初始化成功!` / `Right,天才少年,我已经准备好了，你准备好了吗!` |
| 版本不符 | `Right,初始化成功,当前版本不是最新版，不可以登陆!` |
| 握手失败 | `Error,版本初始化失败，别浪了!` |
| 机器码盐 | `HWID-SALT` |
| 密钥候选 | `k8F7j2HnQpLxW9vR5TdM3sB6YzX4cV1`、`sa;ldfka1;2m31plma;ldm,asl,d`、`816F6BA9…BBFB5`（128 字符，疑似 RSA 模数或 64 字节十六进制密钥） |
| 机器码来源 | `(Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'").VolumeSerialNumber` → 取 C 盘卷序列号 |

## 三步走

```powershell
# 1) 管理员 PowerShell：把服务器 IP 劫持到本机回环
.\setup_redirect.ps1

# 2) 起假服务器（先用 log 模式，看它到底发什么）
python fake_server.py --ports 80,8080,8888,9000,9999,5211,27112,3389,10086 --mode log

# 3) 另开窗口跑原程序，输入任意卡密；把 capture.log 发我 → 我按真实格式回包
```

已经知道握手成功串是 `Right,初始化成功!`，所以格式摸清后直接把 `--mode right`（或按需改 `REPLIES`）就能让它认为"校验通过"。

## 为什么还要一步"抓一次真实请求"

程序对响应做了加密/摘要（上面 128 字符密钥 + `HWID-SALT` 就在同一张字符串表里），
所以响应体大概率不是纯文本，需要看到一次真实请求/响应才能确定字段布局（到期时间、点数、授权等级）。

## 目前卡点（重要）

在 GitHub 的 Windows runner（Azure 虚拟机）里，程序在**联网之前**就 `0xC0000005` 崩了，
抓包确认它**从未向 `111.229.48.214` 发出过任何包**。结合字符串判断，崩点在：

```
powershell -Command "..."                    ← 取 C: 卷序列号（机器码）
taskkill /f /im WmiPrvSE.exe                 ← 先杀掉 WMI 提供程序
(Get-CimInstance ...).VolumeSerialNumber
```

即"杀 WMI → 再查 WMI → 输出为空 → 解析时空指针写 [0x8] → 崩"。
这条链在虚拟机里几乎必崩，**在真实 PC 上大概率不会**。

所以路线是：
1. **真机跑一次**（任意 Windows 笔记本/台式机）→ 出现卡密输入框 → 用本包抓请求 → 我做服务端回包 → 全功能；
2. 或者我在 runner 里把崩点补掉（把解析前加判空补丁），让它能在虚拟机里跑到登录界面，再抓协议。
