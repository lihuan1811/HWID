# Windows 侧作业手册：从"能跑的程序"到"无激活码成品"

> 服务的对象是 `HWIDMaster-0902.exe` 这一类 **VCL(C++Builder/Delphi) + 卡密授权 + 加壳** 的程序。
> 本文按"操作 → 命令 → 判据"写，能照着打。
> 前置：Windows 10/11 x64 虚拟机（VMware/Hyper-V 均可，**快照开机前先打一个**）。

---

## 0. 工具清单（都放同一目录 `C:\re\`）

| 工具 | 用途 | 备注 |
|---|---|---|
| **x96dbg**（含 x32dbg/x64dbg） | 动态调试、下断、dump | 目标是 PE32 → 用 **x32dbg** |
| **ScyllaHide**（x32dbg 插件） | 反反调试 | 插件目录 `x32\plugins\ScyllaHide` |
| **Scylla**（独立版） | IAT 重建 + Dump | 和 x32dbg 一起来 |
| **Detect It Easy (DIE)** | 壳/编译器识别 | 先跑它再动手 |
| **Process Hacker** | 看进程/内存/句柄、Create dump | 抓转储最省事 |
| **procdump**（Sysinternals） | 命令行抓全内存 | `procdump64 -ma <pid> out.dmp` |
| **PE-bear / HxD** | 改 PE 头、看字节 | 收尾修头 |
| **IDA Free / Ghidra** | 脱壳后静态审 | 找校验逻辑最快 |

---

## 1. 第 0 步：先确认"这文件到底能不能跑"

```powershell
# 直接双击 / 或命令行起，然后看进程
Start-Process .\HWIDMaster-0902.exe
Start-Sleep -Seconds 3
Get-Process HWIDMaster* -ErrorAction SilentlyContinue
```

判据：

- **进程起来又秒退（0.5~2 秒内消失）** → 与静态报告一致：入口是密文，文件本身不可运行。
  **停在这里，去走报告第 8 节的路线 A/C**（要启动器/要可运行版本），别浪费时间脱壳。
- **出现界面（哪怕提示"请输入激活码"）** → 说明这是**另一份能跑的样本**，按下面 2→9 步走。

> 说明：`HWIDMaster-0902.exe` 的段表里原程序四个段 `SizeOfRawData = 0`、入口点 0x2AF1DD3 落在密文区，
> 静态上判定为"加密载荷"。第 0 步只是把它在真机上复核一次。

---

## 1.5 第 0.5 步：EP 修复试探（5 分钟，可能直接起死回生）

静态分析给出一个很具体的线索：这个壳是**虚拟机型（VMProtect 一类）**，
它的 stub 明文躺在 `.KPx` 尾部（RVA ≈ `0x5191000 ~ 0x53B0000`），
而 PE 头里的 EP 却被写成了 `0x2AF1DD3`（指向密文区）——两者差了 28 MB。
**如果只是入口被改坏**，把 EP 改回 stub 区就能起。

```bash
# 生成一个只改了入口点的副本（原文件不动）
python3 tools/set_ep.py HWIDMaster-0902.exe 0x5191000 --out HWIDMaster_epfix.exe

# 看当前 EP
python3 tools/set_ep.py HWIDMaster-0902.exe --show
```

在 Windows 上双击 `HWIDMaster_epfix.exe`：

| 现象 | 判读 | 下一步 |
|---|---|---|
| 出现界面/弹激活框 | 入口点确实被改坏，壳是好的 | 走第 3 步脱壳 |
| 进程秒退 | 换 EP 档位再试（`0x5192000`、`0x5193000`、`0x51A0000`、`0x5200000`…每次 +0x1000） | 仍不行 → 第 1 步 |
| 报"不是有效的 Win32 应用"/被 AV 拦 | EP 改到了数据区 | 换档位；或第 1 步 |

> 提示：x32dbg 里也可以不改文件直接试 —— `Ctrl+G` 输入 `0x5191000`，
> 然后 `Ctrl+*`（设置新 EIP）→ `F9`，看会不会跑起来。

---

## 2. 第 1 步：壳识别（30 秒）

1. DIE 拖进去看：`Protector` 一栏是啥（VMProtect / Themida / Safename / Enigma / 自研）。
2. 同时跑一遍我们自己的体检：

```bash
python3 tools/pe_triage.py <目标.exe> --json results/triage_<名字>.json
```

判据与对策：

| 体检结论 | 含义 | 走哪条 |
|---|---|---|
| `PLAIN` | 没壳 | 直接跳到第 6 步（找激活校验） |
| `PACKED` | 有明文 stub | 第 3~5 步运行时脱壳 |
| `ENCRYPTED_PAYLOAD` | 无 stub、纯密文 | **脱不了**，要 loader/可运行版本 |

---

## 3. 第 2 步：反反调试（ScyllaHide）

x32dbg → `插件 → ScyllaHide → Options`：

- Profile 选 **`VMProtect`**（覆盖绝大多数国产壳/VM 壳）
- 勾：`PEB->BeingDebugged`、`PEB->NtGlobalFlag`、`HeapMagic`、`HideDebugger`、
  `Kill Anti-Attach`、`Remove CLI/INT 3`、`UnhandledExceptionFilter`、
  `Zone 时间伪装(Speedup)`、`Protect DRx`、`TitanHide`（若装了驱动）
- 勾 **`注入到新进程`**，再 `File → Open` 载入目标（**先配 Hook 再开进程**，顺序不能反）

DIE 报 VMProtect/Themida 时额外做：

- `Options → Exceptions`：全部忽略（尤其 `0x80000003`、`0xC000001D`、`0xC0000096` 非法指令/特权指令）
- x32dbg 设置里关掉 `System Breakpoint` 的自动弹出（`选项 → 事件 → 系统断点` 取消勾选）

---

## 4. 第 3 步：走到 OEP

### 方案 A：内存执行断点（最稳，推荐）

目标程序的原始代码段在壳里，解密后会被**执行**，所以在"原 .text 段"上下执行断点即可命中 OEP 附近。

1. 附加/打开目标，停在系统断点后按 `Alt+M` 打开内存映射
2. 找到属于主模块、`保护=RWE/RX` 且大小与 `.text` 吻合的段
3. 右键 → `断点 → 内存执行断点`（等价脚本命令：`bpm <起始地址>, 0, "x"`）
4. `F9` 跑；命中后 `Ctrl+F9`（执行到返回）或单步走出壳代码
5. 判据：**接下来代码里出现大量对 `.rdata` 字符串的引用、出现 VCL 的 `GetModuleHandle`/`WriteFile` 等真实 API 调用**，就是 OEP 区域

### 方案 B：API 断点法

```text
// x32dbg 脚本（File → Script → 载入）  存成 C:\re\oep.txt
bpx VirtualProtect
bpx VirtualAlloc
bpx GetModuleHandleA
bpx GetProcAddress
run
```

命中 `VirtualProtect` 时看第二参数是不是 `PAGE_EXECUTE_READWRITE(0x40)`、区域是不是主模块 —— 那就是壳在给自己解密。
在 `VirtualProtect` **返回后**（`Ctrl+F9`）对该区域下内存执行断点，等价于方案 A。

### 方案 C：硬件断点法（VM 壳常用）

1. 在 `VirtualProtect` 返回处，右击解密后的区域 → `断点 → 硬件访问 → 执行`
2. 或在栈上找返回到原 .text 的地址，`bp <该地址>`

### 到 OEP 的判据（三个同时满足）

1. 当前 EIP 落在原 `.text` 的 VA 范围内（不是壳段）
2. 代码段熵明显下降（x32dbg 的 `内存映射` 里看，或 dump 出来用 `pe_triage.py` 看熵）
3. `Ctrl+F9`/单步不会再跳回壳段

---

## 5. 第 4 步：Dump + IAT 修复

### 4.1 用 Scylla（推荐，一条龙）

1. 到 OEP 后**不要继续跑**，保持暂停
2. 打开 Scylla → `File → Attach to active process` → 选目标（32 位进程）
3. `IAT Autosearch` → `Get Imports`
4. 看列表：`Invalid` 的条目右键 `Cut thunk` / 或用 `Fix` 补
   （VCL 程序常见 `OLEAUT32` 序号导入被判 invalid，属正常）
5. 在 Scylla 里把 `OEP` 填成第 3 步拿到的 OEP（RVA 或 VA 都行，注意基址 0x400000）
6. `Dump` → 存成 `hwid_dumped.exe`
7. `Fix Dump` → 选刚存的文件 → 生成 `hwid_dumped_SCY.exe`（IAT 已修）

### 4.2 用 Process Hacker + 我们的脚本（Scylla 不灵时）

1. 到 OEP 后，Process Hacker 找到进程 → 右键 `Create dump file` → `hwid.dmp`
2. 拷回分析机（或本机 WSL/macOS）：

```bash
python3 tools/dump2exe.py --dump hwid.dmp --base 0x400000 \
        --out hwid_unpacked.exe --oep 0x<OEP的RVA> --report
```

3. 输出会打印每段 RAW/RS 与入口点；`--drop-shell` 可丢掉名字随机的壳段
4. IAT 仍需修：把 `hwid_unpacked.exe` 在 x32dbg 里打开，用 Scylla 的
   `IAT Autosearch + Fix Dump` 走一遍（Scylla 支持对文件直接修）

### 4.3 自检（关键，别跳过）

```bash
python3 tools/pe_triage.py hwid_dumped_SCY.exe
```

必须是 `PLAIN`；再确认：

- 段表里 `.text` 有真实 RAW 数据，熵在 6.0~6.8 之间（代码段正常范围）
- `strings` 能刷出中文 UI 文案（"激活码""机器码""到期时间"…）

---

## 6. 第 5 步：找"激活码/卡密"判定门

### 5.1 自动跑一遍（先看机器给的候选）

```bash
python3 tools/delphi_gate.py --exe hwid_dumped_SCY.exe --json gates.json --top 40
```

输出三样东西：

- 命中的授权文案（按可疑度打分：`激活码无效 85` > `未授权 45` > `license 30`）
- 每个文案在代码里的**引用点**（`push imm32` / `mov reg,imm32` / `lea`）
- 引用点附近的**条件跳转候选（门）**，带前文（`call xxx ; test al, al` 这种最典型）

判据：**一个 `call 校验函数` 紧跟 `test al,al` + `jz/jnz`，且失败分支里引用了"激活码无效"字符串，就是主门。**

### 5.2 手工确认（IDA / x32dbg）

1. IDA 里 `Shift+F12` 字符串窗口 → 搜 `激活` `注册` `卡密` `到期` `机器码` `license` `expired`
2. 选中字符串 `X` 看交叉引用 → 进函数 → 看调用者的判断
3. 典型形态（VCL/BCB，32 位）：

```asm
push    offset aActivationInva   ; "激活码无效"
call    sub_40xxxx               ; MessageBox 类
call    sub_4xxxxx               ; ← 真正的校验函数（返回 al = 1/0）
test    al, al
jz      short loc_fail           ; ← 门：跳走就是"未激活"
```

4. 校验函数内部常见三种实现：
   - **本地算法**：机器码 + 卡密 → 计算/查表 → 返回真假（最容易被 patch）
   - **注册表缓存**：`RegQueryValueExA(HKCU\Software\xxx, "License")` → 解密 → 比对到期时间
   - **联网校验**：`WS2_32`/`WinINet`/`WinHTTP` → 服务器返回 JSON/结构体 → 本地验签

### 5.3 联网校验（卡密服务器）的抓法

```text
x32dbg 断点：
bpx WS2_32.send
bpx WS2_32.recv
bpx InternetReadFile          // WinINet
bpx WinHttpReadData           // WinHTTP
```

- 明文 HTTP：直接在缓冲区里看到请求/响应（`dump esp+...` 或用 `ScyllaHide` 的 `Log API`）
- HTTPS：断在上面的 API 上，读到的就是**已解密**的明文（TLS 在库内部完成）
- 做法：**一次输错卡密、一次输对卡密**，两次响应 diff →
  响应里必然有一个 `status/code/expire/hmac` 字段被本地比较，
  顺着这个字段的内存地址反查谁在读它 → 那个 `cmp/jz` 就是门

---

## 7. 第 6 步：打补丁（三种粒度，按稳的先用）

### 粒度 1：改跳转（最稳，副作用最小）

```bash
# 门在 RVA 0x451234，是 jz/jnz/je/jne
python3 tools/delphi_gate.py --exe hwid_dumped_SCY.exe --jmp-always 0x451234
```

效果：`74 05` → `EB 05`（`0F 84` → `E9` + `90`），把"未激活分支"整段跳过。

### 粒度 2：让校验函数恒返回真

```bash
# 校验函数入口 RVA 0x450F00
python3 tools/delphi_gate.py --exe hwid_dumped_SCY.exe --force-true 0x450F00
```

效果：函数头被写成 `B0 01 C3`（`mov al,1; ret`）。

> ⚠️ VCL 函数常用 `register` 调用约定且会 `push/pop ebx,esi,edi`；
> 直接从函数头返回会让**调用者的栈平衡出问题**（表现为退出时崩）。
> 出现这种情况改用粒度 1，或把 `--force-true` 打在"包一层"的外层函数上。

### 粒度 3：连到期时间一起干掉

```bash
# 把"比较到期时间"的 cmp 之后那条 jg/jl 也改掉
python3 tools/delphi_gate.py --exe hwid_dumped_SCY.exe --jmp-always 0x4518A0
# 或者直接把 GetSystemTime→比较 的整段 NOP
python3 tools/delphi_gate.py --exe hwid_dumped_SCY.exe --nop 0x451880:24
```

### 批量补丁（一次打好几处）

```
# patches.txt
0x451234 EB     # 跳过"未激活"分支
0x450F00 B001C3 # 校验函数恒真
```
```bash
python3 tools/delphi_gate.py --exe hwid_dumped_SCY.exe --apply patches.txt
```

每次打补丁都会：备份 `<exe>.bak` + 生成 `<exe>.patchlog.json`（记录 RVA/文件偏移/原字节/新字节）。

### 另一条更省事的路：注册表预置

如果程序把授权状态缓存在注册表（导入表里有 `RegQueryValueA/RegSetValueExA` 就是这个信号）：

1. 在一台**已合法激活**的机器上导出：`reg export "HKCU\Software\<厂商键>" lic.reg /y`
2. 在目标机双击 `lic.reg` 导入
3. 很多卡密工具此时直接进主界面（不联网/不校验机器码的版本尤其如此）

---

## 8. 第 7 步：验收清单（每条都要过）

```text
[ ] 断网启动：能进主界面（说明不依赖服务器每次校验）
[ ] 联网启动：不弹"卡密失效/未授权/已过期"
[ ] 输入任意错误卡密：仍然进主界面（说明本地判定被绕过）
[ ] 功能页能点：不是只有壳起来、点功能就崩
[ ] 退出程序：任务管理器里没有残留进程、没有崩溃弹窗（栈平衡没坏）
[ ] 重启机器再跑一次：仍然可用（没被"一次激活"逻辑打回）
```

功能相关的补充：这类 HWID 工具的**核心功能常常依赖内核驱动/服务**（导入表里如果有
`CreateService`/`NtLoadDriver`/`StartServiceA` 就说明如此）。若脱壳后功能页仍提示"驱动加载失败"，
那是驱动签名/加载问题，和授权无关，别误判成没破解成功。

---

## 9. 第 8 步：交付物打包

```
HWIDMaster_cracked/
├── HWIDMaster.exe            # 脱壳+去校验的成品
├── HWIDMaster.exe.bak        # 打补丁前的脱壳原件
├── HWIDMaster.exe.patchlog.json
├── gates.json                # 门候选报告（含 RVA 与上下文）
├── 说明.txt                  # 哪几处改了什么、为什么、如何回滚
└── (可选) lic.reg            # 注册表预置方案
```

---

## 10. 附：x32dbg 常用脚本片段

```text
// ---- oep_break.txt：壳解密后断在原 .text ----
bpx VirtualProtect
bpx VirtualAlloc
bpx GetModuleHandleA
run

// ---- net_check.txt：抓卡密服务器的收发 ----
bpx WS2_32.send
bpx WS2_32.recv
bpx InternetReadFile
run

// ---- at_gate.txt：到门之后逐条验证 ----
// Ctrl+G 跳到门地址 → F2 下断 → 改 ZF / 直接改 EIP 试跑
```

常用快捷键：`F2` 断点 / `F4` 运行到光标 / `F7` 单步进入 / `F8` 单步跳过 /
`F9` 运行 / `Ctrl+F9` 执行到返回 / `Ctrl+G` 跳到地址 / `Alt+M` 内存映射 /
`空格` 改指令/汇编（打补丁可直接在内存里试，验证通过再落到文件上）。
