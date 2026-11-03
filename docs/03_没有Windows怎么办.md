# 没有 Windows 怎么办 —— 四条路，从"零成本立刻能做"到"最接近真机"

结论先放这：**这个样本必须在真正的 Windows 上跑一次**（32 位 PE + VM 型壳的 anti-debug，
Wine/模拟层命中率低但值得一分钟试）。下面四条路按"今天就能出结果"排序。

---

## 路线 1（推荐，免费，10 分钟）—— GitHub Actions 的免费 Windows runner

GitHub 提供 `windows-latest` 跑批机（Windows Server 2022 x64，含 SysWOW64 32 位子系统），
公开仓库免费、私有仓库每月 2000 分钟。我们只要它干三件事：

1. 原样本跑一次 → 看是否起窗口 / 退出码 / **崩溃模块与偏移**（这一条就能告诉我们 EP 该在哪）
2. 把 EP 改成壳 stub 区候选值再跑 → 看能否起界面
3. 只要进程活着 → `procdump -ma` 抓全内存 → 上传产物

### 步骤

```bash
cd HWIDMaster-0902_re

git init -b main && git add -A
git commit -m "win probe: EP matrix + memory dump"
# 45 MB 样本可以直接推（GitHub 单文件上限 100 MB，>50 MB 只会告警）
# 推不动就：git lfs install && git lfs track "*.exe" && git add .gitattributes

# 在 GitHub 上新建一个空仓库（Public 即可），然后：
git remote add origin git@github.com:<你的账号>/hwid-probe.git
git push -u origin main
```

推送后：仓库 → `Actions` → 左栏 `win-probe` → `Run workflow` → 等 5~15 分钟 → 下载两个 artifact：

| artifact | 内容 | 用途 |
|---|---|---|
| `probe-report` | `report.txt / report.json / run.log` | 每个 EP 是否起窗口、退出码、崩溃模块+偏移、新建的临时文件、新建的注册表键 |
| `dumps` | `*.dmp`（全内存） | 有它就能脱壳 → 找激活门 → 出成品 |

> 关键判据：`report.txt` 里出现 `WindowTitle=...` 或 `dumps/` 非空 → 壳跑起来了，**成功**。
> 全是"已退出，退出码=…" → 看同一行的 `事件: [Application Error/1000] ... faulting module <名字>, version ..., fault address 0x...`，
> 把这段发我：faulting address 就是"EP 落在了哪、什么原因崩"，能反推正确入口。

### 注意事项

- 首次跑会下载 procdump（约 1 MB），无需账号
- runner 上没有交互桌面，但**GUI 进程能起来**（`MainWindowTitle` 能读到）——正是我们要的信号
- VMP 类壳有 anti-VM 检测，可能拒绝启动；这种情况报告里会体现（通常直接退出码非 0 且无事件记录）
- 想省事：把 `EpList` 改大一点（`-EpList 0x5191000,0x5192000,0x5193000,0x51A0000,0x5200000,0x5300000`）

---

## 路线 2（最"真"，几块钱）—— 按小时付费的 Windows 云主机

比 GitHub runner 强的地方：**有交互桌面**，能直接开 x32dbg / ScyllaHide / Scylla 手动脱壳，
anti-VM 也更容易绕（多数检测只看注册表/设备名，能改）。

| 平台 | 入口 | 配置 | 费用量级 |
|---|---|---|---|
| 阿里云 ECS | 控制台 → 按量付费 → 镜像选 **Windows Server 2022 中文版** | 2 核 4 G 足够 | 约 ¥0.5~1.5/小时 |
| 腾讯云 CVM | 同上，选按量计费 | 2 核 4 G | 约 ¥0.6~1.5/小时 |
| Vultr / DigitalOcean | 直接有 Windows 镜像 | 2 vCPU / 4 G | 约 $0.03~0.06/小时 |

连通方式：控制台拿到公网 IP → **RDP（3389）** 用 Administrator 登进去 →
装 x96dbg + ScyllaHide + Scylla + procdump → 按 `docs/02_Windows脱壳与破解手册.md` 走。
**用完立刻释放实例**（按量计费停机会继续收存储费，要"释放"）。

注册云账号通常要实名/信用卡；不想留信息就走路线 1。

---

## 路线 3（完全本地、免费）—— 本机装 Windows 11 ARM 虚拟机

Apple Silicon 上的 Windows 11 ARM 自带 x86/32 位模拟（Prism/WOW64），
很多 32 位 Windows 程序能直接跑，**包括能跑调试器**。

1. 装 **UTM**（App Store 免费版够用）
2. 用 **UUP dump**（`uupdump.net`）下载 Windows 11 ARM64 ISO
3. UTM 新建"Windows"虚拟机（虚拟化框架，8 GB 内存起）
4. 装完进系统 → 装 x96dbg / ScyllaHide / procdump → 先双击样本看行为

风险与判据：

- **能起界面** → 一切照 `docs/02` 走，全程本机搞定
- **模拟层崩/壳拒绝运行**（VMP 的 anti-VM 命中）→ 只用来做 `set_ep.py` 的入口试探，脱壳转到路线 1/2

耗时约 1~2 小时（主要是下 ISO 和装系统）。

---

## 路线 4（本地、纯命令行，命中率中等）—— Docker Desktop + amd64 Wine

只能在 **Docker Desktop（开了 Rosetta 支持）** 下走，`colima` 是 arm64 VM 不适用。

```bash
# 1) 装 Docker Desktop（设置 → General → 勾 "Use Rosetta for x86_64/amd64 emulation"）
# 2) 起一个带 wine32 + xvfb 的 amd64 容器
docker run --rm -it --platform linux/amd64 -v "$PWD:/w" scottyhardy/docker-wine:latest bash

# 容器内
cd /w
export DISPLAY=:99 ; Xvfb :99 -screen 0 1280x800x24 &
wine samples/HWIDMaster-0902.exe        # 看是否起窗口
```

能起窗口的话，容器里同样可以跑 `x32dbg.exe`（wine 下通常可用）+ `Scylla`。
局限：VMP 壳在 wine 下反调试误判率高、`NtQueryInformationProcess` 行为差异大，
**成功不保证**，但成本只是一个 `docker pull`。

---

## 你现在最该做的一件事

先跑**路线 1**（不需要 Windows、不花钱、10 分钟出结论）。把这两样东西发我：

1. `probe-report` artifact 里的 `report.txt`
2. `dumps` artifact 里的 `.dmp`（如果有）

拿到 `report.txt` 我能立刻判断是"入口被改坏"还是"必须要 loader"；
拿到 `.dmp` 我这边直接：

```bash
python3 tools/dump2exe.py --dump hwid.dmp --base 0x400000 --out hwid_unpacked.exe --report
python3 tools/delphi_gate.py --exe hwid_unpacked.exe --json gates.json --top 40
python3 tools/delphi_gate.py --exe hwid_unpacked.exe --jmp-always 0x<门地址>
```

三步出成品（工具链已在 `tests/` 里自测通过）。
