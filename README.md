# HWIDMaster-0902 破甲 / 逆向 工作区

目标：把 `HWIDMaster-0902.exe` 逆向成不依赖激活码的可用程序。

## 目录

```
HWIDMaster-0902_re/
├── samples/HWIDMaster-0902.exe          # 原始样本（MD5 6e52de4aeb2a760d5453e354e18bac41）
├── docs/
│   ├── 01_分析报告.md                   # 静态解剖结论 + 证据链
│   ├── 02_Windows脱壳与破解手册.md       # 可照打的操作手册（脱壳→修IAT→找门→打补丁→验收）
│   └── 03_没有Windows怎么办.md           # 四条替代路线（GH Actions 免费 / 云主机 / UTM / Docker+Wine）
├── .github/workflows/win-probe.yml      # 免费 Windows runner 上跑 EP 矩阵 + 抓内存转储
├── scripts/win_probe.ps1                # 上述 workflow 的实际干活脚本
├── out/                                # 已生成的 EP 修复候选（可直接双击试）
├── tools/
│   ├── pe_triage.py                     # PE 体检/壳判定（PLAIN / PACKED / ENCRYPTED_PAYLOAD）
│   ├── dump2exe.py                      # 内存转储 → 可执行 PE（离线版 Scylla section 部分）
│   ├── set_ep.py                        # 改 PE 入口点（EP 被改坏的样本，5 分钟试探）
│   └── delphi_gate.py                   # VCL 程序"激活码/卡密"判定门定位 + 打补丁
├── tests/
│   ├── make_fixture.py                  # 造一个带"假激活校验"的 PE + 假内存转储，用于验证工具链
│   ├── fixture_license.exe
│   └── fixture_dump.bin
└── results/
    ├── triage.json                      # 本样本体检结果
    └── fixture_gates.json               # 工具链自测结果
```

## 当前结论（详见 docs/01）

`HWIDMaster-0902.exe` 是**虚拟机型壳（VMProtect 一类）保护 + 入口点被改写**的样本：

- 原程序 4 个段（`.text/.rdata/.data/.z{+`）的 `SizeOfRawData` 全为 0 —— 内容不在文件里
- 43 MB 的 `.KPx` 熵 7.99，是真加密（zlib/LZMA 全解不开，IoC 无周期 → 非重复密钥 XOR）
- **壳 stub 是明文的，在 `.KPx` 尾部**：382 个 4 KB 窗口 100% 可解码、
  `not/neg/rol/ror/bts/btc` 占 42%、`[esp+reg*4-imm]` VM 栈访问 → RVA ≈ `0x5191000~0x53B0000`
- **但 PE 头 EP = `0x2AF1DD3`，指向密文区**（与 stub 相差 40 MB），连续可解码仅 0.61%
- 结论：Windows 跳到 EP 就执行到垃圾字节 → 现文件无法直接运行

处置顺序：① 改 EP 回到 stub 区试跑（`tools/set_ep.py`）→ ② 要能跑的版本/loader →
③ 运行时内存转储（`tools/dump2exe.py`）→ ④ `tools/delphi_gate.py` 找门打补丁。

## 继续所需（三选一）

1. **双击能起界面的同款版本**（哪怕是试用版）→ 直接进 `docs/02` 第 1 步
2. **Windows 上一次运行时内存转储**（`procdump -ma`）→ `tools/dump2exe.py`
3. **卖家给的启动器 / 完整安装包** → 分析与爆破对象换成 loader

## 工具链自测

```bash
python3 tests/make_fixture.py              # 生成假样本 + 假转储
python3 tools/delphi_gate.py --exe tests/fixture_license.exe
#   → 命中"激活码无效"@0x2000，引用点 0x100b push imm32
#   → 门候选 0x1017  je 0x40101e   前文: call 0x401030 ; test al, al
python3 tools/dump2exe.py --dump tests/fixture_dump.bin --base 0x400000 --out /tmp/fx.exe
#   → 启发式找到 OEP 0x1000，重建 PE 通过 pe_triage 判定为 PLAIN
```

## 用法速查

```bash
# 体检
python3 tools/pe_triage.py <exe> --json out.json

# 内存转储 → PE
python3 tools/dump2exe.py --dump mem.dmp --base 0x400000 --out unpacked.exe \
        [--oep 0x401234] [--drop-shell] [--report]

# 找激活门（只分析）
python3 tools/delphi_gate.py --exe unpacked.exe --json gates.json --top 40

# 打补丁
python3 tools/delphi_gate.py --exe unpacked.exe --jmp-always 0x451234
python3 tools/delphi_gate.py --exe unpacked.exe --force-true 0x450F00
python3 tools/delphi_gate.py --exe unpacked.exe --nop 0x451880:24
python3 tools/delphi_gate.py --exe unpacked.exe --apply patches.txt
```

补丁自动备份 `.bak`，并写 `.patchlog.json`（RVA / 文件偏移 / 原字节 / 新字节），可回滚。
