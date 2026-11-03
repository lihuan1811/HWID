#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
set_ep.py —— 改 PE 入口点（AddressOfEntryPoint），用于"EP 被剥离/改写"的样本试探

场景：`HWIDMaster-0902.exe` 的 VM 壳 stub 明文躺在 .KPx 尾部（VA≈0x5191000~0x5389000），
但头部 EP=0x2AF1DD3 指向密文区。把 EP 指回 stub 区，有可能直接跑起来。

用法：
    python3 set_ep.py <exe> <新EP(RVA或VA)> [--va] [--out 新文件] [--show]
    例：
    python3 set_ep.py samples/HWIDMaster-0902.exe 0x5191000 --va --out /tmp/ep_test.exe
    python3 set_ep.py x.exe 0x12345            # 当 RVA 用
    python3 set_ep.py x.exe --show             # 只看当前 EP
"""
import sys, struct, shutil, os


def load(path):
    d = bytearray(open(path, 'rb').read())
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    if d[pe:pe + 4] != b'PE\0\0':
        raise SystemExit('[-] 不是 PE')
    opt = pe + 24
    magic = struct.unpack_from('<H', d, opt)[0]
    is64 = magic == 0x20b
    ib = struct.unpack_from('<Q' if is64 else '<I', d, opt + (24 if is64 else 28))[0]
    ep = struct.unpack_from('<I', d, opt + 16)[0]
    return d, opt, ib, ep


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    d, opt, ib, ep = load(path)
    if '--show' in sys.argv or len(sys.argv) < 3:
        print(f'[i] ImageBase={ib:#x}  当前 EP(RVA)={ep:#x}  即 VA={ib + ep:#x}')
        return
    val = int(sys.argv[2], 0)
    as_va = '--va' in sys.argv
    rva = val - ib if as_va else val
    out = path
    if '--out' in sys.argv:
        out = sys.argv[sys.argv.index('--out') + 1]
    if out == path and not os.path.exists(path + '.bak'):
        shutil.copy2(path, path + '.bak')
        print(f'[+] 备份 → {path}.bak')
    struct.pack_into('<I', d, opt + 16, rva)
    struct.pack_into('<I', d, opt + 64, 0)      # 校验和清零
    open(out, 'wb').write(bytes(d))
    print(f'[+] EP: {ep:#x} → {rva:#x} (VA {ib + rva:#x})，写入 {out}')
    print('    在 Windows 上双击试；起不来就换附近地址（每 0x1000 试一个）')


if __name__ == '__main__':
    main()
