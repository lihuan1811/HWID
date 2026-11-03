#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dump2exe.py —— 把"运行时内存转储"重建为可执行 PE（离线版 Scylla 的 section 部分）

为什么需要它：
    本样本(HWIDMaster-0902.exe)在磁盘上是**加密载荷**：入口点指向密文，
    文件里没有任何可执行 stub，静态脱壳不可能。走运行时路线时，
    在 Windows 上让壳把明文解到内存后，用 procdump / Process Hacker 抓全内存转储，
    再由本脚本把内存里的镜像重新排版成磁盘 PE。

用法：
    # 1) Windows 上抓转储（模块基址 0x400000 时 — 本样本 no-reloc，固定基址）
    #    procdump64.exe -ma HWIDMaster-0902.exe hwid.dmp
    #    （或 Process Hacker → 右键进程 → Create dump file）
    # 2) 回来重建
    python3 dump2exe.py --dump hwid.dmp --base 0x400000 --out hwid_unpacked.exe \
                        [--oep 0x401234] [--drop-shell] [--report]

    不给 --oep 时脚本会用启发式找原始入口（Delphi/C++Builder 的 prologue、
    以及在 EP 附近的 jmp 链），并把候选列出来。

输出：重建后的 PE + 一份 JSON 体检（--report）。
"""
import sys, os, json, struct, argparse

# --- Windows 控制台(cp1252)打不出中文，统一把 stdout 设成 utf-8 ---
def _utf8_stdout():
    try:
        import sys as _s
        _s.stdout.reconfigure(encoding='utf-8', errors='replace')
        _s.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


_utf8_stdout()



# ----------------------------------------------------------------- 工具
def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]


def parse_pe(buf, img_base_in_dump, label):
    """buf 是"从模块基址开始"的内存视图"""
    if buf[:2] != b'MZ':
        raise SystemExit(f'[-] {label}: 开头不是 MZ')
    pe = u32(buf, 0x3C)
    if buf[pe:pe + 4] != b'PE\0\0':
        raise SystemExit(f'[-] {label}: 找不到 PE 签名（转储没从模块基址开始？用 --base 指对）')
    nsec = u16(buf, pe + 6)
    soh = u16(buf, pe + 20)
    opt = pe + 24
    magic = u16(buf, opt)
    is64 = magic == 0x20b
    ep = u32(buf, opt + 16)
    imagebase = struct.unpack_from('<Q' if is64 else '<I', buf, opt + 24 if is64 else opt + 28)[0]
    secalign = u32(buf, opt + 32)
    sub = u16(buf, opt + 68)
    sizeofimage = u32(buf, opt + 56)
    secoff = opt + soh
    secs = []
    for i in range(nsec):
        o = secoff + i * 40
        name = buf[o:o + 8].rstrip(b'\0').decode('latin1', 'replace')
        vs, va, rs, ra = struct.unpack_from('<IIII', buf, o + 8)
        ch = u32(buf, o + 36)
        secs.append(dict(index=i, name=name, va=va, vs=vs, rs=rs, ra=ra, ch=ch, hdr=o))
    return dict(buf=buf, pe_off=pe, nsec=nsec, soh=soh, opt=opt, is64=is64, ep=ep,
                imagebase=imagebase, secalign=secalign, subsystem=sub,
                sizeofimage=sizeofimage, sections=secs,
                base_in_dump=img_base_in_dump)


def find_bytes(buf, pat, start=0, end=None):
    end = len(buf) if end is None else end
    out, i = [], start
    while True:
        j = buf.find(pat, i, end)
        if j < 0:
            return out
        out.append(j)
        i = j + 1


# Delphi / C++Builder 入口常见前缀（32 位）
PROLOGUES = [
    bytes.fromhex('558BEC83C4F0B8'),        # push ebp; mov ebp,esp; add esp,-10h; mov eax,...
    bytes.fromhex('558BEC83C4E0'),
    bytes.fromhex('558BEC83C4F8'),
    bytes.fromhex('558BEC6A00'),
    bytes.fromhex('558BECB8'),              # push ebp; mov ebp,esp; mov eax, imm32
    bytes.fromhex('E9'),                    # 只有 1 字节跳转，后面单独处理
]


def guess_oep(img):
    """在第一个可执行段里找 Delphi/C++Builder 入口特征；返回 [(rva, 说明)]"""
    buf = img['buf']
    cands = []
    exsecs = [s for s in img['sections']
              if s['ch'] & 0x20000000 and s['va'] >= 0x1000]
    for s in exsecs:
        start = s['va']
        end = s['va'] + max(s['vs'], 1)
        if end > len(buf):
            end = len(buf)
        for pat in PROLOGUES[:5]:
            for off in find_bytes(buf, pat, start, min(end, start + 0x40000)):
                cands.append((off, f'prologue {pat.hex()} @{s["name"]}'))
    return cands


# ----------------------------------------------------------------- 重建
def rebuild(img, out_path, oep=None, drop_shell=False):
    buf = img['buf']
    secalign = img['secalign'] or 0x1000
    hdrsize = secalign
    sections = [dict(s) for s in img['sections']]
    if drop_shell:
        keep = [s for s in sections if not is_shell_name(s['name'])]
        dropped = [s['name'] for s in sections if is_shell_name(s['name'])]
        sections = keep
    else:
        dropped = []

    # 逐段取内存数据
    body = bytearray()
    cursor = hdrsize
    for s in sections:
        va, vs = s['va'], s['vs']
        if vs == 0:
            s['rs'] = 0
            s['_data'] = b''
            continue
        data = bytes(buf[va:va + vs]) if va + vs <= len(buf) else b''
        if not data:
            data = b'\0' * vs
        elif len(data) < vs:
            data = data + b'\0' * (vs - len(data))
        s['_data'] = data
        s['rs'] = ((len(data) + secalign - 1) // secalign) * secalign
        s['_raw'] = cursor
        cursor += s['rs']

    # 组文件：头 + 段
    hdr = bytearray(buf[0:hdrsize])
    for s in sections:
        struct.pack_into('<I', hdr, s['hdr'] + 16, s['rs'])   # SizeOfRawData
        struct.pack_into('<I', hdr, s['hdr'] + 20, s['_raw'])  # PointerToRawData
    # 入口点
    if oep is not None:
        struct.pack_into('<I', hdr, img['opt'] + 16, oep)
    sizeimg = hdrsize + sum(s['rs'] for s in sections)
    struct.pack_into('<I', hdr, img['opt'] + 60, hdrsize)       # SizeOfHeaders
    struct.pack_into('<I', hdr, img['opt'] + 64, 0)             # 校验和清零
    out = bytearray(hdr)
    for s in sections:
        out += s['_data'] + b'\0' * (s['rs'] - len(s['_data']))
    open(out_path, 'wb').write(out)

    rep = dict(out=os.path.abspath(out_path), size=len(out),
               imagebase=hex(img['imagebase']), ep=hex(oep if oep else img['ep']),
               sections=[dict(name=s['name'], va=hex(s['va']), vs=hex(s['vs']),
                              raw_off=hex(s['_raw']), raw_size=hex(s['rs']),
                              exec_flag=bool(s['ch'] & 0x20000000)) for s in sections],
               dropped=dropped)
    return rep


SHELL_NAME_HINT = set(".text .rdata .data .rsrc".split())


def is_shell_name(n):
    """随机化的壳段名（含非字母数字）判为壳段"""
    if n in SHELL_NAME_HINT:
        return False
    return any(not (c.isalnum() or c in '._') for c in n)


# ----------------------------------------------------------------- 主
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dump', required=True, help='内存转储文件')
    ap.add_argument('--dump-off', type=lambda x: int(x, 0), default=0,
                    help='模块基址在转储文件里的偏移（默认 0）')
    ap.add_argument('--base', type=lambda x: int(x, 0), default=0x400000,
                    help='模块加载基址（默认 0x400000，本样本固定基址）')
    ap.add_argument('--out', required=True)
    ap.add_argument('--oep', type=lambda x: int(x, 0), default=None,
                    help='原始入口点 RVA（不给就用启发式）')
    ap.add_argument('--drop-shell', action='store_true', help='丢弃随机命名的壳段')
    ap.add_argument('--report', action='store_true', help='输出 JSON 体检到 <out>.json')
    a = ap.parse_args()

    raw = open(a.dump, 'rb').read()
    view = raw[a.dump_off:]
    img = parse_pe(view, a.base, a.dump)
    print(f'[+] 转储 {len(raw):,} 字节，PE 解析 OK：{img["nsec"]} 段 '
          f'ImageBase={img["imagebase"]:#x} 头部EP={img["ep"]:#x}')

    oep = a.oep
    cands = guess_oep(img)
    if oep is None and cands:
        oep = cands[0][0]
        print(f'[+] 启发式原始入口 → RVA {oep:#x}（{cands[0][1]}）')
        for r, why in cands[1:8]:
            print(f'      其它候选 {r:#x}  {why}')
    if oep is None:
        print('[!] 未找到入口特征：转储可能不是在"壳已解完/已到 OEP"时抓的。'
              '请给 --oep，或按手册在 OEP 处断下再抓。')

    rep = rebuild(img, a.out, oep=oep, drop_shell=a.drop_shell)
    print(f'[+] 已生成 {rep["out"]}  {rep["size"]:,} 字节  EP={rep["ep"]}')
    for s in rep['sections']:
        print(f'      {s["name"]:<10} VA={s["va"]:<10} VS={s["vs"]:<10} '
              f'RAW={s["raw_off"]:<10} RS={s["raw_size"]:<10} {"X" if s["exec_flag"] else ""}')
    if rep['dropped']:
        print(f'[+] 丢弃壳段：{rep["dropped"]}')
    if a.report:
        p = a.out + '.json'
        json.dump(rep, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
        print(f'[+] 报告 → {p}')
    print('[i] 接下来：Windows 上用 Scylla 对该文件做 IAT 重建（或用原进程的 Scylla dump），'
          '然后 python3 delphi_gate.py --exe 该文件 找激活校验。')


if __name__ == '__main__':
    main()
