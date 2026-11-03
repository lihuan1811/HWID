#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
trace_const_pool.py —— 易语言(VCL 同理)程序的"字符串→常量池→代码"指针链追踪

易语言代码不直接 push 字符串地址，而是 push 常量池里的**指针槽地址**。
所以两步：
  1) 在镜像里找 dword == 字符串VA 的位置 → 得到"指针槽"s
  2) 在代码段找引用槽地址的指令（68 <槽VA> / A1 <槽VA> / B8+r <槽VA> / 8B modrm <槽VA>）
     → 得到"用到这个字符串的代码位置"
输出每条链，并把命中点附近的 test/cmp + jcc 列为候选"门"。

用法：
  python3 tools/trace_const_pool.py --exe work/dumped.exe --str 程序将在五秒后关闭 --json out.json
  python3 tools/trace_const_pool.py --exe work/dumped.exe --kw 卡密,过期,五秒
"""
import sys, struct, json, argparse


def _u():
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


_u()

JCC = {0x70: 'jo', 0x71: 'jno', 0x72: 'jb', 0x73: 'jae', 0x74: 'jz', 0x75: 'jnz',
       0x76: 'jbe', 0x77: 'ja', 0x78: 'js', 0x79: 'jns', 0x7A: 'jp', 0x7B: 'jnp',
       0x7C: 'jl', 0x7D: 'jge', 0x7E: 'jle', 0x7F: 'jg'}


def parse(path):
    d = open(path, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    soh = struct.unpack_from('<H', d, pe + 20)[0]
    opt = pe + 24
    ib = struct.unpack_from('<I', d, opt + 28)[0]
    secoff = opt + soh
    secs = []
    for i in range(nsec):
        o = secoff + i * 40
        name = d[o:o + 8].rstrip(b'\0').decode('latin1', 'replace')
        vs, va, rs, ra = struct.unpack_from('<IIII', d, o + 8)
        ch = struct.unpack_from('<I', d, o + 36)[0]
        secs.append(dict(name=name, va=va, vs=vs, ra=ra, rs=rs, ch=ch,
                         data=d[ra:ra + rs] if rs else b''))
    return d, ib, secs


def find_kw(secs, ib, kw):
    pat = kw.encode('gbk')
    out = []
    for s in secs:
        if s['ch'] & 0x20000000 or not s['data']:
            continue
        start = 0
        while True:
            i = s['data'].find(pat, start)
            if i < 0:
                break
            start = i + 1
            raw = s['data'][i:i + 160].split(b'\0')[0]
            try:
                txt = raw.decode('gbk')
            except Exception:
                txt = raw.decode('latin1', 'replace')
            out.append(dict(rva=s['va'] + i, va=ib + s['va'] + i, text=txt, sec=s['name']))
    return out


def find_slots(secs, va):
    """找 dword == va 的所有位置（= 指针槽）"""
    pat = struct.pack('<I', va)
    slots = []
    for s in secs:
        if not s['data'] or (s['ch'] & 0x20000000):
            continue
        start = 0
        while True:
            i = s['data'].find(pat, start)
            if i < 0:
                break
            start = i + 1
            slots.append(dict(rva=s['va'] + i, va=va, sec=s['name']))
    return slots


def find_refs(secs, slot_va):
    """在代码段找引用槽地址的指令"""
    hits = []
    p = struct.pack('<I', slot_va)
    pats = [b'\x68' + p, b'\xA1' + p]
    pats += [bytes([op]) + p for op in range(0xB8, 0xC0)]
    pats += [b'\x8D' + bytes([m]) + p for m in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D)]
    pats += [b'\x8B' + bytes([m]) + p for m in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D)]
    pats += [b'\xFF\x15' + p, b'\xFF\x25' + p]
    for s in secs:
        if not (s['ch'] & 0x20000000) or not s['data']:
            continue
        for pat in pats:
            start = 0
            while True:
                i = s['data'].find(pat, start)
                if i < 0:
                    break
                start = i + 1
                hits.append(dict(rva=s['va'] + i, sec=s['name'], kind=pat[:2].hex()))
    return hits


def gates_near(code, off, span=0x50):
    out = []
    lo, hi = max(0, off - span), min(len(code), off + span)
    for i in range(lo, hi):
        b = code[i]
        if b in JCC:
            prev = code[max(0, i - 3):i]
            has_cmp = any(x in (0x85, 0x3B, 0x39, 0x83, 0x84, 0x3D) for x in prev)
            out.append(dict(off=i, jcc=JCC[b], bytes=code[i:i + 2].hex(),
                            has_cmp=has_cmp, dist=abs(i - off),
                            score=(40 if has_cmp else 0) + (10 if JCC[b] in ('jz', 'jnz') else 0) - min(abs(i - off) // 4, 20)))
    out.sort(key=lambda x: -x['score'])
    return out[:4]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', required=True)
    ap.add_argument('--kw', default='程序将在五秒后关闭,帐号过期,内部错误,别处登录,点数不足,软件维护中,停止运营,帐号被锁定,卡密')
    ap.add_argument('--json')
    a = ap.parse_args()

    d, ib, secs = parse(a.exe)
    print(f'===== {a.exe} ImageBase={ib:#x} =====')
    report = []
    for kw in [k.strip() for k in a.kw.split(',') if k.strip()]:
        strs = find_kw(secs, ib, kw)
        if not strs:
            print(f'\n[{kw}] 镜像里没有这个字符串')
            continue
        print(f'\n########## [{kw}] 命中 {len(strs)} 个字符串 ##########')
        for s in strs[:3]:
            print(f"  字符串 @RVA {s['rva']:#x}  {s['text'][:60]!r}")
            slots = find_slots(secs, s['va'])
            print(f"    指针槽 {len(slots)} 个: {[hex(x['rva']) for x in slots[:5]]}")
            for sl in slots[:6]:
                refs = find_refs(secs, ib + sl['rva'])
                if not refs:
                    continue
                print(f"    槽 {sl['rva']:#x} 被 {len(refs)} 处代码引用:")
                for r in refs[:6]:
                    sec = next(x for x in secs if x['name'] == r['sec'])
                    code = sec['data']
                    off = r['rva'] - sec['va']
                    gs = gates_near(code, off)
                    print(f"      → 代码 RVA {r['rva']:#x}  ({r['kind']})")
                    for g in gs:
                        aob = code[max(0, g['off'] - 6):g['off'] + 8].hex()
                        print(f"          门 {sec['va'] + g['off']:#x}  {g['jcc']:<4} cmp={g['has_cmp']}  AOB={aob}")
                        report.append(dict(kw=kw, string_rva=hex(s['rva']), slot=hex(sl['rva']),
                                           ref=hex(r['rva']), gate=hex(sec['va'] + g['off']),
                                           jcc=g['jcc'], has_cmp=g['has_cmp'], aob=aob))
    if a.json:
        json.dump(report, open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
        print(f'\n[+] 候选门 {len(report)} 条 → {a.json}')


if __name__ == '__main__':
    main()
