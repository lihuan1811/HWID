#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
decrypt_coverage.py —— 逐段比对"内存镜像 vs 磁盘原文"，算出壳解密了多少

用法：
    python3 tools/decrypt_coverage.py --img mem.bin --orig samples/HWIDMaster-0902.exe \
            [--json cov.json]

判据（每段）：
    changed% ≈ 0    → 这段还是磁盘原样（**没解密**）
    changed% 高      → 这段在内存里已被改写（**解密/重定位完成**）
    另外给熵：熵≈8 仍然是密文；熵 4~6.8 像代码/数据
"""
import sys, struct, math, collections, json


def _utf8_stdout():
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


_utf8_stdout()


def ent(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def sections_of_orig(path):
    d = open(path, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    soh = struct.unpack_from('<H', d, pe + 20)[0]
    opt = pe + 24
    secoff = opt + soh
    out = []
    for i in range(nsec):
        o = secoff + i * 40
        name = d[o:o + 8].rstrip(b'\0').decode('latin1', 'replace')
        vs, va, rs, ra = struct.unpack_from('<IIII', d, o + 8)
        out.append(dict(name=name, va=va, vs=vs, ra=ra, rs=rs,
                        data=d[ra:ra + rs] if rs else b''))
    return d, out


def main():
    ap_img = sys.argv[sys.argv.index('--img') + 1]
    ap_orig = sys.argv[sys.argv.index('--orig') + 1]
    out = sys.argv[sys.argv.index('--json') + 1] if '--json' in sys.argv else None

    img = open(ap_img, 'rb').read()
    orig, secs = sections_of_orig(ap_orig)
    print(f'镜像 {ap_img}  {len(img):,} 字节')
    print(f'原文 {ap_orig}  {len(orig):,} 字节')
    print(f'{"段":<10}{"大小":>12}{"改写字节":>12}{"改写率":>9}{"镜像熵":>8}{"原文熵":>8}   判读')
    rows = []
    for s in secs:
        va, vs = s['va'], s['vs']
        mem = img[va:va + vs] if va + vs <= len(img) else b''
        dis = s['data']
        if not dis and not mem:
            rows.append(dict(name=s['name'], note='文件与内存都无数据'))
            print(f'{s["name"]:<10}{vs:>12,}{"-":>12}{"-":>9}{"-":>8}{"-":>8}   无数据')
            continue
        n = min(len(mem), len(dis))
        if n == 0:
            print(f'{s["name"]:<10}{vs:>12,}{"-":>12}{"-":>9}{ent(mem):>8.2f}{"-":>8}   仅内存有数据')
            rows.append(dict(name=s['name'], va=hex(va), size=vs,
                             img_ent=round(ent(mem), 3), changed=None,
                             note='文件里没有这段的原始字节（磁盘上 raw=0）'))
            continue
        diff = sum(1 for i in range(n) if mem[i] != dis[i])
        rate = diff / n
        mi, di = ent(mem), ent(dis)
        if rate < 0.01:
            verdict = '未解密（与磁盘完全一致）'
        elif rate > 0.9:
            verdict = '已完全改写（解压/解密/重定位完成）' if mi < 7.9 else '已改写但仍高熵（可能是压缩数据）'
        else:
            verdict = '部分改写'
        print(f'{s["name"]:<10}{vs:>12,}{diff:>12,}{rate:>8.1%}{mi:>8.2f}{di:>8.2f}   {verdict}')
        rows.append(dict(name=s['name'], va=hex(va), size=vs, compared=n,
                         changed=diff, rate=round(rate, 4),
                         img_ent=round(mi, 3), orig_ent=round(di, 3), verdict=verdict))
    if out:
        json.dump(dict(img=ap_img, orig=ap_orig, sections=rows),
                  open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
        print(f'[+] → {out}')


if __name__ == '__main__':
    main()
