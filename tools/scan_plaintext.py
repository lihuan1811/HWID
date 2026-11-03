#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_plaintext.py —— 在内存镜像 / PE 文件里扫"明文线索"，判断壳解密到哪一步

用法：
    python3 tools/scan_plaintext.py analysis/mem_crash.bin --json analysis/plain.json

输出：
  · GBK / UTF-16 关键词命中（激活、卡密、机器码、到期、license…）
  · 可打印字符串统计（含中文的最长若干条，直接看出是不是已经解出 UI 文案）
  · 逐 1MB 块的"可读度"（printable 占比），用于定位哪块内存已被解密
"""
import sys, re, json, collections, math


def _utf8_stdout():
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


_utf8_stdout()

KW = ['激活', '激活码', '卡密', '注册码', '机器码', '硬件码', '到期', '已过期', '试用',
      '未授权', '授权失败', '请先激活', '验证失败', '充值', '剩余天数',
      'license', 'expired', 'activation', 'machine', 'hwid', 'serial', 'trial',
      'SOFTWARE\\', 'CurrentVersion', 'AppData', 'ws2_32', 'WinHttp', 'WinINet',
      'spoof', 'disk', 'volume', 'SMBIOS', 'MAC', 'driver', 'CreateService']


def printable_ratio(b):
    if not b:
        return 0.0
    good = sum(1 for x in b if 0x20 <= x < 0x7f or x in (9, 10, 13))
    return good / len(b)


def main():
    path = sys.argv[1]
    out = None
    if '--json' in sys.argv:
        out = sys.argv[sys.argv.index('--json') + 1]
    d = open(path, 'rb').read()
    print(f'=== {path}  {len(d):,} 字节 ===')

    # 1) 关键词（GBK / UTF-16LE / ASCII 三种编码）
    hits = {}
    for k in KW:
        found = []
        for enc in ('gbk', 'utf-16-le', 'latin1'):
            try:
                pat = k.encode(enc, errors='ignore')
            except Exception:
                continue
            if len(pat) >= 2 and pat in d:
                found.append(enc)
        if found:
            hits[k] = found
    print(f'[+] 关键词命中 {len(hits)}/{len(KW)}')
    for k, v in list(hits.items())[:40]:
        print(f'    · {k!r}  编码={",".join(v)}')

    # 2) 中文可读串（GBK）
    zh = []
    for m in re.finditer(rb'(?:[\xb0-\xf7][\xa1-\xfe]){2,}', d):
        try:
            t = m.group().decode('gbk')
        except Exception:
            continue
        if len(t) >= 3:
            zh.append(t)
    uniq = list(dict.fromkeys(zh))
    print(f'[+] GBK 中文串 {len(zh)} 条（去重 {len(uniq)}）；示例：')
    for t in uniq[:25]:
        print(f'    · {t}')

    # 3) ASCII 长串（可能是类名/API/路径）
    asc = [m.group().decode('latin1') for m in re.finditer(rb'[\x20-\x7e]{10,}', d)]
    asc_u = list(dict.fromkeys(asc))
    print(f'[+] ASCII 串 {len(asc)} 条（去重 {len(asc_u)}）；其中最像程序用的大于 20 字符的 15 条：')
    picks = [a for a in asc_u if len(a) >= 20][:15]
    for a in picks:
        print(f'    · {a[:110]}')

    # 4) 逐块可读度
    blocks = []
    for i in range(0, len(d), 1 << 20):
        blk = d[i:i + (1 << 20)]
        blocks.append([round(i / 1048576, 1), round(printable_ratio(blk), 3)])
    readable = [b for b in blocks if b[1] > 0.05]
    print(f'[+] 可读度 >5% 的 1MB 块：{len(readable)}/{len(blocks)}')
    for b in readable[:20]:
        print(f'    · {b[0]:>6} MB  可读 {b[1]:.1%}')

    rep = dict(file=path, size=len(d), keyword_hits=hits,
               gbk_strings=uniq[:200], ascii_strings=asc_u[:200],
               readable_blocks=readable[:100])
    if out:
        json.dump(rep, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
        print(f'[+] 报告 → {out}')


if __name__ == '__main__':
    main()
