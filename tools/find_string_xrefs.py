#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
find_string_xrefs.py —— 在"已解密的易语言/VCL 程序"里，按字符串立即数反查引用点（不依赖完整反汇编）

原理：32 位程序引用字符串常量通常是 `68 <VA>`（push imm32）或 `B8+r <VA>` / `8D 0D <VA>`。
      直接按字节模式搜这些立即数即可，命中率高于 capstone 线性反汇编
      （易语言代码里会夹杂不能解码的字节，线性反汇编会中断）。

用法：
    python3 tools/find_string_xrefs.py --exe work/dumped.exe [--json out.json] [--kw 卡密,登录]

输出：
    每条命中：字符串 → 引用点 RVA → 附近的 test/cmp + jcc（"门"）→ 可直接用于运行期补丁的 AOB
"""
import sys, re, struct, json, argparse, collections


def _utf8():
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


_utf8()

DEFAULT_KW = ['卡密', '登录', '密码', '机器码', '到期', '过期', '授权', '充值', '点数',
              '五秒后关闭', '错误', '非法', '维护中', '停止运营', '别处登录', '锁定',
              '请输入', '验证', '成功', '失败', 'Error', 'VIP', '解码']

JCC = {0x70: 'jo', 0x71: 'jno', 0x72: 'jb', 0x73: 'jae', 0x74: 'jz', 0x75: 'jnz',
       0x76: 'jbe', 0x77: 'ja', 0x78: 'js', 0x79: 'jns', 0x7A: 'jp', 0x7B: 'jnp',
       0x7C: 'jl', 0x7D: 'jge', 0x7E: 'jle', 0x7F: 'jg'}
GATE_PREF = {'jz': 4, 'jnz': 4, 'je': 4, 'jne': 4, 'ja': 2, 'jae': 2, 'jb': 2, 'jbe': 2,
             'jg': 2, 'jge': 2, 'jl': 2, 'jle': 2}


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


def gbk_at(secs, rva, n=80):
    for s in secs:
        if s['va'] <= rva < s['va'] + len(s['data']):
            off = rva - s['va']
            raw = s['data'][off:off + n].split(b'\0')[0]
            try:
                return raw.decode('gbk'), s['name']
            except Exception:
                return raw.decode('latin1', 'replace'), s['name']
    return '', ''


def find_gates(code, pos, span=0x60):
    """在引用点附近找 test/cmp + jcc（不反汇编，直接找 jcc 字节）"""
    out = []
    lo = max(0, pos - span)
    hi = min(len(code), pos + span)
    for i in range(lo, hi):
        b = code[i]
        if b in JCC:
            # 排除误判：前一条指令通常是 test/cmp（85/3B/39/83/2D）
            prev = code[max(0, i - 3):i]
            has_cmp = any(x in (0x85, 0x3B, 0x39, 0x83, 0x84, 0x3D) for x in prev)
            out.append(dict(off=i, jcc=JCC[b], bytes=code[i:i + 2].hex(),
                            has_cmp=has_cmp, dist=abs(i - pos),
                            score=GATE_PREF.get(JCC[b], 0) * 10 + (15 if has_cmp else 0)
                                  - min(abs(i - pos) // 8, 15)))
        elif b == 0x0F and i + 1 < len(code) and 0x80 <= code[i + 1] <= 0x8F:
            out.append(dict(off=i, jcc='近条件跳转 0f8x', bytes=code[i:i + 6].hex(),
                            has_cmp=False, dist=abs(i - pos), score=5))
    out.sort(key=lambda x: -x['score'])
    return out[:5]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', required=True)
    ap.add_argument('--json')
    ap.add_argument('--kw', default='')
    ap.add_argument('--top', type=int, default=40)
    a = ap.parse_args()

    d, ib, secs = parse(a.exe)
    kws = [k.strip() for k in a.kw.split(',') if k.strip()] or DEFAULT_KW
    code_secs = [s for s in secs if s['ch'] & 0x20000000 and s['rs']]

    print(f'===== {a.exe}  ImageBase={ib:#x}  代码段: {[s["name"] for s in code_secs]} =====')

    # 1) 收集 .rdata/.data 里所有关键词字符串的地址
    targets = []
    for s in secs:
        if s['ch'] & 0x20000000:
            continue
        for kw in kws:
            pat = kw.encode('gbk')
            start = 0
            while True:
                i = s['data'].find(pat, start)
                if i < 0:
                    break
                start = i + 1
                rva = s['va'] + i
                txt, where = gbk_at(secs, rva, 120)
                targets.append(dict(kw=kw, rva=rva, va=ib + rva, sec=s['name'], text=txt))
    uniq = {}
    for t in targets:
        uniq.setdefault((t['kw'], t['rva']), t)
    targets = list(uniq.values())
    print(f'[+] 关键词字符串 {len(targets)} 条')

    # 2) 在代码段里搜 push imm32 / mov reg,imm32 / lea / mov eax,[imm32]
    results = []
    for t in targets:
        va = t['va']
        pats = {
            'push imm32': b'\x68' + struct.pack('<I', va),
            'mov reg,imm32': None,
            'lea': None,
        }
        hits = []
        for s in code_secs:
            code = s['data']
            # push imm32
            start = 0
            pat = pats['push imm32']
            while True:
                i = code.find(pat, start)
                if i < 0:
                    break
                hits.append((s, i, 'push imm32'))
                start = i + 1
            # mov r32, imm32  (B8..BF)
            for op in range(0xB8, 0xC0):
                pat = bytes([op]) + struct.pack('<I', va)
                start = 0
                while True:
                    i = code.find(pat, start)
                    if i < 0:
                        break
                    hits.append((s, i, f'mov r{op - 0xB8},imm32'))
                    start = i + 1
            # lea r32,[imm32]  (8D modrm 05/0D/15/1D/25/2D/35/3D)
            for m in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D):
                pat = b'\x8D' + bytes([m]) + struct.pack('<I', va)
                start = 0
                while True:
                    i = code.find(pat, start)
                    if i < 0:
                        break
                    hits.append((s, i, 'lea r,[imm32]'))
                    start = i + 1
        gates = []
        for s, i, kind in hits:
            for g in find_gates(s['data'], i):
                g['via'] = kind
                g['xref_rva'] = s['va'] + i
                g['gate_rva'] = s['va'] + g['off']
                # 运行期补丁用的 AOB：门前后 8 字节
                g['aob'] = s['data'][max(0, g['off'] - 8):g['off'] + 10].hex()
                gates.append(g)
        if hits or gates:
            results.append(dict(kw=t['kw'], rva=hex(t['rva']), text=t['text'][:100],
                                xrefs=[hex(s['va'] + i) for s, i, k in hits][:10],
                                gates=sorted(gates, key=lambda x: -x['score'])[:4]))

    results.sort(key=lambda r: -len(r['gates']))
    print(f'[+] 有引用的字符串 {len(results)} 条，前 {a.top} 条：\n')
    for r in results[:a.top]:
        print(f"[{r['kw']}] {r['text'][:70]!r}  @{r['rva']}  引用 {len(r['xrefs'])} 处")
        for g in r['gates']:
            print(f"     门 {g['gate_rva']:#010x}  {g['jcc']:<12} 前有cmp={g['has_cmp']}  AOB={g['aob']}")
    if a.json:
        json.dump(dict(exe=a.exe, strings=results), open(a.json, 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=2)
        print(f'\n[+] → {a.json}')


if __name__ == '__main__':
    main()
