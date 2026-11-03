#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
delphi_gate.py —— Delphi / C++Builder 程序"激活码/卡密校验"定位与打补丁

适用对象：**脱壳后的** HWIDMaster 主程序（或任何 VCL/BCC 32 位程序）。
做的事情：
  1. 扫描字符串（ANSI + UTF-16LE），按"授权/激活/机器码/到期"等关键词打分
  2. 反查代码里对这些字符串的引用（push imm32 / mov reg,imm32 / lea / mov eax,[imm32]）
  3. 在引用点附近找 test/cmp + 条件跳转（JZ/JNZ/JE/JNE/JA...）= 判定门
  4. 输出候选门清单（VA、字节、上下文），等你确认
  5. 支持直接打补丁：
        --force-true  RVA      → mov al,1; ret        (B0 01 C3)
        --force-false RVA      → xor al,al; ret       (30 C0 C3)
        --jmp-always  RVA      → 把该处的条件跳转改成无条件跳
        --nop         RVA:LEN  → 填 90
        --bytes       RVA:HEX  → 任意字节
        --apply       file.txt → 批量（每行 "RVA HEXCODE  # 备注"）
     打补丁前自动备份 <exe>.bak，并把每条补丁的原始字节写进 <exe>.patchlog.json

用法：
    python3 delphi_gate.py --exe hwid_unpacked.exe                # 只分析
    python3 delphi_gate.py --exe hwid_unpacked.exe --json gates.json
    python3 delphi_gate.py --exe hwid_unpacked.exe --force-true 0x00451234
"""
import sys, os, re, json, struct, shutil, argparse

# --- Windows 控制台(cp1252)打不出中文，统一把 stdout 设成 utf-8 ---
def _utf8_stdout():
    try:
        import sys as _s
        _s.stdout.reconfigure(encoding='utf-8', errors='replace')
        _s.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


_utf8_stdout()


try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
except ImportError:
    Cs = None

# ---------------------------------------------------------------- 关键词
KEYWORDS = [
    # 中文（授权/激活域）
    ('激活码', 40), ('激活成功', 45), ('激活失败', 45), ('激活', 25),
    ('注册码', 40), ('注册成功', 45), ('注册失败', 45), ('注册', 20),
    ('卡密', 45), ('密卡', 35), ('卡号', 25), ('充值', 20),
    ('授权', 30), ('授权码', 40), ('未授权', 45), ('授权失败', 45),
    ('机器码', 35), ('机器特征码', 40), ('硬件码', 35), ('设备码', 30),
    ('到期', 35), ('已过期', 45), ('过期', 30), ('有效期', 30), ('剩余天数', 35),
    ('试用', 25), ('试用期', 30), ('免费试用', 30),
    ('验证失败', 40), ('校验失败', 40), ('无效', 20), ('不合法', 25),
    ('登录成功', 20), ('登录失败', 20), ('请先激活', 45), ('需要激活', 45),
    # 英文
    ('activation', 30), ('activate', 25), ('license', 30), ('licence', 30),
    ('serial', 25), ('expire', 30), ('expired', 40), ('trial', 25),
    ('machine id', 35), ('machine code', 35), ('hardware id', 35), ('hwid', 30),
    ('invalid key', 40), ('invalid license', 45), ('not activated', 45),
    ('unregistered', 35), ('registration', 25), ('product key', 35),
    ('unauthorized', 30), ('forbidden', 15),
]
# 强特征（用于给"门"排序）
STRONG = {'激活成功', '激活失败', '注册成功', '注册失败', '未授权', '授权失败',
          '已过期', '请先激活', '需要激活', 'invalid license', 'not activated',
          'activation', 'expired'}


class PEImg:
    def __init__(self, path):
        self.path = path
        self.d = bytearray(open(path, 'rb').read())
        self.pe = struct.unpack_from('<I', self.d, 0x3C)[0]
        self.nsec = struct.unpack_from('<H', self.d, self.pe + 6)[0]
        self.soh = struct.unpack_from('<H', self.d, self.pe + 20)[0]
        self.opt = self.pe + 24
        self.magic = struct.unpack_from('<H', self.d, self.opt)[0]
        self.is64 = self.magic == 0x20b
        self.ep = struct.unpack_from('<I', self.d, self.opt + 16)[0]
        self.imagebase = struct.unpack_from('<I', self.d, self.opt + (24 if self.is64 else 28))[0]
        self.secoff = self.opt + self.soh
        self.sections = []
        for i in range(self.nsec):
            o = self.secoff + i * 40
            name = bytes(self.d[o:o + 8]).rstrip(b'\0').decode('latin1', 'replace')
            vs, va, rs, ra = struct.unpack_from('<IIII', self.d, o + 8)
            ch = struct.unpack_from('<I', self.d, o + 36)[0]
            self.sections.append(dict(name=name, va=va, vs=vs, ra=ra, rs=rs, ch=ch, hdr=o))
        self.scan = Cs(CS_ARCH_X86, CS_MODE_64 if self.is64 else CS_MODE_32) if Cs else None

    def rva2off(self, rva):
        for s in self.sections:
            if s['va'] <= rva < s['va'] + max(s['vs'], s['rs']):
                if s['rs'] and rva - s['va'] < s['rs']:
                    return s['ra'] + (rva - s['va'])
                return None
        return None

    def exec_sections(self):
        return [s for s in self.sections if s['ch'] & 0x20000000 and s['rs']]

    def data_sections(self):
        return [s for s in self.sections if not (s['ch'] & 0x20000000) and s['rs']]

    def linear(self):
        """每段做一次线性反汇编并缓存：(rva, mnem, op_str, bytes) 列表"""
        if getattr(self, '_lin', None) is not None:
            return self._lin
        self._lin = {}
        if not self.scan:
            return self._lin
        for sec in self.exec_sections():
            code = bytes(self.d[sec['ra']:sec['ra'] + sec['rs']])
            ins = []
            for i in self.scan.disasm(code, self.imagebase + sec['va']):
                ins.append((i.address - self.imagebase, i.mnemonic, i.op_str, i.bytes))
            self._lin[sec['name']] = ins
        return self._lin

    def disasm_at(self, rva, n=14):
        off = self.rva2off(rva)
        if off is None or not self.scan:
            return []
        return list(self.scan.disasm(bytes(self.d[off:off + 64]), self.imagebase + rva))[:n]


# ---------------------------------------------------------------- 字符串
def extract_strings(img):
    out = []
    for s in img.data_sections() + img.exec_sections():
        blob = bytes(img.d[s['ra']:s['ra'] + s['rs']])
        base_rva = s['va']
        # ANSI
        for m in re.finditer(rb'[\x20-\x7e]{4,}', blob):
            txt = m.group().decode('latin1')
            out.append(dict(rva=base_rva + m.start(), kind='ansi', text=txt))
        # UTF-16LE
        for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}', blob):
            txt = m.group().decode('utf-16-le')
            out.append(dict(rva=base_rva + m.start(), kind='utf16', text=txt))
        # GBK 中文（Delphi 多字节串）：用 gbk 试探解码
        for m in re.finditer(rb'(?:[\xb0-\xf7][\xa1-\xfe]){2,}', blob):
            try:
                txt = m.group().decode('gbk')
            except Exception:
                continue
            if len(txt) >= 2:
                out.append(dict(rva=base_rva + m.start(), kind='gbk', text=txt))
    return out


def score_string(txt):
    low = txt.lower()
    sc, hits = 0, []
    for kw, w in KEYWORDS:
        if kw in low or kw in txt:
            sc += w
            hits.append(kw)
    return sc, hits


# ---------------------------------------------------------------- 引用反查
def find_xrefs(img, target_rva):
    """在代码段里找对该字符串的引用。Delphi/BCB 32 位程序用的是**绝对 VA**，
    所以同时搜 imagebase+rva 和裸 rva 两种常量写法。"""
    pats = [struct.pack('<I', img.imagebase + target_rva),
            struct.pack('<I', target_rva)]
    hits = []
    for pat in pats:
        for s in img.exec_sections():
            blob = bytes(img.d[s['ra']:s['ra'] + s['rs']])
            i = 0
            while True:
                j = blob.find(pat, i)
                if j < 0:
                    break
                k = j - 1
                kind = 'imm32?'
                back = 2
                if k >= 0 and blob[k] == 0x68:
                    kind, back = 'push imm32', 1
                elif k >= 0 and blob[k] == 0xA1:
                    kind, back = 'mov eax,[imm32]', 1
                elif k >= 0 and 0xB8 <= blob[k] <= 0xBF:
                    kind, back = 'mov reg,imm32', 1
                elif k >= 1 and blob[k - 1] == 0x8D and (blob[k] & 0xC7) == 0x05:
                    kind, back = 'lea reg,[imm32]', 2
                hits.append(dict(rva=s['va'] + j - back,
                                 at=s['va'] + j, kind=kind))
                i = j + 1
    # 去重
    seen, uniq = set(), []
    for h in hits:
        if h['rva'] in seen:
            continue
        seen.add(h['rva'])
        uniq.append(h)
    return uniq


# ---------------------------------------------------------------- 找"门"
JCC1 = set(range(0x70, 0x80))          # 短条件跳转
JCC2 = set(range(0x80, 0x90))          # 0F 8x 近条件跳转


JCC_MNEM = {'jo', 'jno', 'jb', 'jae', 'je', 'jne', 'jbe', 'ja', 'js', 'jns',
            'jp', 'jnp', 'jl', 'jge', 'jle', 'jg', 'jz', 'jnz', 'jcxz', 'jecxz'}
# 最像"授权判定门"的
GATE_PREF = {'jz': 3, 'je': 3, 'jnz': 2, 'jne': 2, 'ja': 1, 'jae': 1, 'jbe': 1, 'jb': 1}


def gates_near(img, rva, span=0x80):
    """在引用点附近找 test/cmp + 条件跳转（= 判定门），按可疑度排序"""
    out = []
    lo, hi = rva - span, rva + span
    for secname, ins in img.linear().items():
        for idx, (addr, mnem, ops, byt) in enumerate(ins):
            if not (lo <= addr <= hi) or mnem not in JCC_MNEM:
                continue
            prev = ins[max(0, idx - 2):idx]
            prev_txt = ' ; '.join(f'{m} {o}'.strip() for _, m, o, _ in prev)
            # 前一两条里出现 test/cmp 更像判定
            has_cmp = any(m in ('test', 'cmp', 'or', 'and') for _, m, _, _ in prev)
            dist = abs(addr - rva)
            score = GATE_PREF.get(mnem, 0) * 10 + (15 if has_cmp else 0) - min(dist // 8, 15)
            out.append(dict(gate_rva=addr, section=secname, jcc=f'{mnem} {ops}',
                            bytes=byt.hex(), prev=prev_txt, near_cmp=has_cmp,
                            dist=dist, score=score))
    out.sort(key=lambda x: -x['score'])
    return out


# ---------------------------------------------------------------- 打补丁
def apply_patch(img, rva, data, note, log):
    off = img.rva2off(rva)
    if off is None:
        raise SystemExit(f'[-] RVA {rva:#x} 不在任何段的文件数据里，无法打补丁')
    old = bytes(img.d[off:off + len(data)])
    img.d[off:off + len(data)] = data
    log.append(dict(rva=hex(rva), file_off=hex(off), old=old.hex(), new=data.hex(), note=note))
    print(f'[patch] {rva:#010x} (file {off:#x})  {old.hex()} → {data.hex()}   {note}')


def patch_jmp_always(img, rva, log):
    off = img.rva2off(rva)
    if off is None:
        raise SystemExit(f'[-] RVA {rva:#x} 不可写')
    b = img.d[off]
    if b in JCC1:
        img.d[off] = 0xEB
        log.append(dict(rva=hex(rva), file_off=hex(off), old=f'{b:02x}', new='eb',
                        note='短条件跳转 → 无条件跳转'))
        print(f'[patch] {rva:#010x} {b:02x}→eb (短 Jcc → JMP)')
    elif b == 0x0F and img.d[off + 1] in JCC2:
        img.d[off] = 0xE9
        img.d[off + 1] = img.d[off + 1]          # 保留 disp32 低字节位置：0F 8x rel32 → E9 rel32 需重排
        # 0F 8x rel32 = 6 字节; E9 rel32 = 5 字节 → 需要平移
        # 做法：把 rel32 前移一字节，末字节填 90
        rel = bytes(img.d[off + 2:off + 6])
        img.d[off + 1:off + 5] = rel
        img.d[off + 5] = 0x90
        log.append(dict(rva=hex(rva), file_off=hex(off), old='0f8x', new='e9..90',
                        note='近条件跳转 → JMP + NOP'))
        print(f'[patch] {rva:#010x} 0F8x→E9 + 90 (近 Jcc → JMP)')
    else:
        raise SystemExit(f'[-] {rva:#x} 处不是条件跳转（字节 {b:02x}）')


# ---------------------------------------------------------------- 主
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', required=True)
    ap.add_argument('--json')
    ap.add_argument('--top', type=int, default=25)
    ap.add_argument('--force-true', type=lambda x: int(x, 0), action='append', default=[])
    ap.add_argument('--force-false', type=lambda x: int(x, 0), action='append', default=[])
    ap.add_argument('--jmp-always', type=lambda x: int(x, 0), action='append', default=[])
    ap.add_argument('--nop', action='append', default=[], help='RVA:LEN')
    ap.add_argument('--bytes', action='append', default=[], help='RVA:HEX')
    ap.add_argument('--apply', help='补丁清单文件，每行 "RVA HEX  # 备注"')
    a = ap.parse_args()

    img = PEImg(a.exe)
    print(f'===== {a.exe} =====')
    print(f'{img.nsec} 段  ImageBase={img.imagebase:#x}  EP={img.ep:#x}')
    for s in img.sections:
        print(f'  {s["name"]:<10} VA={s["va"]:#x} VS={s["vs"]:#x} RAW={s["ra"]:#x} '
              f'RS={s["rs"]:#x} {"X" if s["ch"] & 0x20000000 else " "}')

    strs = extract_strings(img)
    scored = []
    for s in strs:
        sc, hits = score_string(s['text'])
        if sc >= 20:
            scored.append(dict(**s, score=sc, hits=hits))
    scored.sort(key=lambda x: -x['score'])
    print(f'[+] 命中授权关键词的字符串 {len(scored)} 条')

    results = []
    for s in scored[:a.top]:
        xrefs = find_xrefs(img, s['rva'])
        gates = []
        for x in xrefs:
            for g in gates_near(img, x['rva']):
                g['via'] = x['kind']
                g['xref'] = hex(x['rva'])
                gates.append(g)
        results.append(dict(text=s['text'], rva=hex(s['rva']), kind=s['kind'],
                            score=s['score'], hits=s['hits'],
                            xrefs=[hex(x['rva']) for x in xrefs],
                            gates=gates[:6]))
        print(f'\n[{s["score"]:>3}] {s["text"][:60]!r}  @{s["rva"]:#x} ({s["kind"]})  '
              f'引用 {len(xrefs)} 处')
        for x in xrefs[:4]:
            print(f'      ← {x["rva"]:#010x}  {x["kind"]}')
        for g in gates[:4]:
            print(f'      门候选 {g["gate_rva"]:#010x}  {g["jcc"]:<22} 前文: {g["prev"][:70]}')

    if a.json:
        json.dump(dict(exe=os.path.abspath(a.exe), strings=results),
                  open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
        print(f'\n[+] 报告 → {a.json}')

    # ---- 打补丁
    patches = []
    for r in a.force_true:
        patches.append((r, bytes.fromhex('B001C3'), 'force true (mov al,1; ret)'))
    for r in a.force_false:
        patches.append((r, bytes.fromhex('30C0C3'), 'force false (xor al,al; ret)'))
    for spec in a.nop:
        r, ln = spec.split(':')
        patches.append((int(r, 0), b'\x90' * int(ln, 0), f'nop {ln}'))
    for spec in a.bytes:
        r, hexs = spec.split(':')
        patches.append((int(r, 0), bytes.fromhex(hexs), 'raw bytes'))
    if a.apply:
        for line in open(a.apply, encoding='utf-8'):
            line = line.split('#')[0].strip()
            if not line:
                continue
            r, hexs = line.split()[:2]
            patches.append((int(r, 0), bytes.fromhex(hexs), 'from file'))

    if patches or a.jmp_always:
        bak = a.exe + '.bak'
        if not os.path.exists(bak):
            shutil.copy2(a.exe, bak)
            print(f'[+] 备份 → {bak}')
        log = []
        for r, data, note in sorted(patches):
            apply_patch(img, r, data, note, log)
        for r in sorted(a.jmp_always):
            patch_jmp_always(img, r, log)
        open(a.exe, 'wb').write(bytes(img.d))
        json.dump(log, open(a.exe + '.patchlog.json', 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=2)
        print(f'[+] 已写入 {a.exe}（{len(log)} 处补丁），日志 {a.exe}.patchlog.json')
    else:
        print('\n[i] 未打补丁。确认"门"之后这样打：')
        print('    python3 delphi_gate.py --exe <exe> --jmp-always 0x<门地址>   # 最稳：跳过判定')
        print('    python3 delphi_gate.py --exe <exe> --force-true 0x<校验函数入口>  # 让函数恒返回真')


if __name__ == '__main__':
    main()
