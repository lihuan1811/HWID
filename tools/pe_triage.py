#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pe_triage.py —— PE 静态体检 / 壳判定器

用途：拿到一个 PE 后，先判断它到底是
  [A] 正常的（可静态分析）程序
  [B] 加壳/加密的容器（需要运行时脱壳）
  [C] 根本没有可执行代码的"加密载荷"（单靠本文件不可能跑起来）

判定依据（全部可复现）：
  1. 段表：VirtualSize > 0 但 SizeOfRawData == 0  → 该段内容不在文件里
  2. 熵：按块统计，>7.9 即视为密文/压缩流
  3. 入口点：能否被 capstone 连续解码出合理指令（垃圾字节解不出）
  4. EP 是否落在"熵=8 的密文区"里（=不可能被 CPU 直接执行）
  5. 是否存在可解压的 zlib/lzma 流（能解 → 说明只是压缩，不是加密）
  6. 是否能在文件里找到壳的明文 stub（可执行代码密度）

用法：
  python3 pe_triage.py <file.exe> [--json out.json]
"""
import sys, os, json, struct, math, collections

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
except ImportError:
    Cs = None


# ---------------------------------------------------------------- PE 解析
class PE:
    def __init__(self, path):
        self.path = path
        self.d = open(path, 'rb').read()
        if self.d[:2] != b'MZ':
            raise SystemExit('[-] 不是 MZ 文件')
        self.pe_off = struct.unpack_from('<I', self.d, 0x3C)[0]
        if self.d[self.pe_off:self.pe_off + 4] != b'PE\0\0':
            raise SystemExit('[-] 找不到 PE 签名')
        self.machine, self.nsec = struct.unpack_from('<HH', self.d, self.pe_off + 4)
        self.soh = struct.unpack_from('<H', self.d, self.pe_off + 20)[0]
        self.opt = self.pe_off + 24
        self.magic = struct.unpack_from('<H', self.d, self.opt)[0]
        self.is64 = self.magic == 0x20b
        self.ep = struct.unpack_from('<I', self.d, self.opt + 16)[0]
        self.imagebase = struct.unpack_from('<I', self.d, self.opt + 28)[0]
        self.secalign = struct.unpack_from('<I', self.d, self.opt + 32)[0]
        self.filealign = struct.unpack_from('<I', self.d, self.opt + 36)[0]
        self.sizeofimage = struct.unpack_from('<I', self.d, self.opt + 56)[0]
        self.sizeofheaders = struct.unpack_from('<I', self.d, self.opt + 60)[0]
        self.subsystem = struct.unpack_from('<H', self.d, self.opt + 68)[0]
        self.dd = []
        base = self.opt + (112 if self.is64 else 96)
        for i in range(16):
            self.dd.append(struct.unpack_from('<II', self.d, base + i * 8))
        self.secoff = self.opt + self.soh
        self.sections = []
        for i in range(self.nsec):
            o = self.secoff + i * 40
            name = self.d[o:o + 8].rstrip(b'\0').decode('latin1', 'replace')
            vs, va, rs, ra = struct.unpack_from('<IIII', self.d, o + 8)
            ch = struct.unpack_from('<I', self.d, o + 36)[0]
            self.sections.append(dict(name=name, va=va, vs=vs, ra=ra, rs=rs, ch=ch,
                                      index=i, hdr_off=o))
        self.overlay_off = max((s['ra'] + s['rs']) for s in self.sections)

    def rva2off(self, rva):
        for s in self.sections:
            if s['va'] <= rva < s['va'] + max(s['vs'], s['rs']):
                if s['rs'] == 0:
                    return None
                delta = rva - s['va']
                if delta >= s['rs']:
                    return None            # 落在 BSS 式的零填充尾部
                return s['ra'] + delta
        return None

    def section_of(self, rva):
        for s in self.sections:
            if s['va'] <= rva < s['va'] + max(s['vs'], s['rs']):
                return s
        return None

    def imports(self):
        rva, sz = self.dd[1]
        if not rva:
            return []
        off = self.rva2off(rva)
        if off is None:
            return []
        out = []
        i = 0
        while True:
            o = off + i * 20
            if o + 20 > len(self.d):
                break
            ilt, ts, fc, name_rva, iat = struct.unpack_from('<IIIII', self.d, o)
            if (ilt, ts, fc, name_rva, iat) == (0, 0, 0, 0, 0):
                break
            no = self.rva2off(name_rva) if name_rva else None
            if no is None:
                out.append(dict(dll=f'<bad name rva {name_rva:#x}>', count=0, names=[]))
                i += 1
                continue
            end = self.d.index(b'\0', no)
            dll = self.d[no:end].decode('latin1', 'replace')
            names = []
            t = self.rva2off(ilt)
            while t is not None and t + 4 <= len(self.d):
                v = struct.unpack_from('<I', self.d, t)[0]
                if v == 0:
                    break
                if v & 0x80000000:
                    names.append(f'ord{v & 0xffff}')
                else:
                    n2 = self.rva2off(v & 0x7fffffff)
                    if n2 is None:
                        names.append(f'<bad {v:#x}>')
                        break
                    e2 = self.d.index(b'\0', n2 + 2)
                    names.append(self.d[n2 + 2:e2].decode('latin1', 'replace'))
                t += 4
            out.append(dict(dll=dll, count=len(names), names=names))
            i += 1
            if i > 200:
                break
        return out


# ---------------------------------------------------------------- 度量
def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def entropy_map(data, window=1 << 16, step=None):
    step = step or window
    return [(i, entropy(data[i:i + window])) for i in range(0, max(1, len(data) - 1), step)]


def decode_density(code, is64, base_va):
    """返回 (解码出的指令数, 覆盖字节数, 首条指令示例)"""
    if Cs is None:
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
    md.detail = False
    ins = list(md.disasm(code, base_va))
    if not ins:
        return (0, 0, [])
    cover = ins[-1].address + ins[-1].size - base_va
    return (len(ins), cover, [f'{i.address:#x}: {i.mnemonic} {i.op_str}' for i in ins[:12]])


def try_decompress(blob, limit=40):
    """在密文里找能解开的 zlib/lzma 流：能解开说明只是压缩不是加密"""
    import zlib, lzma
    hits = []
    cand = [
        i for i in range(0, len(blob) - 8)
        if blob[i] == 0x78 and blob[i + 1] in (0x01, 0x9c, 0xda, 0x5e)
    ]
    for i in cand[:limit * 50]:
        try:
            out = zlib.decompressobj().decompress(blob[i:i + (1 << 20)], 1 << 22)
            if len(out) > 8192:
                hits.append(('zlib', i, len(out)))
                if len(hits) >= limit:
                    return hits
        except Exception:
            pass
    if not hits:
        for i in range(0, len(blob) - 16):
            if blob[i] == 0x5D and blob[i + 1:i + 4] == b'\0\0\0':
                try:
                    out = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(
                        blob[i:i + (4 << 20)], 1 << 23)
                    if len(out) > 8192:
                        hits.append(('lzma', i, len(out)))
                        if len(hits) >= limit:
                            break
                except Exception:
                    pass
    return hits


DEF_IMPORTS = {
    'bsvfw32.dll': 'Borland/Embarcadero VCL', 'avifil32.dll': 'VCL(AVI/Video)',
    'msimg32.dll': 'VCL(GradientFill)', 'winspool.drv': 'VCL(打印)',
    'comctl32.dll': 'VCL 控件', 'oleaut32.dll': 'VCL OLE',
}
PY_SIGS = [b'PyInstaller', b'_MEIPASS', b'python3', b'Py_Initialize',
           b'pyiboot', b'pyimod', b'python.exe']
DOTNET_SIGS = [b'mscoree', b'_CorExeMain', b'BSJB']
GO_SIGS = [b'go:buildid', b'Go build ID', b'runtime.morestack']
PROT_SIGS = {
    'VMProtect': [b'VMProtect', b'.vmp0', b'.vmp1'],
    'Themida/WinLicense': [b'Themida', b'.themida', b'.winlice', b'XSPROTECT'],
    'Safengine(Shielden)': [b'Safengine', b'.sedata', b'.sdata'],
    'Enigma Protector': [b'Enigma', b'.enigma1', b'.enigma2'],
    'Obsidium': [b'Obsidium', b'.obsidium'],
    'ASProtect': [b'ASProtect', b'.adata', b'.aspack'],
    'ASPack': [b'ASPack', b'.aspack'],
    'PECompact': [b'PECompact', b'PEC2'],
    'UPX': [b'UPX!', b'UPX0', b'UPX1'],
    'MPRESS': [b'MPRESS1', b'MPRESS2'],
    'ZProtect': [b'ZProtect', b'.zprotect'],
    'EXECryptor': [b'EXECryptor'],
    'MoleBox': [b'MoleBox'],
    'Enigma VB': [b'Enigma Virtual Box', b'.enigma'],
}


def fingerprint(p):
    notes = []
    d = p.d
    for name, sigs in PROT_SIGS.items():
        for s in sigs:
            if s in d:
                notes.append(f'命中壳特征串 {name}: {s!r}')
    for s in PY_SIGS:
        if s in d:
            notes.append(f'疑似 Python 打包: {s!r}')
            break
    for s in DOTNET_SIGS:
        if s in d:
            notes.append(f'疑似 .NET: {s!r}')
            break
    for s in GO_SIGS:
        if s in d:
            notes.append(f'疑似 Go 编译: {s!r}')
            break

    dlls = [i['dll'].lower() for i in getattr(p, '_imports', [])]
    for k, v in DEF_IMPORTS.items():
        if k in dlls:
            notes.append(f'导入表特征：{v}（{k}）')
    # 随机段名特征（保护壳常随机化段名）
    weird = [s['name'] for s in p.sections
             if any(not (c.isalnum() or c in '._$') for c in s['name'])]
    if weird:
        notes.append('段名被随机化/非标准：' + ', '.join(repr(w) for w in weird))
    return notes


# ---------------------------------------------------------------- 主流程
def triage(path):
    p = PE(path)
    p._imports = p.imports()
    rep = dict(file=os.path.abspath(path), size=len(p.d),
               md5=__import__('hashlib').md5(p.d).hexdigest(),
               machine=hex(p.machine), bits=64 if p.is64 else 32,
               subsystem=p.subsystem, imagebase=hex(p.imagebase),
               entry_point=hex(p.ep), sizeofimage=hex(p.sizeofimage),
               overlay_off=hex(p.overlay_off), overlay_size=len(p.d) - p.overlay_off)

    # 段表
    secs = []
    for s in p.sections:
        secs.append(dict(name=s['name'], va=hex(s['va']), vs=hex(s['vs']),
                         raw_off=hex(s['ra']), raw_size=hex(s['rs']),
                         flags=hex(s['ch']),
                         ent_file=round(entropy(p.d[s['ra']:s['ra'] + s['rs']]), 3) if s['rs'] else None,
                         data_in_file=s['rs'] > 0))
    rep['sections'] = secs

    zero_raw = [s['name'] for s in p.sections if s['vs'] > 0 and s['rs'] == 0]
    rep['sections_without_file_data'] = zero_raw

    # 段数据合并（用于熵/解压探测）
    payload = b''.join(p.d[s['ra']:s['ra'] + s['rs']] for s in p.sections if s['rs'])
    emap = entropy_map(payload, 1 << 20, 1 << 20)
    rep['entropy_mb'] = [[round(i / 1048576, 2), round(e, 3)] for i, e in emap]
    frac_hi = sum(1 for _, e in emap if e > 7.9) / max(1, len(emap))
    rep['fraction_blocks_entropy_gt_7.9'] = round(frac_hi, 3)
    rep['mean_entropy'] = round(sum(e for _, e in emap) / max(1, len(emap)), 3)

    # 入口点是否在密文中 / 能否解码
    ep_off = p.rva2off(p.ep)
    ep_sec = p.section_of(p.ep)
    rep['ep_section'] = ep_sec['name'] if ep_sec else None
    rep['ep_file_offset'] = hex(ep_off) if ep_off is not None else None
    if ep_off is None:
        rep['ep_readable'] = False
    else:
        chunk = p.d[ep_off:ep_off + 4096]
        rep['ep_window_entropy'] = round(entropy(chunk[:1024]), 3)
        dd = decode_density(chunk, p.is64, p.imagebase + p.ep)
        if dd:
            rep['ep_decoded_insns'], rep['ep_decoded_bytes'], rep['ep_disasm_head'] = dd
            rep['ep_decoded_ratio'] = round(dd[1] / len(chunk), 4)

    # 全文件找"可执行代码密度"最高的 4KB 窗口（= 壳的明文 stub 所在）
    best = []
    blob = p.d
    step = 4096
    for i in range(0, max(1, len(blob) - step), step):
        w = blob[i:i + step]
        # 全零/填充区会被解成无穷多 add [eax],al，必须排除
        if w.count(0) > step * 0.05:
            continue
        if entropy(w) > 7.2:
            continue
        dd = decode_density(w, p.is64, 0x400000 + i)
        if not dd or dd[1] == 0:
            continue
        mnem = {ln.split(': ', 1)[1].split(' ')[0] for ln in dd[2]}
        if len(mnem) < 8:            # 指令种类太少 → 不是真实代码
            continue
        best.append((min(dd[1] / step, 1.0), i, dd[0]))
    best.sort(reverse=True)
    rep['top_code_windows'] = [dict(off=hex(o), ratio=round(r, 3), insns=n) for r, o, n in best[:8]]
    # 真正的"壳 stub"判定：某窗口里连续可解码字节 > 40%（垃圾字节做不到）
    rep['has_plaintext_stub'] = bool(best) and best[0][0] > 0.40
    rep['best_code_window_ratio'] = round(best[0][0], 3) if best else 0.0

    # VM 型壳的"虚拟机 handler 代码"识别：
    #   特征 = 4KB 窗口内 100% 可解码 + mov/xor/lea/not/neg/rol/ror/bts/btc 占比高
    #         （VMProtect 3 / 同类 VM 壳的变异代码就是这个形态）
    VM_MNEMS = {'not', 'neg', 'ror', 'rol', 'rcl', 'rcr', 'bts', 'btc', 'btr', 'bts',
                'bt', 'bswap', 'xchg', 'sal', 'sar', 'shl', 'shr', 'xor', 'and', 'or'}
    vm_windows = []
    if Cs:
        from capstone import Cs as _Cs, CS_ARCH_X86 as _A, CS_MODE_32 as _M32, CS_MODE_64 as _M64
        md = _Cs(_A, _M64 if p.is64 else _M32)
        for i in range(0, max(1, len(blob) - 4096), 4096):
            w = blob[i:i + 4096]
            if w.count(0) > 4096 * 0.05:
                continue
            if entropy(w) > 7.75:
                continue
            ins = list(md.disasm(w, 0x400000 + i))
            if len(ins) < 500:
                continue
            cover = ins[-1].address + ins[-1].size - (0x400000 + i)
            if cover < 4096 * 0.95:
                continue
            vm = sum(1 for x in ins if x.mnemonic in VM_MNEMS)
            if vm / len(ins) > 0.25:
                vm_windows.append((i, round(vm / len(ins), 2), len(ins)))
    rep['vm_handler_windows'] = len(vm_windows)
    if vm_windows:
        rep['vm_handler_range'] = [hex(vm_windows[0][0]), hex(vm_windows[-1][0] + 4096)]
        rep['vm_handler_ratio_avg'] = round(
            sum(v[1] for v in vm_windows) / len(vm_windows), 2)
        rep['vm_handler_sample'] = [dict(off=hex(a), ratio=r, insns=n)
                                    for a, r, n in vm_windows[:6]]

    # 压缩流探测（只在前 8MB 采样，够用）
    rep['decompressible_streams'] = try_decompress(payload[:8 << 20])

    # 导入表
    rep['imports'] = [dict(dll=i['dll'], count=i['count']) for i in p._imports]
    rep['import_dirs'] = {n: [hex(r), hex(s)] for n, (r, s) in zip(
        ['Export', 'Import', 'Resource', 'Exception', 'Security', 'Reloc', 'Debug',
         'Arch', 'GlobalPtr', 'TLS', 'LoadConfig', 'BoundImport', 'IAT', 'Delay', 'CLR', 'Res'],
        p.dd) if r or s}

    rep['fingerprint_notes'] = fingerprint(p)

    # ---- 结论
    verdict, why = [], []
    if zero_raw:
        verdict.append('C_RAW_EMPTY')
        why.append(f'这些段在文件里没有任何字节（SizeOfRawData=0），只能在内存里被壳填出来：{zero_raw}')
    if rep.get('ep_decoded_ratio') is not None and rep['ep_decoded_ratio'] < 0.05:
        verdict.append('EP_NOT_CODE')
        why.append(f'入口点连续可解码字节只占 {rep["ep_decoded_ratio"]:.2%}，'
                   f'即 EP 处不是机器码（CPU 跳过去只会执行到垃圾字节）')
    if rep.get('ep_window_entropy', 0) > 7.8:
        verdict.append('EP_ENCRYPTED')
        why.append('入口点所在 1KB 熵 ≈ 8.0，是密文/压缩流，不可能是壳的明文引导代码')
    if frac_hi > 0.70:
        verdict.append('BODY_ENCRYPTED')
        why.append(f'{frac_hi:.0%} 的 1MB 块熵 > 7.9，主体数据是加密的')
    if not rep['decompressible_streams']:
        verdict.append('NOT_JUST_COMPRESSED')
        why.append('全文件采样未找到任何可解开的 zlib/lzma 流 → 不是"压缩壳"，是真加密')
    if not rep['has_plaintext_stub']:
        verdict.append('NO_PLAINTEXT_STUB')
        why.append(f'全文件最高的 4KB 可解码窗口只占 {rep["best_code_window_ratio"]:.1%}'
                   '（随机字节级别）→ 文件内不存在可执行的脱壳 stub')
    if rep.get('vm_handler_windows', 0) >= 20:
        verdict.append('VM_STUB_PRESENT')
        why.append(f'{rep["vm_handler_windows"]} 个 4KB 窗口是"虚拟机 handler 代码"形态'
                   f'（100% 可解码、not/neg/rol/ror/bts/btc/xor 占比均值 '
                   f'{rep["vm_handler_ratio_avg"]:.0%}），地址区间 '
                   f'{rep["vm_handler_range"][0]}~{rep["vm_handler_range"][1]}'
                   ' → 这是 VMProtect 这一类**虚拟机壳**的 stub，壳确实存在')
    rep['verdict_codes'] = verdict
    rep['verdict_reasons'] = why

    if 'EP_NOT_CODE' in verdict and 'VM_STUB_PRESENT' in verdict:
        rep['conclusion'] = ('VM_PACKED_EP_MISMATCH: 壳是**虚拟机型（VMProtect 类）**，'
                             '它的 VM stub 就明文躺在文件尾部的 .KPx 里；'
                             '但 PE 头里的入口点(EP)指向另一片密文区 —— 也就是说'
                             '"入口点"被二次改写/剥离过，CPU 不会跳到 VM stub 上，'
                             '本文件双击无法启动。要脱壳必须在 Windows 上让它在真实入口开始跑，'
                             '或者拿到配套的 loader/启动器，或者用运行时内存转储。')
    elif 'EP_NOT_CODE' in verdict and 'NO_PLAINTEXT_STUB' in verdict:
        rep['conclusion'] = ('ENCRYPTED_PAYLOAD: 这是"加密载荷/受保护容器"，不是能独立运行的程序。'
                             '文件内没有可执行代码、没有解壳 stub、也没有可解压的压缩流，'
                             '入口点直接指向密文。静态分析拿不到明文程序，'
                             '必须拿到启动器(loader)/可运行版本/或运行时内存转储才能继续。')
    elif 'BODY_ENCRYPTED' in verdict:
        rep['conclusion'] = ('PACKED: 已加壳/加密，但是带明文 stub 的正常壳 —— '
                             '按 Windows 手册做运行时脱壳（x64dbg+ScyllaHide+Scylla）。')
    else:
        rep['conclusion'] = 'PLAIN: 未明显加壳，可直接静态分析（找激活校验 → 打补丁）。'
    return rep


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    rep = triage(path)
    out = None
    if '--json' in sys.argv:
        out = sys.argv[sys.argv.index('--json') + 1]
    txt = json.dumps(rep, ensure_ascii=False, indent=2)
    if out:
        open(out, 'w', encoding='utf-8').write(txt)
        print(f'[+] JSON 报告 → {out}')
    print(f'===== {rep["file"]} =====')
    print(f'大小 {rep["size"]:,}  MD5 {rep["md5"]}  {rep["bits"]}位 EP={rep["entry_point"]}')
    print(f'平均熵 {rep["mean_entropy"]}   高熵块占比 {rep["fraction_blocks_entropy_gt_7.9"]}')
    print(f'EP 段={rep["ep_section"]}  文件偏移={rep["ep_file_offset"]}  '
          f'1KB熵={rep.get("ep_window_entropy")}  可解码比例={rep.get("ep_decoded_ratio")}')
    print('--- 段表 ---')
    for s in rep['sections']:
        print(f'  {s["name"]:<10} VA={s["va"]:<10} VS={s["vs"]:<10} RAW={s["raw_off"]:<10} '
              f'RS={s["raw_size"]:<10} 文件内={"是" if s["data_in_file"] else "否(全零)"} '
              f'熵={s["ent_file"]}')
    print('--- 特征 ---')
    for n in rep['fingerprint_notes']:
        print('  ·', n)
    print('--- 判定 ---')
    for c in rep['verdict_codes']:
        print('  [' + c + ']')
    for w in rep['verdict_reasons']:
        print('     -', w)
    print('--- 结论 ---')
    print(' ', rep['conclusion'])
    return 0


if __name__ == '__main__':
    sys.exit(main())
