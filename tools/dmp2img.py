#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dmp2img.py —— 从 Windows 用户态内存转储(.dmp) 里抽出"某个模块的完整内存镜像"

用法（配合 dump2exe.py）：
    # 1) 抽模块镜像（默认 0x400000，本样本无重定位、固定基址）
    python3 tools/dmp2img.py --dmp hwid.dmp --base 0x400000 --size 0x54b1000 \
            --out mem.bin [--module HWIDMaster-0902.exe]
    # 2) 把镜像重新排版成可执行 PE
    python3 tools/dump2exe.py --dump mem.bin --base 0x400000 --out unpacked.exe --report

它做的事：
  - 解析 minidump（procdump -ma / WER LocalDumps / 任务管理器转储 都是这个格式）
  - 支持两种内存流：MINIDUMP_MEMORY64_LIST(9) 与 MINIDUMP_MEMORY_LIST(5)
  - 打印异常信息（ExceptionStream）：异常码 + **出错地址** —— 这条能直接判定"崩在哪"
  - 打印模块列表（含基址/大小），确认目标模块确实加载在预期基址
  - 把 [base, base+size) 的内存拼成一个连续文件，并统计每段覆盖情况
"""
import sys, os, struct, json, argparse

# ---- minidump 常量
MDMP_SIG = b'MDMP'
ST_MODULE_LIST = 4
ST_MEMORY_LIST = 5
ST_EXCEPTION = 6
ST_MEMORY64_LIST = 9


class Dmp:
    def __init__(self, data):
        self.d = data
        if data[:4] != MDMP_SIG:
            raise SystemExit('[-] 不是 minidump（文件头不是 MDMP）；'
                             '若这是 PAGEDUMP/完整内核转储，先在 Windows 上用 procdump -ma 重抓')
        self.version, self.nstreams, self.dir_rva = struct.unpack_from('<IIII', data, 4)[0], \
            struct.unpack_from('<I', data, 8)[0], struct.unpack_from('<I', data, 12)[0]
        self.streams = {}
        for i in range(self.nstreams):
            o = self.dir_rva + i * 12
            typ, sz, rva = struct.unpack_from('<III', data, o)
            self.streams.setdefault(typ, (sz, rva))

    # ---- 模块列表
    def modules(self):
        if ST_MODULE_LIST not in self.streams:
            return []
        _, rva = self.streams[ST_MODULE_LIST]
        n = struct.unpack_from('<I', self.d, rva)[0]
        out = []
        for i in range(n):
            o = rva + 4 + i * 108
            base = struct.unpack_from('<Q', self.d, o)[0]
            size = struct.unpack_from('<I', self.d, o + 8)[0]
            name_rva = struct.unpack_from('<I', self.d, o + 20)[0]
            name = ''
            if name_rva:
                nlen = struct.unpack_from('<I', self.d, name_rva)[0]
                name = self.d[name_rva + 4:name_rva + 4 + nlen].decode('utf-16-le', 'replace')
            out.append(dict(base=base, size=size, name=name))
        return out

    # ---- 异常信息
    def exception(self):
        if ST_EXCEPTION not in self.streams:
            return None
        _, rva = self.streams[ST_EXCEPTION]
        tid = struct.unpack_from('<I', self.d, rva)[0]
        code = struct.unpack_from('<I', self.d, rva + 8)[0]
        flags = struct.unpack_from('<I', self.d, rva + 12)[0]
        addr = struct.unpack_from('<Q', self.d, rva + 16)[0]
        nparams = struct.unpack_from('<I', self.d, rva + 24)[0]
        params = [struct.unpack_from('<Q', self.d, rva + 32 + i * 8)[0] for i in range(min(nparams, 4))]
        return dict(thread_id=tid, code=code, flags=flags, address=addr, params=params)

    # ---- 内存区间
    def ranges(self):
        out = []
        if ST_MEMORY64_LIST in self.streams:
            _, rva = self.streams[ST_MEMORY64_LIST]
            nranges = struct.unpack_from('<Q', self.d, rva)[0]
            base_rva = struct.unpack_from('<Q', self.d, rva + 8)[0]
            cur = base_rva
            for i in range(nranges):
                o = rva + 16 + i * 16
                start = struct.unpack_from('<Q', self.d, o)[0]
                size = struct.unpack_from('<Q', self.d, o + 8)[0]
                out.append((start, size, cur))
                cur += size
        elif ST_MEMORY_LIST in self.streams:
            _, rva = self.streams[ST_MEMORY_LIST]
            n = struct.unpack_from('<I', self.d, rva)[0]
            for i in range(n):
                o = rva + 4 + i * 16
                start = struct.unpack_from('<Q', self.d, o)[0]
                size = struct.unpack_from('<I', self.d, o + 8)[0]
                frva = struct.unpack_from('<I', self.d, o + 12)[0]
                out.append((start, size, frva))
        else:
            raise SystemExit('[-] 找不到内存流（既没有 MEMORY64_LIST 也没有 MEMORY_LIST）。'
                             '说明这个 dump 不是 -ma 全内存，重抓：procdump -ma <pid> out.dmp')
        out.sort()
        return out

    def read_at(self, addr, length, ranges=None):
        """从内存镜像里按虚拟地址读（跨区间拼）"""
        ranges = ranges or self.ranges()
        buf = bytearray()
        want = addr
        need = length
        for start, size, frva in ranges:
            if need <= 0:
                break
            if want < start:
                # 空洞
                gap = min(need, start - want)
                buf += b'\0' * gap
                want += gap
                need -= gap
                if need <= 0:
                    break
            if start <= want < start + size:
                off = want - start
                n = min(need, size - off)
                buf += self.d[frva + off:frva + off + n]
                want += n
                need -= n
        if need > 0:
            buf += b'\0' * need
        return bytes(buf)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dmp', required=True)
    ap.add_argument('--base', type=lambda x: int(x, 0), default=0x400000)
    ap.add_argument('--size', type=lambda x: int(x, 0), default=0x54b1000)
    ap.add_argument('--out', required=True)
    ap.add_argument('--module', default='')
    ap.add_argument('--json')
    a = ap.parse_args()

    dmp = Dmp(open(a.dmp, 'rb').read())
    rep = dict(dmp=os.path.abspath(a.dmp), size=len(dmp.d),
               streams={str(k): v for k, v in dmp.streams.items()})

    ex = dmp.exception()
    if ex:
        code = ex['code']
        sign = {0xC0000005: 'ACCESS_VIOLATION', 0xC000001D: 'ILLEGAL_INSTRUCTION',
                0xC0000096: 'PRIVILEGED_INSTRUCTION', 0x80000003: 'BREAKPOINT',
                0xC0000409: 'STACK_BUFFER_OVERRUN'}.get(code, '')
        rep['exception'] = dict(code=hex(code), name=sign, address=hex(ex['address']),
                                thread_id=ex['thread_id'],
                                params=[hex(p) for p in ex['params']],
                                rva=hex(ex['address'] - a.base) if ex['address'] > a.base else '?')
        print(f'[!] 异常: {code:#010x} {sign}  出错地址={ex["address"]:#x} '
              f'(若在主模块内则 RVA={ex["address"] - a.base:#x})')

    mods = dmp.modules()
    target = None
    for m in mods:
        if a.module and a.module.lower() in m['name'].lower():
            target = m
    rep['modules_count'] = len(mods)
    rep['modules'] = [dict(base=hex(m['base']), size=hex(m['size']), name=m['name'])
                      for m in mods[:40]]
    if target:
        print(f'[+] 目标模块: {target["name"]}  base={target["base"]:#x} size={target["size"]:#x}')
        rep['target_module'] = dict(base=hex(target['base']), size=hex(target['size']),
                                    name=target['name'])
    else:
        print('[i] 没按名字匹配到模块，仍按 --base 直接取内存')

    ranges = dmp.ranges()
    rep['mem_ranges'] = len(ranges)
    print(f'[+] 内存区间 {len(ranges)} 个，总覆盖 {sum(r[1] for r in ranges) / 1048576:.1f} MB')

    img = dmp.read_at(a.base, a.size, ranges)
    open(a.out, 'wb').write(img)
    # 覆盖率：按 64KB 块统计非零
    nz = sum(1 for i in range(0, len(img), 65536) if any(img[i:i + 65536]))
    print(f'[+] 已写出 {a.out}  {len(img):,} 字节；非零 64KB 块 {nz}/{len(img) // 65536}')
    rep['out'] = os.path.abspath(a.out)
    rep['nonzero_64k_blocks'] = nz
    if a.json:
        json.dump(rep, open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
        print(f'[+] 报告 → {a.json}')


if __name__ == '__main__':
    main()
