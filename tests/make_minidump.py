#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""造一个最小可用 minidump（MDMP），用来验证 tools/dmp2img.py 的解析逻辑。
   内容：1 个模块(HWIDMaster-0902.exe @0x400000) + 1 段内存 + 1 条异常(0xC0000005 @0x2AF1DD3)"""
import struct, sys, os

BASE = 0x400000
IMG_SIZE = 0x3000

def build(path):
    # 内存内容：MZ 头 + 可辨识填充
    mem = bytearray(IMG_SIZE)
    mem[0:2] = b'MZ'
    struct.pack_into('<I', mem, 0x3C, 0x80)
    mem[0x80:0x84] = b'PE\0\0'
    for i in range(0x1000, IMG_SIZE):
        mem[i] = (i * 7) & 0xFF
    mem_block = bytes(mem)

    modname = 'HWIDMaster-0902.exe'.encode('utf-16-le')
    # 布局：header(32) | dir(4*12) | exc | modlist | mem64list | modname | memdata
    hdr = 32
    ndir = 4
    dir_sz = ndir * 12
    off = hdr + dir_sz

    exc_off = off; exc_len = 8 + 4 + 4 + 8 + 4 + 4 + 8 * 15
    off += exc_len
    mod_off = off; mod_len = 4 + 108
    off += mod_len
    m64_off = off; m64_len = 8 + 8 + 16
    off += m64_len
    name_off = off; off += 4 + len(modname)
    off = (off + 15) & ~15
    data_off = off

    out = bytearray(data_off + len(mem_block))
    out[0:4] = b'MDMP'
    struct.pack_into('<I', out, 4, 0xA793)          # version
    struct.pack_into('<I', out, 8, ndir)
    struct.pack_into('<I', out, 12, hdr)            # dir rva
    struct.pack_into('<II', out, 16, 0, 0)          # flags, checksum
    struct.pack_into('<II', out, 24, 0, 0)          # timestamp, flags2

    # dir
    entries = [(6, exc_len, exc_off), (4, mod_len, mod_off), (9, m64_len, m64_off)]
    # 第 4 条占位（填充为 0）
    for i, (typ, sz, rva) in enumerate(entries):
        struct.pack_into('<III', out, hdr + i * 12, typ, sz, rva)

    # ExceptionStream
    struct.pack_into('<I', out, exc_off, 1234)              # thread id
    struct.pack_into('<I', out, exc_off + 4, 0)             # align
    struct.pack_into('<I', out, exc_off + 8, 0xC0000005)    # code
    struct.pack_into('<I', out, exc_off + 12, 0)            # flags
    struct.pack_into('<Q', out, exc_off + 16, 0x2AF1DD3)    # address
    struct.pack_into('<I', out, exc_off + 24, 2)            # nparams
    struct.pack_into('<Q', out, exc_off + 32, 0)            # p0 (read)
    struct.pack_into('<Q', out, exc_off + 40, 0x2AF1DD3)    # p1 (write)

    # ModuleList
    struct.pack_into('<I', out, mod_off, 1)
    mo = mod_off + 4
    struct.pack_into('<Q', out, mo, BASE)
    struct.pack_into('<I', out, mo + 8, IMG_SIZE)
    struct.pack_into('<I', out, mo + 20, name_off)

    # Memory64List
    struct.pack_into('<Q', out, m64_off, 1)                 # nranges
    struct.pack_into('<Q', out, m64_off + 8, data_off)       # base rva
    struct.pack_into('<Q', out, m64_off + 16, BASE)          # start va
    struct.pack_into('<Q', out, m64_off + 24, len(mem_block))# size

    # name
    struct.pack_into('<I', out, name_off, len(modname))
    out[name_off + 4:name_off + 4 + len(modname)] = modname
    out[data_off:data_off + len(mem_block)] = mem_block

    open(path, 'wb').write(bytes(out))
    print(f'[+] 测试 minidump → {path}  {len(out)} 字节')

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else 'tests/fixture.dmp')
