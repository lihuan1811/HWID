#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_fixture.py —— 生成测试用 PE（用来验证 delphi_gate.py / dump2exe.py 是否工作）

构造一个 32 位 PE：
  .text @RVA 0x1000 : 一段"看起来像激活校验"的代码（push 字符串 / call 校验 / test al,al / jz）
  .data @RVA 0x2000 : GBK 字符串 "激活码无效" + "机器码"
用途：在拿到真正的脱壳程序之前，先证明工具链能正确找到"门"并打补丁。
"""
import struct, os, sys

TEXT_RVA, TEXT_VS = 0x1000, 0x1000
DATA_RVA, DATA_VS = 0x2000, 0x1000
IMG_BASE = 0x400000
FILE_ALIGN = 0x200
SEC_ALIGN = 0x1000
HDR_SIZE = 0x200


def build(out_path):
    # ---- .data：GBK 字符串
    s1 = '激活码无效'.encode('gbk') + b'\0'
    s2 = '机器码'.encode('gbk') + b'\0'
    s3 = '请先激活后再使用'.encode('gbk') + b'\0'
    data = bytearray(b'\0' * DATA_VS)
    data[0x00:0x00 + len(s1)] = s1
    data[0x20:0x20 + len(s2)] = s2
    data[0x40:0x40 + len(s3)] = s3
    STR1 = IMG_BASE + DATA_RVA + 0x00
    STR2 = IMG_BASE + DATA_RVA + 0x20

    # ---- .text：伪校验流程
    text = bytearray(b'\xCC' * TEXT_VS)
    code = bytearray()

    def emit(b): code.extend(b)

    # 0x1000: 入口 prologue（Delphi 特征）
    emit(bytes.fromhex('558BEC83C4F0B8'))                # push ebp; mov ebp,esp; add esp,-0x10; mov eax,imm32
    emit(struct.pack('<I', IMG_BASE + TEXT_RVA))         #   → mov eax, 0x401000
    emit(bytes.fromhex('68') + struct.pack('<I', STR1))  # push "激活码无效"
    emit(bytes.fromhex('E8') + struct.pack('<i', 0x30 - (len(code) + 5)))  # call check
    emit(bytes.fromhex('84C0'))                          # test al,al
    emit(bytes.fromhex('7405'))                          # jz  +5   ← 这就是"门"
    emit(bytes.fromhex('33C0C3'))                        # xor eax,eax; ret   (失败分支)
    emit(bytes.fromhex('B80100000 0'.replace(' ', '')))  # mov eax,1           (成功分支)
    emit(bytes.fromhex('C3'))                            # ret

    # 补到 0x30 偏移处放"校验函数"
    while len(code) < 0x30:
        emit(b'\x90')
    # 0x1030: 校验函数：读机器码字符串然后返回 1
    emit(bytes.fromhex('55'))                            # push ebp
    emit(bytes.fromhex('8BEC'))                          # mov ebp,esp
    emit(bytes.fromhex('68') + struct.pack('<I', STR2))  # push "机器码"
    emit(bytes.fromhex('B001'))                          # mov al,1
    emit(bytes.fromhex('5D'))                            # pop ebp
    emit(bytes.fromhex('C3'))                            # ret

    text[0:len(code)] = code

    # ---- 组装文件
    hdr = bytearray(HDR_SIZE)
    hdr[0:2] = b'MZ'
    struct.pack_into('<I', hdr, 0x3C, 0x40)
    hdr[0x40:0x44] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', hdr, 0x44, 0x14c, 2, 0, 0, 0, 0xE0, 0x0102)
    opt = 0x58
    struct.pack_into('<H', hdr, opt, 0x10b)
    struct.pack_into('<I', hdr, opt + 4, TEXT_VS)          # SizeOfCode
    struct.pack_into('<I', hdr, opt + 16, TEXT_RVA)        # EP
    struct.pack_into('<I', hdr, opt + 20, TEXT_RVA)        # BaseOfCode
    struct.pack_into('<I', hdr, opt + 24, DATA_RVA)        # BaseOfData
    struct.pack_into('<I', hdr, opt + 28, IMG_BASE)
    struct.pack_into('<I', hdr, opt + 32, SEC_ALIGN)
    struct.pack_into('<I', hdr, opt + 36, FILE_ALIGN)
    struct.pack_into('<I', hdr, opt + 56, 0x3000)          # SizeOfImage
    struct.pack_into('<I', hdr, opt + 60, HDR_SIZE)        # SizeOfHeaders
    struct.pack_into('<H', hdr, opt + 68, 2)               # GUI
    # 段表
    st = opt + 0xE0
    def sec(name, vs, va, rs, ra, ch, _st=[st]):
        struct.pack_into('<8sIIIIIIHHI', hdr, _st[0], name.encode(), vs, va, rs, ra,
                         0, 0, 0, 0, ch)
        _st[0] += 40
    sec('.text', TEXT_VS, TEXT_RVA, TEXT_VS, HDR_SIZE, 0x60000020)
    sec('.data', DATA_VS, DATA_RVA, DATA_VS, HDR_SIZE + TEXT_VS, 0xC0000040)

    out = bytes(hdr) + bytes(text) + bytes(data)
    open(out_path, 'wb').write(out)
    print(f'[+] 测试样本 → {out_path}  {len(out)} 字节')
    print(f'    EP=0x{TEXT_RVA:x}  门在 RVA 0x1000+0x11 = 0x1011 (jz)')
    print(f'    校验函数 RVA 0x1030')


def build_fake_dump(exe_path, dump_path):
    """把 PE 按内存布局展开，模拟一个"已经在内存里跑起来"的转储"""
    d = open(exe_path, 'rb').read()
    img = bytearray(b'\0' * 0x3000)
    img[0:HDR_SIZE] = d[0:HDR_SIZE]
    img[TEXT_RVA:TEXT_RVA + TEXT_VS] = d[HDR_SIZE:HDR_SIZE + TEXT_VS]
    img[DATA_RVA:DATA_RVA + DATA_VS] = d[HDR_SIZE + TEXT_VS:HDR_SIZE + TEXT_VS + DATA_VS]
    open(dump_path, 'wb').write(bytes(img))
    print(f'[+] 伪造内存转储 → {dump_path}  {len(img)} 字节（基址 0x400000）')


if __name__ == '__main__':
    base = os.path.dirname(os.path.abspath(__file__))
    exe = os.path.join(base, 'fixture_license.exe')
    dmp = os.path.join(base, 'fixture_dump.bin')
    build(exe)
    build_fake_dump(exe, dmp)
