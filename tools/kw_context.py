#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kw_context.py —— 在转储/镜像里找关键词并打印上下文（GBK/UTF-16/ASCII），带 RVA 换算"""
import sys, re, json

def _u():
    try: sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception: pass
_u()

KW = ['激活码', '激活', '卡密', '注册码', '机器码', '到期', '已过期', '过期', '试用', '未授权',
      '授权', '有效期', '剩余天数', '充值', '购买', '联系客服', '验证失败', '登录', '账号', '密码',
      'http://', 'https://', '.com', '.cn', 'api/', 'license', 'expired', 'serial', 'hwid']

def main():
    path = sys.argv[1]
    base = int(sys.argv[sys.argv.index('--base') + 1], 0) if '--base' in sys.argv else 0x400000
    d = open(path, 'rb').read()
    print(f'=== {path}  {len(d):,} 字节  base={base:#x} ===')
    total = 0
    for k in KW:
        for enc, label in (('gbk', 'GBK'), ('utf-16-le', 'U16'), ('latin1', 'RAW')):
            try:
                pat = k.encode(enc, errors='ignore')
            except Exception:
                continue
            if len(pat) < 3:
                continue
            start = 0
            shown = 0
            while shown < 3:
                i = d.find(pat, start)
                if i < 0:
                    break
                start = i + 1
                lo = max(0, i - 60)
                hi = min(len(d), i + len(pat) + 60)
                ctx = d[lo:hi]
                # 用同编码解码上下文
                try:
                    txt = ctx.decode(enc, errors='replace')
                except Exception:
                    txt = repr(ctx)
                txt = ''.join(ch if ch.isprintable() else '.' for ch in txt)
                print(f'  [{label}] {k!r}  off=0x{i:x}  (若在模块内 RVA=0x{i-base:x}): ...{txt}...')
                shown += 1
                total += 1
    print(f'[+] 共打印 {total} 处上下文')

if __name__ == '__main__':
    main()
