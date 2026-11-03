#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fake_server.py —— 冒充 HWIDMaster 的卡密服务器（干掉服务端的核心件）

已从程序里挖出的服务端情报：
    服务器 IP : 111.229.48.214
    软件 ID   : 271120358
    版本号    : 0902
    握手成功串: Right,初始化成功!
    版本不符  : Right,初始化成功,当前版本不是最新版，不可以登陆!
    失败串    : Error,版本初始化失败，别浪了!
    机器码盐  : HWID-SALT
    密钥候选  : k8F7j2HnQpLxW9vR5TdM3sB6YzX4cV1
                sa;ldfka1;2m31plma;ldm,asl,d
                816F6BA9563B877B87D05467E7435ED996C4EF4233422D37B7F9137B6C6D6432AC70AE243B1B381FF225A7D674D68A87E86D3FCA32F1E794B3C71398B69BBFB5

用法：
    1) 先跑 setup_redirect.ps1（把 111.229.48.214 指到本机）
    2) python fake_server.py --ports 80,8080,8888,9000,9999,3389,5211,27112 --mode log
       —— 所有连进来的包都会以 hex+ascii 打印，用来摸清它的请求格式
    3) 摸清后改成 --mode right，按猜测的格式回 "Right,初始化成功!" 等
"""
import argparse, socket, threading, binascii, time, sys

def hexdump(b, n=512):
    b = b[:n]
    asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in b)
    return binascii.hexlify(b).decode() + '\n    ascii: ' + asc

REPLIES = {
    # 先给最常见的几种形态，逐个试
    'right':  'Right,初始化成功!',
    'right2': 'Right,天才少年,我已经准备好了，你准备好了吗!',
    'ok':     '1',
    'json':   '{"code":200,"msg":"Right,初始化成功!","expire":"2099-12-31","point":999999,"vip":9}',
}

def handle(conn, addr, mode, out):
    conn.settimeout(3)
    try:
        data = b''
        try:
            data = conn.recv(4096)
        except Exception:
            pass
        rec = f"[{time.strftime('%H:%M:%S')}] {addr[0]}:{addr[1]} 收到 {len(data)} 字节\n    {hexdump(data)}\n"
        print(rec, flush=True)
        out.write(rec); out.flush()
        payload = REPLIES.get(mode, REPLIES['right']).encode('gbk', 'replace')
        try:
            conn.sendall(payload)
            print(f"    → 已回 {payload[:80]!r}", flush=True)
        except Exception as e:
            print(f"    → 回包失败 {e}", flush=True)
    finally:
        try: conn.close()
        except Exception: pass

def serve(port, mode, out, host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
    except Exception as e:
        print(f"[!] 端口 {port} 绑定失败: {e}")
        return
    s.listen(8)
    print(f"[+] 监听 {host}:{port} (mode={mode})")
    while True:
        try:
            c, a = s.accept()
        except Exception:
            break
        threading.Thread(target=handle, args=(c, a, mode, out), daemon=True).start()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='111.229.48.214', help='监听地址（redirect 后可用这个 IP）')
    ap.add_argument('--ports', default='80,8080,8888,9000,9999,5211,27112,3389,10086')
    ap.add_argument('--mode', default='log', choices=['log'] + list(REPLIES.keys()))
    ap.add_argument('--log', default='capture.log')
    a = ap.parse_args()
    out = open(a.log, 'a', encoding='utf-8')
    ports = [int(x) for x in a.ports.split(',') if x.strip()]
    print(f"[i] 目标：冒充 {a.host}，监听端口 {ports}，模式 {a.mode}")
    for p in ports:
        threading.Thread(target=serve, args=(p, a.mode, out, a.host), daemon=True).start()
    print("[i] 等待程序连接…（Ctrl+C 结束）")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[i] 退出")

if __name__ == '__main__':
    main()
