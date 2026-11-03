#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
win_minidbg.py —— 无 GUI 的迷你调试器：断在 MessageBox / ExitProcess / 崩溃点上，抓调用栈

为什么需要它：
    易语言(VCL)程序对字符串常量用的不是"直接 push 地址"，静态追引用会断。
    最快的办法是在真机上断在 MessageBoxA/W 上，直接读 [esp+8] 的文本 + 栈上的返回地址，
    一步拿到"谁弹的框、在模块里的哪条指令"。

用法（Windows 上跑）：
    python scripts/win_minidbg.py --exe samples\\HWIDMaster-0902.exe \
        --bp user32!MessageBoxW --bp user32!MessageBoxA \
        --bp kernel32!ExitProcess --bp ntdll!NtTerminateProcess \
        --maxhits 4 --json out.json

可选：
    --patch 0x1abd8:eb       运行期把 RVA 处的字节改成 eb（可多次给）
    --patch 0x1abd9:05
    --continue-after-patch   打完补丁继续跑（默认打完就退出）

输出：每次命中打印 文本/标题/返回地址(RVA)/栈，最后写 JSON。
"""
import ctypes
import ctypes.wintypes as wt
import json
import sys
import time
import argparse
import struct

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

DEBUG_ONLY_THIS_PROCESS = 0x00000002
CREATE_NEW_CONSOLE = 0x00000010
INFINITE = 0xFFFFFFFF
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004

PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x1F03FF
MEM_COMMIT = 0x1000
PAGE_EXECUTE_READWRITE = 0x40


class WOW64_CONTEXT(ctypes.Structure):
    _pack_ = 4
    _fields_ = [
        ('ContextFlags', wt.DWORD), ('Dr0', wt.DWORD), ('Dr1', wt.DWORD), ('Dr2', wt.DWORD),
        ('Dr3', wt.DWORD), ('Dr6', wt.DWORD), ('Dr7', wt.DWORD),
        ('FloatSave', wt.BYTE * 112),
        ('SegGs', wt.DWORD), ('SegFs', wt.DWORD), ('SegEs', wt.DWORD), ('SegDs', wt.DWORD),
        ('Edi', wt.DWORD), ('Esi', wt.DWORD), ('Ebx', wt.DWORD), ('Edx', wt.DWORD),
        ('Ecx', wt.DWORD), ('Eax', wt.DWORD), ('Ebp', wt.DWORD), ('Eip', wt.DWORD),
        ('SegCs', wt.DWORD), ('EFlags', wt.DWORD), ('Esp', wt.DWORD), ('SegSs', wt.DWORD),
        ('ExtendedRegisters', wt.BYTE * 512),
    ]


class EXCEPTION_RECORD(ctypes.Structure):
    # 64 位调试器的自然对齐：ExceptionInformation 从 offset 32 开始
    _fields_ = [
        ('ExceptionCode', wt.DWORD), ('ExceptionFlags', wt.DWORD),
        ('ExceptionRecord', ctypes.c_void_p), ('ExceptionAddress', ctypes.c_void_p),
        ('NumberParameters', wt.DWORD), ('Align', wt.DWORD),
        ('ExceptionInformation', ctypes.c_void_p * 15),
    ]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [('ExceptionRecord', EXCEPTION_RECORD), ('dwFirstChance', wt.DWORD)]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ('hFile', wt.HANDLE), ('lpBaseOfDll', ctypes.c_void_p),
        ('dwDebugInfoFileOffset', wt.DWORD), ('nDebugInfoSize', wt.DWORD),
        ('lpImageName', ctypes.c_void_p), ('fUnicode', wt.WORD),
    ]


class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [('dwExitCode', wt.DWORD)]


class DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ('Exception', EXCEPTION_DEBUG_INFO),
        ('LoadDll', LOAD_DLL_DEBUG_INFO),
        ('ExitProcess', EXIT_PROCESS_DEBUG_INFO),
        ('raw', wt.BYTE * 160),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [('dwDebugEventCode', wt.DWORD), ('dwProcessId', wt.DWORD),
                ('dwThreadId', wt.DWORD), ('u', DEBUG_EVENT_UNION)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ('cb', wt.DWORD), ('lpReserved', wt.LPWSTR), ('lpDesktop', wt.LPWSTR),
        ('lpTitle', wt.LPWSTR), ('dwX', wt.DWORD), ('dwY', wt.DWORD),
        ('dwXSize', wt.DWORD), ('dwYSize', wt.DWORD), ('dwXCountChars', wt.DWORD),
        ('dwYCountChars', wt.DWORD), ('dwFillAttribute', wt.DWORD), ('dwFlags', wt.DWORD),
        ('wShowWindow', wt.WORD), ('cbReserved2', wt.WORD), ('lpReserved2', ctypes.c_void_p),
        ('hStdInput', wt.HANDLE), ('hStdOutput', wt.HANDLE), ('hStdError', wt.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [('hProcess', wt.HANDLE), ('hThread', wt.HANDLE),
                ('dwProcessId', wt.DWORD), ('dwThreadId', wt.DWORD)]


# ---- 显式声明签名（否则 64 位句柄会被截断成 32 位）
P = ctypes.c_void_p
k32.ReadProcessMemory.argtypes = [P, P, P, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wt.BOOL
k32.WriteProcessMemory.argtypes = [P, P, P, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = wt.BOOL
k32.VirtualProtectEx.argtypes = [P, P, ctypes.c_size_t, wt.DWORD, ctypes.POINTER(wt.DWORD)]
k32.VirtualProtectEx.restype = wt.BOOL
k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenThread.restype = P
k32.CloseHandle.argtypes = [P]
k32.TerminateProcess.argtypes = [P, wt.UINT]
k32.Wow64GetThreadContext.argtypes = [P, ctypes.POINTER(WOW64_CONTEXT)]
k32.Wow64GetThreadContext.restype = wt.BOOL
k32.K32EnumProcessModules.argtypes = [P, P, wt.DWORD, ctypes.POINTER(wt.DWORD)]
k32.K32EnumProcessModules.restype = wt.BOOL
k32.K32GetModuleInformation.argtypes = [P, P, P, wt.DWORD]
k32.K32GetModuleInformation.restype = wt.BOOL
k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
k32.GetModuleHandleW.restype = P
k32.GetProcAddress.argtypes = [P, ctypes.c_char_p]
k32.GetProcAddress.restype = P
k32.CreateProcessW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, P, P, wt.BOOL, wt.DWORD,
                               P, ctypes.c_wchar_p, ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)]
k32.CreateProcessW.restype = wt.BOOL
k32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wt.DWORD]
k32.WaitForDebugEvent.restype = wt.BOOL
k32.ContinueDebugEvent.argtypes = [wt.DWORD, wt.DWORD, wt.DWORD]
k32.ContinueDebugEvent.restype = wt.BOOL


def rpm(hp, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(P(hp), P(addr), buf, size, ctypes.byref(n)):
        return b''
    return buf.raw[:n.value]


def wpm(hp, addr, data):
    old = wt.DWORD(0)
    k32.VirtualProtectEx(P(hp), P(addr), len(data), PAGE_EXECUTE_READWRITE, ctypes.byref(old))
    n = ctypes.c_size_t(0)
    ok = k32.WriteProcessMemory(P(hp), P(addr), data, len(data), ctypes.byref(n))
    k32.VirtualProtectEx(P(hp), P(addr), len(data), old, ctypes.byref(old))
    return bool(ok)


def read_gbk(hp, addr, maxlen=300):
    if not addr:
        return ''
    raw = rpm(hp, addr, maxlen)
    raw = raw.split(b'\0')[0]
    for enc in ('gbk', 'utf-16-le', 'latin1'):
        try:
            t = raw.decode(enc)
            if t:
                return t
        except Exception:
            continue
    return repr(raw)


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', required=True)
    ap.add_argument('--bp', action='append', default=[], help='dll!func，可多次')
    ap.add_argument('--maxhits', type=int, default=4)
    ap.add_argument('--timeout', type=int, default=60)
    ap.add_argument('--patch', action='append', default=[], help='RVA:HEX，可多次')
    ap.add_argument('--continue-after-patch', action='store_true')
    ap.add_argument('--json')
    a = ap.parse_args()

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = f'"{a.exe}"'
    ok = k32.CreateProcessW(None, cmd, None, None, False,
                            DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                            None, None, ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        raise SystemExit(f'CreateProcess 失败: {ctypes.get_last_error()}')
    hp, hthread, pid = pi.hProcess, pi.hThread, pi.dwProcessId
    print(f'[+] 已启动 pid={pid}')

    # 主模块基址/大小（从 CREATE_PROCESS_DEBUG_EVENT 里拿不到 name，改用查询）
    class MODULEINFO(ctypes.Structure):
        _fields_ = [('lpBaseOfDll', ctypes.c_void_p), ('SizeOfImage', wt.DWORD),
                    ('EntryPoint', ctypes.c_void_p)]
    mod = MODULEINFO()
    mods = (wt.HMODULE * 1024)()
    cb = wt.DWORD(0)
    k32.K32EnumProcessModules(P(hp), ctypes.byref(mods), ctypes.sizeof(mods), ctypes.byref(cb))
    k32.K32GetModuleInformation(P(hp), ctypes.cast(mods[0], P), ctypes.byref(mod), ctypes.sizeof(mod))
    base, size = mod.lpBaseOfDll or 0, mod.SizeOfImage
    print(f'[+] 主模块 base={base:#x} size={size:#x} EP RVA={(mod.EntryPoint or 0) - base:#x}')

    # 解析断点目标 → 目标进程内的地址
    # 系统 DLL 在同一次开机内基址一致，但更稳的做法是每个 DLL 加载事件时用"本进程偏移"换算
    own = {}
    for name in ('user32.dll', 'kernel32.dll', 'ntdll.dll'):
        h = k32.GetModuleHandleW(ctypes.c_wchar_p(name))
        if h:
            own[name.lower()] = h
    def own_addr(dll, fn):
        h = own.get(dll.lower())
        if not h:
            return None
        p = k32.GetProcAddress(h, ctypes.c_char_p(fn.encode()))
        return (p - h) if p else None

    wanted = {}
    for spec in a.bp:
        dll, fn = spec.split('!')
        off = own_addr(dll, fn)
        if off is None:
            print(f'[!] 本进程里找不到 {spec}，跳过')
            continue
        wanted[spec] = off
    print(f'[+] 待下断: {list(wanted.keys())}')

    armed = {}          # addr -> (spec, orig_byte)
    dll_bases = {}
    hits = []
    t0 = time.time()
    ev = DEBUG_EVENT()

    def try_arm():
        for spec, off in list(wanted.items()):
            dll = spec.split('!')[0].lower()
            if dll not in dll_bases:
                continue
            addr = dll_bases[dll] + off
            if addr in armed:
                continue
            b = rpm(hp, addr, 1)
            if not b:
                continue
            if wpm(hp, addr, b'\xcc'):
                armed[addr] = (spec, b[0])
                print(f'[+] 断点已下: {spec} @ {addr:#x}')

    exited = False
    while time.time() - t0 < a.timeout and len(hits) < a.maxhits and not exited:
        if not k32.WaitForDebugEvent(ctypes.byref(ev), 500):
            continue
        code = ev.dwDebugEventCode
        cont = DBG_CONTINUE

        if code == LOAD_DLL_DEBUG_EVENT:
            lp = ev.u.LoadDll.lpBaseOfDll
            # 拿 DLL 名字：读目标进程里 lpImageName（可能是相对地址）
            nm = ''
            try:
                p = ev.u.LoadDll.lpImageName
                if p:
                    nameptr = rpm(hp, p, 4)
                    if nameptr:
                        real = struct.unpack('<I', nameptr)[0]
                        if real:
                            raw = rpm(hp, real, 520)
                            enc = 'utf-16-le' if ev.u.LoadDll.fUnicode else 'latin1'
                            nm = raw.decode(enc, 'replace').split('\0')[0]
            except Exception:
                pass
            if nm:
                dll_bases.setdefault(nm.lower().split('\\')[-1], lp)
            try_arm()

        elif code == EXCEPTION_DEBUG_EVENT:
            er = ev.u.Exception.ExceptionRecord
            ecode = er.ExceptionCode
            eaddr = er.ExceptionAddress or 0
            if ecode == EXCEPTION_BREAKPOINT and eaddr - 1 in armed:
                spec, orig = armed[eaddr - 1]
                # 恢复原字节并把 EIP 退回去，读上下文
                wpm(hp, eaddr - 1, bytes([orig]))
                ht = k32.OpenThread(THREAD_ALL_ACCESS, False, ev.dwThreadId)
                ctx = WOW64_CONTEXT()
                ctx.ContextFlags = 0x10007  # CONTROL|INTEGER|SEGMENTS
                k32.Wow64GetThreadContext(ht, ctypes.byref(ctx))
                ctx.Eip = eaddr - 1
                # 读参数（MessageBoxW: hWnd, lpText, lpCaption, uType）
                args = [struct.unpack('<I', rpm(hp, ctx.Esp + 4 + i * 4, 4) or b'\0\0\0\0')[0]
                        for i in range(4)]
                txt = read_gbk(hp, args[1]) if len(args) > 1 else ''
                cap = read_gbk(hp, args[2]) if len(args) > 2 else ''
                # 栈回溯：扫栈上落在主模块内的返回地址
                stack = rpm(hp, ctx.Esp, 1024)
                rets = []
                for i in range(0, len(stack) - 4, 4):
                    v = struct.unpack_from('<I', stack, i)[0]
                    if base <= v < base + size:
                        rets.append(dict(slot=f'esp+{i:#x}', va=hex(v), rva=hex(v - base)))
                rec = dict(spec=spec, eip=hex(eaddr - 1), esp=hex(ctx.Esp),
                           text=txt, caption=cap, args=[hex(x) for x in args],
                           stack_returns=rets[:12])
                hits.append(rec)
                print(f'\n[命中] {spec}  EIP={eaddr - 1:#x}  ESP={ctx.Esp:#x}')
                print(f'  文本: {txt!r}')
                print(f'  标题: {cap!r}')
                for r in rets[:10]:
                    print(f'  栈 {r["slot"]}: {r["va"]} (RVA {r["rva"]})')
                k32.CloseHandle(ht)

                # 打补丁（可选）
                for spec2 in a.patch:
                    rva_s, hexs = spec2.split(':')
                    rva = int(rva_s, 0)
                    data = bytes.fromhex(hexs)
                    if wpm(hp, base + rva, data):
                        print(f'  [patch] RVA {rva:#x} ← {data.hex()}')
                if not a.continue_after_patch:
                    k32.TerminateProcess(P(hp), 0)
                    cont = DBG_CONTINUE
                else:
                    cont = DBG_CONTINUE
            elif ecode == EXCEPTION_ACCESS_VIOLATION:
                ht = k32.OpenThread(THREAD_ALL_ACCESS, False, ev.dwThreadId)
                ctx = WOW64_CONTEXT(); ctx.ContextFlags = 0x10007
                k32.Wow64GetThreadContext(ht, ctypes.byref(ctx))
                info = [er.ExceptionInformation[i] or 0 for i in range(min(2, er.NumberParameters))]
                stack = rpm(hp, ctx.Esp, 1024)
                rets = []
                for i in range(0, len(stack) - 4, 4):
                    v = struct.unpack_from('<I', stack, i)[0]
                    if base <= v < base + size:
                        rets.append(dict(slot=f'esp+{i:#x}', va=hex(v), rva=hex(v - base)))
                print(f'\n[崩溃] ACCESS_VIOLATION EIP={ctx.Eip:#x} (RVA {ctx.Eip - base:#x})'
                      f' 参数={[hex(x) for x in info]}')
                for r in rets[:10]:
                    print(f'  栈 {r["slot"]}: {r["va"]} (RVA {r["rva"]})')
                hits.append(dict(spec='ACCESS_VIOLATION', eip=hex(ctx.Eip),
                                 rva=hex(ctx.Eip - base), params=[hex(x) for x in info],
                                 stack_returns=rets[:12]))
                k32.CloseHandle(ht)

        elif code == EXIT_PROCESS_DEBUG_EVENT:
            print(f'[+] 进程退出 code={ev.u.ExitProcess.dwExitCode:#x}')
            exited = True

        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

    k32.TerminateProcess(P(hp), 0)
    if a.json:
        json.dump(dict(exe=a.exe, pid=pid, base=hex(base), size=hex(size), hits=hits),
                  open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
        print(f'\n[+] → {a.json}')
    print(f'[+] 命中 {len(hits)} 次')


if __name__ == '__main__':
    main()
