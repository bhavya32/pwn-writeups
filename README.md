# pwn-writeups

### openECSC
    a. CFP
    b. Avalonia
    c. Exitnction

### pwnable.tw

| S.No | Challenge | Desc |
|------|-----------|------------------|
| 1.    | [calc](pwnable.tw/calc.md) | x32 ROP, int 0x80 syscall |
| 2.    | [3x17](pwnable.tw/3x17.md) | x64 ROP, destuctor hijack with fini_array |
| 3.    | [silver_bullet](pwnable.tw/silver_bullet.md) | x32 ROP, Off By One, BOF |
| 4.    | [seethefile](pwnable.tw/seethefile.md) | x32 FSOP, fclose() hijack |
| 5.    | [hacknote](pwnable.tw/hacknote.md) | Heap- Use After Free, GOT overwrite |
| 6.    | [re-alloc](pwnable.tw/re-alloc.md) | Heap - Double Free, tcache corruption|
| 7.    | [tcache-tear](pwnable.tw/tcache-tear.md) | Heap - Double Free, Fake unsorted bin Chunk|
| 8.    | [sprited-away](pwnable.tw/spirited-away.md) | Heap - Fake fastbin chunk passed to free() |
| 9.    | [babystack](pwnable.tw/babystack.md) | Stack Overlap, Buffer overflow |
| 10.    | [starbound](pwnable.tw/starbound.md) | x32 ROP, libc leak, Used ESP gadget |
| 11.    | [secret-garden](pwnable.tw/secret-garden.md) | Heap - Double Free, Fastbin Corruption, malloc hook hijacking |