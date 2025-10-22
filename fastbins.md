## Fastbins

Almost same as tcachebins, just shared for every thread. No entry limit like limit of 7 chunks per bin in tcache.

Bin sizes from 0x20, 0x30... to 0xb0 totalling to 10 bins.


### Key Points 
1. Even if you overwrite your fake pointer in fastbin, during allocating that chunk, fastbin checks if that chunk size belongs to that bin or not, limiting the arbitratry write primitive.

### fake chunk structure

1. x32

|addr|content|description|
|----|-------|-----------|
|0|p32(0)|padding just for alignment. can be anything.|
|4|p32(0x40)|setting chunk size as 0x40|
|8|b"A"*0x3c|junk chunk content. again can set 0x3c bytes to anything|
|0x44|p32(0x20)|glibc checks the size of next chunk if its valid or not so we can set any reasonable chunk size. |


2. x64

|addr|content|description|
|----|-------|-----------|
|0|p64(0)|padding just for alignment. can be anything.|
|8|p64(0x40)|setting chunk size as 0x40|
|16|b"A"*0x38|junk chunk content. again can set 0x38 bytes to anything|
|0x48|p64(0x20)|glibc checks the size of next chunk if its valid or not so we can set any reasonable chunk size. |
