1. Although its fgets, we can overflow, and then code overwrites a PIE pointer inside our overflowed string, so we can leak PIE before hitting null byte.

2. On second iteration, we overflow and overwrite main's return pointer to put puts_got into RDI and then call puts to leak Libc address, and finally we ret to main.

3. Now, we just put "/bin/sh" location of libc into rdi, and ret to system in libc and we will get a shell!.