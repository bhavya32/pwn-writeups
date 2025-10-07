### Avalonia

1. We could index negatively.
2. The only problem was, what we were indexing into had to be a valid pointer to a pointer. This eliminated the option to relatively index into GOT and print the resolved function addr.
3. Now comes __dso_handle, which is defined as - `void *__dso_handle = &__dso_handle;`. So its a pointer to itself, and is present at fixed offset in PIE. We try and view note at this offset, and it gives us the PIE leak.
4. First 32 bits of the leak were in timestamp, and next 2 bytes (last/first 2 bytes are mostly 00) were received.
5. Now, we can create a pointer to GOT in our notes, and then call view on our note's content directly, which will give us the actual libc address of GOT entry.
6. Finally we modify printf GOT entry with a one_gadget. We just create a note with content that points to printf GOT - 4 (to adjust for first 4 bytes being auto added time data), and edit the note with one_gadget's address.
7. We get the shell.