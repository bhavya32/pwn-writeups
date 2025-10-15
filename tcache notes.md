## Tcache C definitions

```c
typedef struct tcache_entry
{
    struct tcache_entry *next;
    struct tcache_perthread_struct *key;
} tcache_entry;

typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

Creates bins of sizes 0x20, 0x30, 0x40... till 0x410. Each bin can store upto 7 chunks, stored as singly linked list.

The `tcache_perthread_struct *key` in tcache_entry is only present to detect double free. Basically when a chunk is freed, glibc goes to that address, and writes the tcache entry there. The key points to the `tcache_perthread_struct` that manages the tcache bins. The double free check just sees if the key matches it goes and sees if the address is also present in tcache bin's linked list.

When a tcache chunk is issued back, key is explicitly zeroed out from allocated region.


### Useful Tricks
 - If you can somehow modify the size metadata of a chunk which is already freed and present in tcache bin, you can bypass the double free check, as the check only traverses linked list from same bin. This will create a duplicate entry in tcache, and can be allotted twice.

 - `realloc(<freed ptr>, some_size)` can behave weirdly, and not remove the tcache entry if present. From my tests, it appears it believes chunk is valid. So if new size is same as current chunk size or next chunk is non alloted, it never queries the tcache.

 - When a chunk address is recovered from tcache, its metadata bytes are not updated/checked. So if you manage to put a fake address in tcache bin, and you have a writable region, you can write fake chunks there, force malloc to use tcache bin address, but when free is called, your fake metadata will still be there. Can be used to fake chunk size or prev pointer.

### Version Differences
 - Present in glibc >= 2.27
 - Double Free key check introduced in glibc >= 2.29
 - Starting from version 2.34, key was changed to a independent random value. This prevents heap location leaks.
