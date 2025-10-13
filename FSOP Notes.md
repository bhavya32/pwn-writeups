## FSOP

FSOP is just hijacking streams (std in/out, and files). 


### File Struct
```c
struct _IO_FILE_plus
{
  FILE file; (_IO_FILE)
  const struct _IO_jump_t *vtable;
};

```
_IO_FILE struct contains flags, metadata and stream/buffer pointers, and the vtable contains pointers to various functions which will be called at specific times.

Simple pwntools utility to forge a file struct - 
```py
fileStr = FileStructure(null=null_ptr)
fileStr.vtable=vtable_loc
```

### Important Notes - 
1. Alway set lock to a pointer that points to null. Any operation on file stream first checks if lock is acquired by some other thread.


### fclose
_IO_IS_FILEBUF is set in flags. It can be set by doing - `FileStructure().flags = 0xFFDFFFFF`. If _IO_IS_FILEBUF is not set, the fclose() calls `_IO_finish_t __finish`, otherwise, it calls - `_IO_close_t __close`.

Both finish and close are passed base pointer of _IO_FILE as parameter. I find it easier to overwrite both function pointers with your payload function, just so that you can start you payload parameter at 0th index itself in _IO_File.