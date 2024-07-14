# GDB Basics

In this document I will focus on the x86 (32-bit) architecture, for simplicity.

## gcc

Compile 32-bit program with debugging symbols.
```bash
gcc -m32 -g main.c -o main
gdb -q ./main
```

## ~/.gdbinit

Tell GDB to use Intel syntax:
```bash
echo "set disassembly intel" >> ~/.gdbinit
```

Adding the [GEF](https://github.com/hugsy/gef) extension to `gdb`:
```bash
wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
echo "source ~/.gdbinit-gef.py" >> ~/.gdbinit
```

## GDB commands

| Command
| -------
| list, l (compile with debugging symbols -g)
| break, b
| run, r
| continue, c
| info, i
| info registers, i r, i r eip
| disassemble main, disass main
| examine, x
| print, p
| nexti, ni
| backtrace, bt, bt full

| Examine Format | Size
| -------------- | ----
| o, octal       | b, single byte
| x, hexadecimal | h, halfword (2 bytes)
| u, unsigned    | w, word (4 bytes)
| t, binary      | g, giant, qword (8 bytes)
| i, instruction
| s, string
| d, integer

### Examples:

```bash
(gdb) i r eip
eip            0x8048384        0x8048384 <main+16>
(gdb) x/o 0x8048384
0x8048384 <main+16>:    077042707
(gdb) x/x $eip
0x8048384 <main+16>:    0x00fc45c7
(gdb) x/u $eip
0x8048384 <main+16>:    16532935
(gdb) x/t $eip
0x8048384 <main+16>:    00000000111111000100010111000111
(gdb) x/2x $eip
0x8048384 <main+16>:    0x00fc45c7      0x83000000
```

```bash
(gdb) x/8xb $eip
0x8048384 <main+16>:    0xc7    0x45    0xfc    0x00    0x00    0x00    0x00    0x83
(gdb) x/8xh $eip
0x8048384 <main+16>:    0x45c7  0x00fc  0x0000  0x8300  0xfc7d  0x7e09  0xeb02  0xc713
(gdb) x/8xw $eip
0x8048384 <main+16>:    0x00fc45c7      0x83000000      0x7e09fc7d      0xc713eb02
0x8048394 <main+32>:    0x84842404      0x01e80804      0x8dffffff         0x00fffc45
```

```bash
(gdb) x/i $eip
0x8048384 <main+16>:    mov    DWORD PTR [ebp-4],0x0
(gdb) x/3i $eip
0x8048384 <main+16>:    mov    DWORD PTR [ebp-4],0x0
0x804838b <main+23>:    cmp    DWORD PTR [ebp-4],0x9
0x804838f <main+27>:    jle    0x8048393 <main+31>
(gdb) x/7xb $eip
0x8048384 <main+16>:    0xc7    0x45    0xfc    0x00    0x00    0x00    0x00
```

```bash
(gdb) x/xw &pointer
0xbffff7dc:     0xbffff7e0
(gdb) print &pointer
$1 = (char **) 0xbffff7dc
(gdb) print pointer
$2 = 0xbffff7e0 "Hello, world!\n"
```


## Memory

The memory of a program is divided into segments, which are organized as in the figure below. Also check out `programs/memory_segments.c` for an ilustration.

| Segment | Description
| ------- | -----------
| Text    | Where the instructions, functions, code are stored
| Data    | Initialized global and static variables
| bss     | Uninitialized global and static variables
| Heap    | Malloc memory
| Stack   | Function context (automatic variables)

<img src="fig/memory_segments.png" alt="Description" width="400" height="400">
