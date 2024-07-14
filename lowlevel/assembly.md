# Assembly

## Basics

Main references: [HTB Intro to Assembly Language](https://academy.hackthebox.com/course/preview/intro-to-assembly-language) and [The Art of Exploitation](https://en.wikipedia.org/wiki/Hacking:_The_Art_of_Exploitation).

Assemble code:
```bash
nasm -f elf64 helloWorld.s
```

Link code (with libc functions):
```bash
ld -o fib fib.o --dynamic-linker /lib64/ld-linux-x86-64.so.2
```

Disassemble:
```bash
objdump -M intel -d helloWorld  # .text section
objdump -sj .data helloWorld    # .data section
```

### Registers

| Register Description          |  64-bit | 32-bit | 16-bit | 8-bit |
| ----------------------------- | ------- | ------ | ------ | ----- |
| **Data/Arguments Registers**  |
| Syscall Number/Return value   | rax     | eax    | ax     | al
| Callee Saved                  | rbx     | ebx    | bx     | bl
| 1st arg - Destination operand | rdi     | edi    | di     | dil
| 2nd arg - Source operand      | rsi     | esi    | si     | sil
| 3rd arg                       | rdx     | edx    | dx     | dl
| 4th arg - Loop counter        | rcx     | ecx    | cx     | cl
| 5th arg                       | r8      | r8d    | r8w    | r8b
| 6th arg                       | r9      | r9d    | r9w    | r9b
| **Pointer Registers**         |
| Base Stack Pointer            | rbp     | ebp    | bp     | bpl
| Current/Top Stack Pointer     | rsp     | esp    | sp     | spl
| Instruction Pointer           | rip     | eip    | ip     | ipl

## Assembly instructions


| Instruction                             | Description                                                                               | Example
| --------------------------------------- | ----------------------------------------------------------------------------------------- | -------
| **Data**                                |                                                                                           |
| `mov`                                   | Move data or load immediate data                                                          | `mov rax, 1 ; rax = 1`
| `lea`                                   | Load an address pointing to the value                                                     | `lea rax, [rsp+5] ; rax = rsp+5`
| `xchg`                                  | Swap data between two registers or addresses                                              | `xchg rax, rbx`
| **Unary**                               |                                                                                           |
| `inc`                                   | Increment by 1                                                                            | `inc rax`
| `dec`                                   | Decrement by 1                                                                            | `dec rax`
| **Binary**                              |                                                                                           |
| `add`                                   | Add both operands                                                                         | `add rax, rbx  ; rax = rax + rbx`
| `sub`                                   | Subtract Source from Destination                                                          | `sub rax, rbx  ; rax = rax - rbx`
| `imul`                                  | Multiply both operands                                                                    | `imul rax, rbx ; rax = rax * rbx`
| **Bitwise**                             |                                                                                           |
| `not`                                   | Bitwise NOT                                                                               | `not rax`
| `and`                                   | Bitwise AND                                                                               | `and rax, rbx`
| `or`                                    | Bitwise OR                                                                                | `or rax, rbx`
| `xor`                                   | Bitwise XOR                                                                               | `xor rax, rbx`
| **Loops**                               |                                                                                           |
|                                         | Sets loop (rcx) counter to x                                                              | `mov rcx, 3`
| `loop`                                  | Jumps back to the start of loop until counter reaches 0                                   | `loop exampleLoop`
| **Branching**                           |                                                                                           |
| `jmp`                                   | Jumps to specified label, address, or location                                            | `jmp loop`
| `jz`                                    | Destination equal to Zero                                                                 | `; D = 0`
| `jnz`                                   | Destination Not equal to Zero                                                             | `; D != 0`
| `js`                                    | Destination is Negative                                                                   | `; D < 0`
| `jns`                                   | Destination is Not Negative (i.e. 0 or positive)                                          | `; D >= 0`
| `jg`                                    | Destination Greater than Source                                                           | `; D > S`
| `jge`                                   | Destination Greater than or Equal Source                                                  | `; D >= S`
| `jl`                                    | Destination Less than Source                                                              | `; D < S`
| `jle`                                   | Destination Less than or Equal Source                                                     | `; D <= S`
| `cmp`                                   | Sets RFLAGS by evaluating (first - second)                                                | `cmp rax, rbx`
| **Stack**                               |                                                                                           |
| `push`                                  | Copies the specified register/address to the top of the stack                             | `push rax`
| `pop`                                   | Moves the item at the top of the stack to the specified register/address                  | `pop rax`
| **Functions**                           |                                                                                           |
| `call`                                  | push the next instruction pointer rip to the stack, then jumps to the specified procedure | `call printMessage`
| `ret`                                   | pop the address at rsp into rip, then jump to it                                          | `ret`


