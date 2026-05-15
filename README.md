# Cssllt- (securevault terminal)
A low-level access management and encryption auditing system built in x86 NASM Assembly.


A low-level access management and encryption auditing system developed entirely in x86 NASM Assembly** for 32-bit Linux environments. 

This project demonstrates systems-level programming by executing complex control flows, dynamic memory management, and advanced arithmetic operations without the abstraction of high-level languages.

##Core Architecture & Features
Unlike standard high-level applications, this terminal directly interacts with CPU registers (`EAX`, `EBX`, `ECX`, `EDX`) and manages memory via strict kernel system calls (`int 0x80`).

* Dual-Tier Authentication: Byte-by-byte memory string comparison.
* Dynamic Threat Math: Calculates threat coefficients using native `MUL` and `DIV` arithmetic.
* Cryptographic Obfuscation: Implements a bitwise `XOR` payload decrypter and a dynamic variable substitution cipher (Caesar ROT) with strict ASCII bounds checking.
* Contiguous Memory Array: Uses dynamic offset arithmetic `Base_Address + (Index * 5)` to securely write and traverse records in the `.bss` RAM segment.
* **Anti-Forensics Tarpit:** Features nested execution loops (`NOP` cycles) to throttle brute-force scripts, and a zero-fill secure memory erase protocol.
* **Defensive Stack Preservation:** All I/O operations are modularized into custom subroutines that strictly `PUSH` and `POP` states to prevent Linux kernel register clobbering.

##  Compilation and Execution
To compile and run this system, you must be operating in a 32-bit or 64-bit Linux environment (such as Ubuntu or WSL) with the Netwide Assembler (`nasm`) installed.

1. Assemble, link and run the code:
```bash
nasm -f elf32 securevault.asm -o securevault.o

ld -m elf_i386 securevault.o -o securevault
./securevault



## This project was developed as an academic exercise in low-level architecture and malware analysis defense 


