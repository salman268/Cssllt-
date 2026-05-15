; ==============================================================================
; SecureVault: Assembly-Level Access & Encryption Auditor
; Author   : [Salman TP084268]
; Assembler: NASM (x86, 32-bit Linux)
;
; 
;   I built this to demonstrate all the math operations (ADD, SUB, MUL, DIV, 
;   INC, DEC) and low-level memory management. It includes a dynamic Caesar 
;   cipher, an XOR decrypter, and a secure array that I manage using offset 
;   arithmetic. I also added strict PUSH/POP stack preservation so the Linux 
;   kernel doesn't break my loops!
; ==============================================================================

section .data
    ; --- Terminal Strings ---
    op_prompt       db  "Initialize SecureOps Terminal.", 0xA, "Enter Operator Initial (A-Z): "
    op_prompt_len   equ $ - op_prompt

    banner          db  0xA, "================================================", 0xA
                    db  "   SecureVault | Terminal Active          ", 0xA
                    db  "================================================", 0xA
    banner_len      equ $ - banner

    prompt_msg      db  0xA, "[?] Enter 4-digit Access PIN: "
    prompt_len      equ $ - prompt_msg

    denied_msg      db  0xA, "[-] Access Denied. Wrong PIN.", 0xA
    denied_len      equ $ - denied_msg

    threat_msg      db  0xA, "[i] Calculating Threat Coefficient...", 0xA, "Threat Score: "
    threat_len      equ $ - threat_msg

    vault_menu_msg  db  0xA, "--- VAULT MENU ---"
                    db  0xA, "[1] Decrypt Vault Payload (XOR)"
                    db  0xA, "[2] Encode Message (Dynamic Caesar)"
                    db  0xA, "[3] Write to Vault Array"
                    db  0xA, "[4] Secure Erase Array (Zero-Fill)"
                    db  0xA, "[5] Exit & Print Report"
                    db  0xA, "Choice: "
    vault_menu_len  equ $ - vault_menu_msg
    
    timeout_msg     db  0xA, "[!] SESSION TIMEOUT. Forcing Exit.", 0xA
    timeout_len     equ $ - timeout_msg

    invalid_msg     db  0xA, "[-] Invalid option. Tarpit engaged... Please wait.", 0xA
    invalid_len     equ $ - invalid_msg

    ; --- Cipher Strings ---
    caesar_prompt   db  0xA, "Enter 5 uppercase letters to encrypt: "
    caesar_plen     equ $ - caesar_prompt
    shift_prompt    db  "Enter encryption shift key (1-9): "
    shift_plen      equ $ - shift_prompt
    caesar_out      db  "Encrypted: "
    caesar_olen     equ $ - caesar_out

    ; --- Array Strings ---
    array_prompt    db  0xA, "Enter 4 chars to store in Vault Array: "
    array_plen      equ $ - array_prompt
    array_full      db  "[-] Array Full. Please Secure Erase first.", 0xA
    array_flen      equ $ - array_full
    array_view_hdr  db  0xA, "[+] Current Vault Array Contents:", 0xA
    array_vlen      equ $ - array_view_hdr
    
    erase_msg       db  0xA, "[!] Anti-Forensics Protocol engaged. RAM zeroed.", 0xA
    erase_len       equ $ - erase_msg

    ; --- Report Strings ---
    rep_hdr         db  0xA, "===================================", 0xA, "     FINAL SECURITY REPORT         ", 0xA, "===================================", 0xA
    rep_hdr_len     equ $ - rep_hdr
    rep_fails       db  "Failed Logins : "
    rep_fails_len   equ $ - rep_fails
    rep_ops         db  0xA, "Menu Ops Run  : "
    rep_ops_len     equ $ - rep_ops
    rep_ciph        db  0xA, "Ciphers Run   : "
    rep_ciph_len    equ $ - rep_ciph

    newline         db  0xA
    newline_len     equ 1
    
    ; --- Configuration ---
    secret_pin      db  "7331"
    pin_len         equ 4
    max_attempts    equ 3

    ; I XOR'd this payload myself. Key is 0x5A ('Z').
    xor_key         equ 0x5A
    enc_payload     db  0x09, 0x13, 0x1D, 0x14, 0x1B, 0x16, 0x08, 0x1B, 0x14, 0x11, 0x05, 0x1B, 0x0A, 0x13, 0x05, 0x11, 0x1F, 0x03, 0x05, 0x1B, 0x19, 0x0E, 0x13, 0x0C, 0x1F
    payload_len     equ $ - enc_payload


section .bss
    ; Reserving raw memory bytes for my variables
    op_initial      resb 2
    user_input      resb 6      
    shift_key       resb 2      
    dec_buffer      resb 30     
    
    fail_counter    resb 1      
    ops_counter     resb 1      
    cipher_counter  resb 1      
    session_timer   resb 1      
    record_index    resb 1      

    ; Reserving exactly 15 bytes for a 3-record array (5 bytes each)
    vault_array     resb 15     


section .text
    global _start

_start:
    ; Starting with a clean slate for my counters
    mov     byte [fail_counter], 0
    mov     byte [ops_counter], 0
    mov     byte [cipher_counter], 0
    mov     byte [session_timer], 20    ; Giving myself 20 actions to present everything
    mov     byte [record_index], 0

    call    init_operator       
    call    auth_loop           
    call    exit_program


init_operator:
    mov     ecx, op_prompt
    mov     edx, op_prompt_len
    call    sys_print

    mov     ecx, op_initial
    mov     edx, 2
    call    sys_read
    ret


auth_loop:
    mov     ecx, prompt_msg
    mov     edx, prompt_len
    call    sys_print

    mov     ecx, user_input
    mov     edx, 5
    call    sys_read

    ; Setting up my pointers to compare the PIN byte-by-byte
    mov     esi, user_input
    mov     edi, secret_pin
    mov     ecx, pin_len

.check_secret:
    mov     al, [esi]
    mov     bl, [edi]
    cmp     al, bl
    jne     .pin_wrong          ; If any byte is wrong, jump to fail state
    inc     esi
    inc     edi
    loop    .check_secret
    jmp     access_granted      ; All 4 bytes matched!

.pin_wrong:
    mov     al, [fail_counter]
    inc     al                  ; ARITHMETIC: Add 1 to fail counter
    mov     [fail_counter], al

    cmp     al, max_attempts    ; Did we hit the 3 attempt limit?
    je      exit_program        ; If yes, lock the system and exit

    mov     ecx, denied_msg
    mov     edx, denied_len
    call    sys_print
    jmp     auth_loop


access_granted:
    mov     ecx, threat_msg
    mov     edx, threat_len
    call    sys_print

    ; --- RUBRIC CHECK: Complex Math (MUL/DIV) ---
    ; Formula: ((Fails * 4) + 2) / 2
    xor     eax, eax        ; Wiping EAX completely so DIV doesn't crash on garbage data
    mov     al, [fail_counter]
    mov     bl, 4           
    mul     bl              ; AX = AL * BL (Multiply fails by 4)
    add     ax, 2           ; Add base level 2
    mov     bl, 2           
    div     bl              ; AL = AX / BL (Divide total by 2)
    add     al, '0'         ; Convert raw integer back into a printable ASCII character
    mov     [user_input], al

    mov     ecx, user_input
    mov     edx, 1
    call    sys_print
    
    call    vault_menu
    ret


vault_menu:
.menu_loop:
    ; --- Session Tarpit (DEC/JE requirement) ---
    mov     al, [session_timer]
    dec     al                  ; Count down every time the menu loads
    mov     [session_timer], al
    cmp     al, 0               ; Out of time?
    je      .timeout

    ; Print standard menu
    mov     ecx, vault_menu_msg
    mov     edx, vault_menu_len
    call    sys_print

    mov     ecx, user_input
    mov     edx, 2
    call    sys_read

    mov     al, [user_input]
    cmp     al, '1'
    je      do_decrypt
    cmp     al, '2'
    je      do_caesar
    cmp     al, '3'
    je      do_array_write
    cmp     al, '4'
    je      do_secure_erase
    cmp     al, '5'
    je      do_exit

    ; --- CPU Tarpit (Nested Loop requirement) ---
    ; If the user types a wrong number, I force the CPU to count down 
    ; 25 million times to simulate a brute-force prevention delay.
    mov     ecx, invalid_msg
    mov     edx, invalid_len
    call    sys_print
    
    mov     ecx, 5000       ; Outer loop counter
.tarpit_outer:
    push    ecx             ; Save outer counter to stack so the inner loop doesn't ruin it
    mov     ecx, 5000       ; Inner loop counter
.tarpit_inner:
    nop                     ; NOP burns 1 clock cycle without doing anything
    loop    .tarpit_inner
    pop     ecx             ; Restore outer counter
    loop    .tarpit_outer

    jmp     .menu_loop

.timeout:
    mov     ecx, timeout_msg
    mov     edx, timeout_len
    call    sys_print
    jmp     do_exit


do_decrypt:
    inc     byte [ops_counter]
    inc     byte [cipher_counter]
    
    mov     esi, enc_payload
    mov     edi, dec_buffer
    mov     ecx, payload_len

.decrypt_loop:
    mov     al,  [esi]
    xor     al,  xor_key        ; Applying XOR bitwise logic. Because it's symmetric, applying it again decrypts it!
    mov     [edi], al
    inc     esi
    inc     edi
    loop    .decrypt_loop

    mov     ecx, dec_buffer
    mov     edx, payload_len
    call    sys_print

    mov     ecx, newline
    mov     edx, newline_len
    call    sys_print
    jmp     vault_menu.menu_loop


 
; Dynamic Variable Caesar Shift (ADD/SUB/CMP/JG Wraparound)
 
do_caesar:
    inc     byte [ops_counter]
    inc     byte [cipher_counter]

    ; 1. Get the string to encrypt
    mov     ecx, caesar_prompt
    mov     edx, caesar_plen
    call    sys_print
    mov     ecx, user_input
    mov     edx, 6              
    call    sys_read

    ; 2. Ask the user how much they want to shift it by
    mov     ecx, shift_prompt
    mov     edx, shift_plen
    call    sys_print
    mov     ecx, shift_key
    mov     edx, 2
    call    sys_read

    ; Convert ASCII input (like '3') into actual math integer (3)
    mov     dl, [shift_key]
    sub     dl, '0'             

    mov     esi, user_input
    mov     ecx, 5              

.shift_loop:
    mov     al, [esi]
    add     al, dl              ; DYNAMIC MATH: Add the variable shift key stored in DL
    cmp     al, 'Z'             ; Did we go past 'Z'?
    jle     .store_char         ; If Less or Equal, it's fine.
    sub     al, 26              ; If Greater, subtract 26 to wrap around back to 'A'

.store_char:
    mov     [esi], al
    inc     esi
    loop    .shift_loop

    mov     ecx, caesar_out
    mov     edx, caesar_olen
    call    sys_print
    mov     ecx, user_input
    mov     edx, 5
    call    sys_print
    jmp     vault_menu.menu_loop


 
; Feature 4: Memory Array Offset Math

do_array_write:
    inc     byte [ops_counter]

    ; Buffer Overflow protection: Checking if array index is 3 or more
    mov     al, [record_index]
    cmp     al, 3
    jge     .array_full

    mov     ecx, array_prompt
    mov     edx, array_plen
    call    sys_print
    mov     ecx, user_input
    mov     edx, 5              
    call    sys_read

    ; CALCULATING OFFSETS: Base Address + (Index * 5 bytes)
    xor     eax, eax            
    mov     al, [record_index]
    mov     bl, 5               
    mul     bl                  
    
    mov     edi, vault_array    ; Base address of my array
    add     edi, eax            ; Add the offset I just calculated
    
    mov     esi, user_input
    mov     ecx, 5
.copy_loop:
    mov     bl, [esi]
    mov     [edi], bl
    inc     esi
    inc     edi
    loop    .copy_loop

    inc     byte [record_index] 

    ; --- Auto-Read the Array to prove it worked ---
    mov     ecx, array_view_hdr
    mov     edx, array_vlen
    call    sys_print

    mov     esi, vault_array    
    xor     ecx, ecx
    mov     cl, [record_index]  

.read_loop:
    push    ecx                 ; Must save ECX because sys_print uses it!
    mov     ecx, esi            
    mov     edx, 5              
    call    sys_print
    pop     ecx                 
    add     esi, 5              ; Jump 5 bytes forward to read the next record
    loop    .read_loop

    jmp     vault_menu.menu_loop

.array_full:
    mov     ecx, array_full
    mov     edx, array_flen
    call    sys_print
    jmp     vault_menu.menu_loop


 
; Feature 5: Secure Memory Erase (Anti-Forensics)
 
do_secure_erase:
    inc     byte [ops_counter]
    
    mov     edi, vault_array    ; Point right at the start of my array
    mov     ecx, 15             ; My array is 15 bytes long total

.zero_loop:
    mov     byte [edi], 0x00    ; Overwriting RAM with absolute zero (null byte)
    inc     edi
    loop    .zero_loop

    mov     byte [record_index], 0 ; Resetting my index back to 0 so I can write again

    mov     ecx, erase_msg
    mov     edx, erase_len
    call    sys_print
    jmp     vault_menu.menu_loop


do_exit:
    ret



;  Exit Report

exit_program:
    mov     ecx, rep_hdr
    mov     edx, rep_hdr_len
    call    sys_print

    mov     ecx, rep_fails
    mov     edx, rep_fails_len
    call    sys_print
    mov     al, [fail_counter]
    add     al, '0'
    mov     [user_input], al
    mov     ecx, user_input
    mov     edx, 1
    call    sys_print

    mov     ecx, rep_ops
    mov     edx, rep_ops_len
    call    sys_print
    mov     al, [ops_counter]
    add     al, '0'
    mov     [user_input], al
    mov     ecx, user_input
    mov     edx, 1
    call    sys_print

    mov     ecx, rep_ciph
    mov     edx, rep_ciph_len
    call    sys_print
    mov     al, [cipher_counter]
    add     al, '0'
    mov     [user_input], al
    mov     ecx, user_input
    mov     edx, 1
    call    sys_print

    mov     ecx, newline
    mov     edx, newline_len
    call    sys_print

    ; Safely killing the program
    mov     eax, 1
    mov     ebx, 0
    int     0x80


; ==============================================================================
; CUSTOM SUBROUTINES (Stack Preservation)
; I made these because writing int 0x80 50 times makes the code messy, and 
; the Linux kernel sometimes overwrites EAX/EBX when it prints, which breaks loops.
; ==============================================================================
sys_print:
    push    eax         ; Saving state to the stack
    push    ebx
    push    ecx
    push    edx

    mov     eax, 4      ; sys_write
    mov     ebx, 1      ; stdout
    int     0x80

    pop     edx         ; Popping state back in exact reverse order
    pop     ecx
    pop     ebx
    pop     eax
    ret

sys_read:
    push    eax
    push    ebx
    push    ecx
    push    edx

    mov     eax, 3      ; sys_read
    mov     ebx, 0      ; stdin
    int     0x80

    pop     edx
    pop     ecx
    pop     ebx
    pop     eax
    ret
