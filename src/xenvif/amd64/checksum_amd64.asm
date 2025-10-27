; SPDX-License-Identifier: MIT

.code

;   VOID
;   AccumulateChecksum(
;       IN OUT  PULONG  Accumulator,
;       IN      PUCHAR  BaseVa,
;       IN      ULONG   ByteCount
;       )
public AccumulateChecksum
AccumulateChecksum  proc
    ; rcx:  Accumulator
    ; rdx:  BaseVa
    ; r8:   ByteCount
    ; rax:  temporary accumulator
    ; r9:   scratch

    mov eax, [rcx]

l64:
    cmp r8, 64                      ; eight qwords
    jb l32

    add rax, [rdx]
    adc rax, [rdx + 8]
    adc rax, [rdx + 16]
    adc rax, [rdx + 24]
    adc rax, 0
    mov r9, [rdx + 32]
    add r9, [rdx + 40]
    adc r9, [rdx + 48]
    adc r9, [rdx + 56]
    adc rax, r9
    adc rax, 0

    sub r8, 64
    add rdx, 64
    jmp l64

l32:
    cmp r8, 32                      ; four qwords
    jb l16

    add rax, [rdx]
    adc rax, [rdx + 8]
    adc rax, [rdx + 16]
    adc rax, [rdx + 24]
    adc rax, 0

    sub r8, 32
    add rdx, 32

l16:
    cmp r8, 16                      ; two qwords
    jb l8

    add rax, [rdx]
    adc rax, [rdx + 8]
    adc rax, 0

    sub r8, 16
    add rdx, 16

l8:
    cmp r8, 8                       ; one qword
    jb l4

    add rax, [rdx]
    adc rax, 0

    sub r8, 8
    add rdx, 8

l4:
    cmp r8, 4                       ; one dword
    jb l2

    mov r9d, dword ptr [rdx]
    add rax, r9
    adc rax, 0

    sub r8, 4
    add rdx, 4

l2:
    cmp r8, 2                       ; one word
    jb l1

    movzx r9d, word ptr [rdx]
    add rax, r9
    adc rax, 0

    sub r8, 2
    add rdx, 2

l1:
    cmp r8, 1                       ; last byte
    jb l0

    movzx r9d, byte ptr [rdx]
    add rax, r9
    adc rax, 0

l0:
    mov r9, rax
    shr r9, 32
    add eax, r9d
    adc eax, 0

    mov r9d, eax
    shr r9d, 16
    add ax, r9w
    adc ax, 0

    movzx eax, ax

    mov [rcx], eax
    ret
AccumulateChecksum  endp

end
