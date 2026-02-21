[bits 16]
[org 0x7c00]
section .text
global main

main:
    xor ah, ah ; режим - установка видеорежима
    mov al, 13h ; режим 0x13 - графика 320x200
    int 0x10 ; устанавливаем
    
    mov bx, 0xA000 
    mov ds, bx ; получается адрес 0xA0000 (VGA-буфер для 320x200)
    ; как он так получается?
    ; физический адрес = сегмент * 16 + смещение
    ; то есть ds(0xA000) * 16 = 0xA0000
    ; и 0xA0000 + bx(0) = 0xA0000
    ; вот так
    xor bx, bx           
.loop:
    mov byte [ds:bx], al ; рисуем!
    inc bx
    inc al
    cmp bx, 64000
    jb .loop

times 510-($-$$) db 0
dw 0xaa55
; а все говорят что ассемблер сложный