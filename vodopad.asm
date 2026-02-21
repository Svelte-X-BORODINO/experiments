bits 16 
org 0x7c00 
section .text
global main

main:
    mov ax, 0x0013 ; ax = 0013 
    int 0x10 ; 00 - установка видеорежима, 13 - графика, 320x200

    mov ax, 0C0Ah ; 0C - функция рисования пикселя, 0A - цвет(зеленый)
    xor cx, cx ; позиция X = 0
    xor dx, dx ; позиция Y = 0
.loop:
    int 0x10 ; рисовка пикселя
    inc cx ; обновление позиции X
    inc dx ; обновление позиции Y
    inc al ; обновление цвета
    jmp .loop    

times 510-($-$$) db 0
dw 0xaa55