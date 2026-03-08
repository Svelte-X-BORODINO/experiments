#define _GNU_SOURCE
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

void analyze_registers(struct user_regs_struct *regs) {
    printf("\n\033[1;32m=== REGISTERS ANALYZE ===\033[0m\n");
    
    // Попытка определить системный вызов
    printf("RAX (return/syscall): 0x%016lx (%ld)\n", regs->rax, regs->rax);
    printf("ORIG_RAX (syscall no.): 0x%016lx\n", regs->orig_rax);
    
    if (regs->orig_rax != (unsigned long)-1 && regs->orig_rax < 400) {
        printf("\nPossible syscall №%ld:\n", regs->orig_rax);
        
        // x86_64 syscall table (часть)
        switch(regs->orig_rax) {
            case 0:   printf("  read(fd=%ld, buf=0x%lx, count=%ld)\n", 
                             regs->rdi, regs->rsi, regs->rdx); break;
            case 1:   printf("  write(fd=%ld, buf=0x%lx, count=%ld)\n", 
                             regs->rdi, regs->rsi, regs->rdx); break;
            case 2:   printf("  open(pathname=0x%lx, flags=0x%lx, mode=0x%lx)\n",
                             regs->rdi, regs->rsi, regs->rdx); break;
            case 3:   printf("  close(fd=%ld)\n", regs->rdi); break;
            case 9:   printf("  mmap(addr=0x%lx, length=%ld, ...)\n",
                             regs->rdi, regs->rsi); break;
            case 12:  printf("  brk(addr=0x%lx)\n", regs->rdi); break;
            case 60:  printf("  exit(status=%ld)\n", regs->rdi); break;
            case 231: printf("  exit_group(status=%ld)\n", regs->rdi); break;
            default:  printf("  Watch https://syscalls.mebeim.net/?table=x86/64/%ld\n",
                             regs->orig_rax); break;
        }
    }
    
    // Анализ указателей
    printf("  RIP: 0x%016lx", regs->rip);
    
    if (regs->rip >= 0x400000 && regs->rip < 0x500000) {
        printf(" -> .text of program");
    } else if (regs->rip >= 0x7f0000000000) {
        printf(" -> library (maybe libc/ld)");
    } else if (regs->rip < 0x400000) {
        printf(" -> [low memory]");
    }
    printf("\n");
    
    printf("  RSP: 0x%016lx (stack)", regs->rsp);
    if (regs->rsp >= 0x7ffffffde000) {
        printf(" [user stack]");
    }
    printf("\n");
    
    // Попытка прочитать строку по RDI если это указатель
    printf("\nArguments (x86_64 calling convention):\n");
    const char *arg_names[] = {"RDI", "RSI", "RDX", "RCX", "R8", "R9"};
    unsigned long args[] = {regs->rdi, regs->rsi, regs->rdx, regs->rcx, regs->r8, regs->r9};
    
    for (int i = 0; i < 6; i++) {
        printf("  %s: 0x%016lx", arg_names[i], args[i]);
        
        // Попытка интерпретации
        if (args[i] == 0) {
            printf(" \033[90m(NULL)\033[0m");
        } else if (args[i] == 1 || args[i] == 2) {
            printf(" \033[33m(fd %ld: %s)\033[0m", 
                   args[i], args[i]==1?"stdout":(args[i]==2?"stderr":"stdin"));
        } else if (args[i] >= 0x600000 && args[i] < 0x700000) {
            printf(" \033[32m[heap/data]\033[0m");
        } else if (args[i] >= 0x7f0000000000) {
            printf(" \033[35m[library]\033[0m");
        }
        printf("\n");
    }
    
    // Анализ флагов
    printf("\nRFLAGS: 0x%016lx\n", regs->eflags);
    const char* flag_names[] = {"CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF"};
    int flag_bits[] = {0, 2, 4, 6, 7, 8, 9, 10, 11};
    
    for (int i = 0; i < 9; i++) {
        int set = (regs->eflags >> flag_bits[i]) & 1;
        printf("  %s: %d%s", flag_names[i], set, set ? " \033[32m✓\033[0m" : "");
        if (i == 3 || i == 6) printf("\n");
    }
    printf("\n");
}

// Безопасное чтение памяти
int safe_peek(pid_t pid, unsigned long addr, long *result) {
    errno = 0;
    *result = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    return (errno == 0);
}

void dump_stack_safe(pid_t pid, unsigned long rsp, int lines) {
    printf("\n\033[1;35m=== THE STACK ===\033[0m\n");
    printf("RSP: 0x%016lx\n\n", rsp);
    
    printf("%-18s %-18s %s\n", "Address", "Value", "Interpretation");
    printf("------------------ ------------------ -----------------\n");
    
    for (int i = 0; i < lines; i++) {
        unsigned long addr = rsp + i * 8;
        long value;
        
        if (!safe_peek(pid, addr, &value)) {
            printf("%016lx   <unavailable>    \033[31m[PAGE FAULT OH NO]\033[0m\n", addr);
            continue;
        }
        
        printf("%016lx   %016lx", addr, value);
        
        // Интерпретация
        if (value == 0) {
            printf("   \033[90mNULL\033[0m");
        } else if (value >= 0x400000 && value < 0x500000) {
            printf("   \033[33m.text+0x%lx\033[0m", value - 0x400000);
        } else if (value >= 0x600000 && value < 0x700000) {
            printf("   \033[32m.data/heap\033[0m");
        } else if (value >= 0x7f0000000000) {
            printf("   \033[35mlibrary\033[0m");
        } else if ((value & 0xFFFF000000000000) == 0x00007fff00000000) {
            printf("   \033[36mstack\033[0m");
        }
        
        // Возвратный адрес?
        if (i == 1) {  // Обычно адрес возврата на стеке
            printf(" \033[90m[possible return address]\033[0m");
        }
        
        printf("\n");
    }
}

void dump_memory_regions(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    
    printf("\n\033[1;34m=== MEMORY REGIONS (/proc/%d/maps) ===\033[0m\n", pid);
    
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("Bro, i cant open %s\n", path);
        return;
    }
    
    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), f) && count < 20) { // Ограничим вывод
        printf("%s", line);
        count++;
    }
    if (count == 20) {
        printf("... (there's only 20 lines)\n", path);
    }
    fclose(f);
}

void print_current_time_safe() {
    time_t now;
    time(&now);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str)-1] = '\0'; // Убираем \n
        printf("Analyze Time: %s\n", time_str);
    } else {
        printf("Analyze Time: <unknown>\n");
    }
}

int main(int argc, char **argv) {
    pid_t pid;
    
    
    if (argc > 1) {
        // Анализ существующего процесса
        pid = atoi(argv[1]);
        printf("PID=%d\n", pid);
        
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
            perror("ptrace");
            return 1;
        }
        waitpid(pid, NULL, 0);
    } else {
        // Создаем тестовый процесс
        pid = fork();
        if (pid == 0) {
            // Дочерний процесс
            printf("Test proccess PID=%d launched\n", getpid());
            
            // Делаем что-то интересное
            ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            
            printf("Allocating memory...\n");
            void *ptr1 = malloc(1024);
            void *ptr2 = calloc(1, 512);
            
            printf("Writing in stdout...\n");
            write(1, "Hello from traced process!\n", 27);
            
            printf("Stopping...\n");
            raise(SIGSTOP);  // Останавливаемся
            
            free(ptr1);
            free(ptr2);
            printf("Test proccess killed\n");
            return 0;
        }
        // Родительский процесс
        waitpid(pid, NULL, 0);
        printf("Child PID=%d\n", pid);
    }
    
    print_current_time_safe();
    
    // Получаем регистры
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("PTRACE_GETREGS");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    
    // Анализируем
    analyze_registers(&regs);
    dump_stack_safe(pid, regs.rsp, 12);
    dump_memory_regions(pid);
    
    // Пытаемся прочитать код по RIP
    printf("\n\033[1;33m=== CODE AROUND %RIP (raw bytes) ===\033[0m\n");
    printf("RIP = 0x%016lx\n\n", regs.rip);
    
    for (long offset = -32; offset <= 32; offset += 8) {
        unsigned long addr = regs.rip + offset;
        long value;
        
        if (safe_peek(pid, addr, &value)) {
            printf("%c0x%016lx: 0x%016lx", 
                   (offset == 0) ? '>' : ' ', addr, value);
            
            if (offset == 0) printf(" \033[1;31m<-- CURRENT INSTRUCTION!\033[0m");
            printf("\n");
        }
    }
    
    // Отсоединяемся
    printf("\n\033[1;32m=== DEBUG END ===\033[0m\n");
    
    if (argc > 1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    } else {
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        waitpid(pid, NULL, 0); // Ждем завершения
    }
    
    return 0;
}