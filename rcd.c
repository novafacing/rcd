#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#if __X86_64__
extern void save_x86_64(void);
extern void restore_x86_64(void);
#define save (,) do { save_x86_64(); } while (0x00);
#define restore (,) do { restore_x86_64(); } while (0x00);
#elif __i386__
extern void save_x86(void);
extern void restore_x86(void);
#define save (,) do { save_x86(); } while (0x00);
#define restore (,) do { restore_x86(); } while (0x00);
#else
#error
#endif

#define _NUM_SYS_CHDIR 0x50

#define _WANT_CODE_ADDR 0x70000

#define PATH_MAX 0x1000

typedef struct code {
    char * codeptr;
    size_t sz;
} code;

void usage(const char * execname) {
    fprintf(stderr, "usage: %s [path]\n", execname);
}

pid_t attach_parent(void) {
    pid_t parent = getppid();
    if (parent == 0x01) {
        fprintf(stderr, "ERROR: Do not execute cd as init.\n");
        goto err;
    } else if (parent < 0x00) {
        fprintf(stderr, "ERROR: Unable to execute.\n");
        goto err;
    }

    long pt_res = ptrace(PTRACE_ATTACH, parent, NULL, NULL);
    if (pt_res == -0x01) {
        perror("ptrace");
    }
err:
    return parent;
}

int wait_for_syscall(pid_t parent) {
    int status;
    int err = 0x00;

    while (0x01) {
        if ((err = ptrace(PTRACE_SYSCALL, parent, 0x00, 0x00)) != 0) {
            perror("ptrace");
            return err;
        }

        waitpid(parent, &status, 0x00);

        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
			return 0;
		}

		if (WIFEXITED(status)) {
			return 1;
		}
    }

    return 0;
}


code * compile_chdir(const char * path) {

    #define WORD_SZ 0x02
#if __X86_64__
    #define ROUND_UP (size) ((((size) + (sizeof(uint64_t) - 0x01)) / (sizeof(uint64_t))) * (sizeof(uint64_t)))
    #define SZ_PUSH 0x0b
    #define COPY_OFFSET 0x02
    #define SZ_GETPTR 0x03
    #define SZ_SET_SYS_NUM 0x07
    #define SZ_SYSCALL 0x02
    char push[] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50};
    char getptr[] = {0x48, 0x89, 0xe7};
    char set_sys_num[] = {0x48, 0xc7, 0xc0, 0x50, 0x00, 0x00, 0x00};
    char syscall[] = {0x0f, 0x05};
#elif __i386__
    #define ROUND_UP (size) ((((size) + (sizeof(uint32_t) - 0x01)) / (sizeof(uint32_t))) * (sizeof(uint32_t)))
    #define SZ_PUSH 0x06
    #define COPY_OFFSET 0x01
    #define SZ_GETPTR 0x02
    #define SZ_SET_SYS_NUM 0x05
    #define SZ_SYSCALL 0x02
    char push[] = {0xb8, 0x00, 0x00, 0x00, 0x00, 0x50};
    char getptr[] = {0x89, 0xE5};
    char set_sys_num[] = {0xb8, 0x0c, 0x00, 0x00, 0x00};
    char syscall[] = {0xcd, 0x50};
#else
#error
#endif

    /* x86_64: chdir[rax = 0x50](rdi = const char * filename);
     * 0:  48 b8 | 00 00 00 00 00    movabs rax,0x1000000000000000
     * 7:  00 00 10
     * a:  50                        push   rax
     *
     * 0:  48 31 c0                  xor    rax,rax
     * 0:  48 89 e7                  mov    rdi,rsp
     * 0:  48 c7 c0 50 00 00 00      mov    rax,0x50
     * 0:  0f 05                     syscall
     *
     * x86: chdir[eax = 0xc](ebx = const char * filename);
     * 0:  b8 | 00 00 00 10          mov    eax,0x10000000
     * 5:  50                        push   eax
     *
     * 0:  31 c0                     xor    eax,eax
     * 0:  89 e5                     mov    ebp,esp
     * 0:  b8 0c 00 00 00            mov    eax,0xc
     * 0:  cd 50                   int    0x50
     */

    code * final = (code *)calloc(0x01, sizeof(code));

    size_t path_len = strnlen(path, PATH_MAX) + 1;
    size_t ct_push = ROUND_UP(path_len / sizeof(void *));
    size_t total_sz = ROUND_UP((ct_push * SZ_PUSH) + SZ_GETPTR + SZ_SET_SYS_NUM + SZ_SYSCALL);
    char * code = (char *)calloc(total_sz, sizeof(char));

    char * i = code;
    char * j = path;

    for (; i < code + (ct_push * SZ_PUSH); i += SZ_PUSH, j += sizeof(void *)) {
        memcpy(i, push, SZ_PUSH);
        memcpy(i + COPY_OFFSET, j, sizeof(void *));
    }

    memcpy(i, gtptr, SZ_GETPTR);
    i += SZ_GETPTR;
    memcpy(i, set_sys_num, SZ_SET_SYS_NUM);
    i += SZ_SET_SYS_NUM;
    memcpy(i, syscall, SZ_SYSCALL);
    i += SZ_SYSCALL;

    size_t actual_sz = i - code;

    if (actual_sz < total_sz) {
        memset(i, 0x90, total_sz - actual_sz);
    }

    final->codeptr = code;
    final->sz = total_sz;
    return final;
}

int do_inject_cd(pid_t parent, const char * path) {
    int rv = 0x00;
    struct user_regs_struct regs;
    struct user_regs_struct initial_regs;
    if (ptrace(PTRACE_GETREGS, parent, 0x00, &regs) != 0x00) {
        perror("ptrace");
        rv = 1;
        goto err;
    }

    memcpy(&initial_regs, &regs, sizeof(struct user_regs_struct));

    code * final = compile_chdir(path);
    void * target_addr = NULL;
#if __X86_64__
    target_addr = regs.rip;
#elif __i386__
    target_addr = regs.eip;
#else
#error
#endif

    void * pt_word = NULL;
    char * orig_text = (char *)calloc(final->sz, sizeof(char));
    void * cur_text = NULL;
    
    for (size_t i = 0; i < final->sz; i += sizeof(void *)) {
        memcpy(pt_word, final->codeptr + i, sizeof(void *));
        (long) cur_text = ptrace(PTRACE_PEEKTEXT, parent, target_addr + i, 0x00) != 0x00);
        memcpy(orig_text + i, &cur_text, sizeof(void *));
        if (ptrace(PTRACE_POKETEXT, parent, target_addr + i, pt_word) != 0x00) {
            perror("ptrace");
            rv = 1;
            goto err;
        }
    }


    if (wait_for_syscall(parent)) {
        rv = 1;
        goto err;
    }

    if (wait_for_syscall(parent)) {
        rv = 1;
        goto err;
    }

    for (size_t i = 0; i < final->sz; i += sizeof(void *)) {
        memcpy(pt_word, orig_text + i, sizeof(void *));
        if (ptrace(PTRACE_POKETEXT, parent, target_addr + i, pt_word) != 0x00) {
            perror("ptrace");
            rv = 1;
            goto err;
        }
    }

    if (ptrace(PTRACE_SETREGS, parent, 0x00, &initial_regs) != 0x00) {
        perror("ptrace");
        rv = 1;
        goto err;
    }

err:
    return rv;
}

int main(int argc, char ** argv) {
    if (argc != 0x02) {
        usage(argv[0x00]);
    }

    pid_t parent = 0x00;
    if ((parent = attach_parent()) == 0x01 || parent == 0x00) {
        _exit(0x01);
    }

    do_inject_cd(parent, argv[0x01]);
}
