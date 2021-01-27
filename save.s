; save.s - save execution state on x86 and x86_64

save_x86_64:
   push %rax
   push %rbx
   push %rcx
   push %rdx
   push %rbp
   push %rdi
   push %rsi
   push %r8 
   push %r9 
   push %r10
   push %r11
   push %r12
   push %r13
   push %r14
   push %r15
   ret

restore_x86_64:
   pop %r15
   pop %r14
   pop %r13
   pop %r12
   pop %r11
   pop %r10
   pop %r9
   pop %r8
   pop %rsi
   pop %rdi
   pop %rbp
   pop %rdx
   pop %rcx
   pop %rbx
   pop %rax
   ret
    
save_x86:
    pushal
    ret

restore_x86:
    popal
    ret
