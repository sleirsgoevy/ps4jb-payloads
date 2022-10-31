import sys

with open(sys.argv[1], 'rb') as file:
    while True:
        for i in ('rip', 'cs', 'eflags', 'rsp', 'ss', 'rax', 'rcx', 'rdx', 'rbx', '---', 'rbp', 'rsi', 'rdi', 'r8 ', 'r9 ', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'):
            q = file.read(8)
            if not q: break
            if i == '---': continue
            print(i, '=', q[::-1].hex(), end=('\n' if i == 'r15' else ' '))
        else:
            print()
            continue
        break
