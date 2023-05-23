import sys, io

if len(sys.argv) >= 3:
    chksz = int(sys.argv[2])
else:
    chksz = 168

with open(sys.argv[1], 'rb') as file:
    while True:
        for idx, i in zip(range(-(chksz//8), 0), ('rip', 'cs', 'eflags', 'rsp', 'ss', 'rax', 'rcx', 'rdx', 'rbx', '---', 'rbp', 'rsi', 'rdi', 'r8 ', 'r9 ', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')):
            q = file.read(8)
            if not q: break
            if i == '---': continue
            print(i, '=', q[::-1].hex(), end=('\n' if idx == -1 else ' '))
        else:
            print()
            continue
        break
