import urllib.request, http.client, html

print('global addr__dynlib_dlsym')
print('use64')

with open('syscalls.txt') as file:
    for l in map(str.split, file):
        if not l: continue
        i, j = l
        if j == 'UNKNOWN' or j == 'MISSING' or j == 'HIDDEN':
            continue
        print('section .text.'+i, 'exec')
        print('global', i)
        print(i+':')
        print('cmp qword [rel addr__'+i+'], 0')
        print('jne .resolved')
        print('push rdi')
        print('push rsi')
        print('push rdx')
        print('push rcx')
        print('push r8')
        print('push r9')
        print('push rax')
        print('mov edi, 0x1')
        print('lea rsi, [rel str__'+i+']')
        print('lea rdx, [rel addr__'+i+']')
        print('call [rel addr__dynlib_dlsym]')
        print('pop rax')
        print('pop r9')
        print('pop r8')
        print('pop rcx')
        print('pop rdx')
        print('pop rsi')
        print('pop rdi')
        print('.resolved:')
        print('jmp [rel addr__'+i+']')
        print('str__'+i+':')
        print('db "'+j+'", 0')
        print('section .bss.'+i)
        print('addr__'+i+':')
        print('dq 0')
