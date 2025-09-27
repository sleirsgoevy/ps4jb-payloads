import urllib.request, http.client, html

def get_freebsd_syscalls():
    data = urllib.request.urlopen('https://raw.githubusercontent.com/freebsd/freebsd/stable/9/sys/kern/syscalls.master').read().decode('ascii')
    data = '\n'.join(i.strip() for i in data.split('\n') if not i.startswith(';')).replace('\\\n', ' ')
    assert data.startswith('$FreeBSD$\n')
    data = data[10:]
    ans = {}
    for i in data.split('\n'):
        i = i.strip()
        if not i or 'STD' not in i.split() or i.startswith('#include'): continue
        name = i.split('(', 1)[0].split()[-1]
        idx = int(i.split()[0])
        ans[idx] = name
    return ans

def get_sony_syscalls():
    # TODO: PS5-specific syscalls
    r = urllib.request.urlopen('http://web.archive.org/web/20210124215126js_/https://psdevwiki.com/ps4/edit/Syscalls')
    data = html.unescape(r.read().decode('latin-1').split('<textarea ', 1)[1].split('</textarea>', 1)[0])
    ans = {}
    for i in data.split('\n'):
        if i.startswith('| '):
            try:
                syscno, fw, syscname, proto, notes = i[2:].split(' || ')
                syscno = int(syscno)
            except ValueError: continue
            if syscname.startswith('sys_'):
                ans[syscno] = syscname[4:]
    return ans

def get_syscalls():
    ans = {}
    ans.update(get_freebsd_syscalls())
    ans.update(get_sony_syscalls())
    return ans

print('section .text')
print('use64')
print('global p_syscall')
print()

for idx, name in sorted(get_syscalls().items()):
    if '#' in name: continue
    print('section .text.'+name+' exec')
    print('global', name)
    print(name+':')
    print('mov eax,', idx)
    if name == 'pipe':
        print('push rbp')
        print('call common_syscall')
        print('pop rbp')
        print('cmp eax, -1')
        print('jz .skip_write')
        print('mov [rdi], eax')
        print('mov [rdi+4], edx')
        print('xor eax, eax')
        print('.skip_write:')
        print('ret')
    else:
        print('jmp common_syscall')

print('''\
section .text.common_syscall exec
common_syscall:
mov r10, [rel p_syscall]
test r10, r10
jnz .jmp
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rax
push rax
mov r10, [rel addr__dynlib_dlsym]
push r10
mov edi, 0x1
lea rsi, [rel getpid_str]
mov rdx, rsp
call r10
pop r10
pop rax
pop rax
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
add r10, 7
mov [rel p_syscall], r10
.jmp:
jmp r10

section .text.__error exec
global __error
__error:
mov r10, [rel addr____error]
test r10, r10
jnz .have_error
push rax
mov edi, 0x1
lea rsi, [rel error_str]
mov rdx, rsp
call [rel addr__dynlib_dlsym]
pop r10
.have_error:
jmp r10

section .text.syscall exec
global syscall
$syscall:
mov rax, rdi
mov rdi, rsi
mov rsi, rdx
mov rdx, rcx
mov rcx, r8
mov r8, r9
mov r9, [rsp+8]
jmp common_syscall

section .rodata.getpid_str
getpid_str:
db "getpid", 0

section .rodata.error_str
error_str:
db "__error", 0

section .bss.addr__dynlib_dlsym
global addr__dynlib_dlsym
addr__dynlib_dlsym:
dq 0

section .bss.addr____error
global addr____error
addr____error:
dq 0

section .bss.p_syscall
p_syscall:
dq 0\
''')
