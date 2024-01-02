import json, sys

symbols = json.load(open(sys.argv[1]))

a = symbols.get('syscall_parasites', [])
b = symbols.get('fself_parasites', [])
c = symbols.get('unsorted_parasites', [])

print('static struct PARASITES(%d) parasites_### = {'%(len(a)+len(b)+len(c)))
print('    .lim_syscall = %d,'%len(a))
print('    .lim_fself = %d,'%(len(a)+len(b)))
print('    .lim_total = %d,'%(len(a)+len(b)+len(c)))

def out(x):
    for i in x:
        print('        {%s, %s},'%(hex(i[0]), ['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15'][i[1]]))

print('    .parasites = {')
print('        /* syscall parasites */')
out(a)
print('        /* fself parasites */')
out(b)
print('        /* unsorted parasites */')
out(c)
print('    }')
print('};')

print('static struct shellcore_patch shellcore_patches_###[] = {')
for i, j in symbols['shellcore_offsets']:
    print('    {%s, "%s"},'%(hex(i), ''.join(map('\\x%02x'.__mod__, bytes.fromhex(j)))))
print('};')
