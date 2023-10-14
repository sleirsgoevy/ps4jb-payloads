import sys

with open(sys.argv[1], 'rb') as file:
    kdata = file.read()

kdata_base = int(sys.argv[2], 16)

while True:
    l = input().split(' ')
    i = 0
    while i + 1 < len(l):
        if l[i] == '=' and len(l[i+1]) == 16:
            try: addr = int(l[i+1], 16)
            except ValueError:
                i += 1
                continue
            if addr in range(kdata_base, kdata_base+len(kdata)):
                ss = kdata[addr-kdata_base:kdata.find(b'\0', addr-kdata_base)]
                l.insert(i+2, '(%r)'%ss)
        i += 1
    print(*l)
