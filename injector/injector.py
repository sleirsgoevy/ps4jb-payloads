import socket, sys, readline

x = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
x.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
x.bind(('', 0))
x.listen(1)

data = open(sys.argv[2] if len(sys.argv) > 2 else 'payload.bin', 'rb').read()

nc = socket.create_connection((sys.argv[1], 9021))

data = data.replace(b'\x04\xd2\xb3\xb3\xb3\xb3', x.getsockname()[1].to_bytes(2, 'big')+socket.inet_aton(nc.getsockname()[0]))
nc.sendall(data)
nc.close()

y = x.accept()[0]

def recvall(n):
    ans = b''
    while len(ans) < n: ans += y.recv(n - len(ans))
    return ans

while True:
    cmd = input('> ')
    if cmd == 'ps':
        y.sendall(b'\1\0\0\0\0\0\0\0')
        while True:
            pid = int.from_bytes(recvall(4), 'little')
            namelen = int.from_bytes(recvall(8), 'little')
            name = recvall(namelen).decode('ascii', 'replace')
            if not pid and not namelen: break
            print(pid, name, sep='\t')
    elif cmd.startswith('mmap '):
        pid = int(cmd[5:])
        y.sendall(b'\2\0\0\0'+pid.to_bytes(4, 'little'))
        mapping = []
        while True:
            low = int.from_bytes(recvall(8), 'little')
            high = int.from_bytes(recvall(8), 'little')
            namelen = int.from_bytes(recvall(8), 'little')
            name = recvall(namelen).decode('ascii', 'replace')
            if not low and not high and not namelen: break
            mapping.append((low, high, name))
        mapping.sort()
        for i, j, k in mapping:
            print('%012x %012x %s'%(i, j, k))
    elif cmd.startswith('inject '):
        pid, file = cmd[7:].split(' ', 1)
        pid = int(pid)
        try: data = open(file, 'rb').read()
        except IOError: print('File not found.')
        else: y.sendall(b'\3\0\0\0'+pid.to_bytes(4, 'little')+len(data).to_bytes(8, 'little')+data)
    elif cmd.startswith('kill '):
        pid = int(cmd[5:])
        y.sendall(b'\4\0\0\0'+pid.to_bytes(4, 'little'))
    elif cmd == 'help':
        print('Supported commands: ps, mmap, inject')
    else:
        print('Unknown command')
