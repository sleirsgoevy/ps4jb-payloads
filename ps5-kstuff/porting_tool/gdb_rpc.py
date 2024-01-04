import subprocess, os, threading, socket, sys, signal, time, functools

token = os.urandom(16).hex()

rpc_server = '''
import sys
sys.stdin = sys.__stdin__
sys.stdout = sys.__stdout__
print(%r)

while True:
    try: prompt = input()
    except (EOFError, KeyboardInterrupt):
        gdb.execute('quit')
        break
    try: ans = eval(prompt)
    except gdb.error as e: ans = str(e)
    print(repr([[[ans]]]))
'''%token

class DisconnectedException(Exception): pass

class GDB:
    def __init__(self, ps5_ip, ps5_port=9019):
        self.ps5_ip = ps5_ip
        self.ps5_port = ps5_port
        self.payload = None
        self.payload_path = None
        self.r0gdb_cflags = None
        self.kstuff_cflags = None
        self.self_dumper_flags = None
        self.popen = None
        threading.Thread(target=self._monitor, daemon=True).start()
    def bind_socket(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock0:
            sock0.connect((self.ps5_ip, self.ps5_port))
            addr = sock0.getsockname()[0]
        sock = socket.socket()
        sock.bind((addr, 0))
        sock.listen(1)
        return sock, sock.getsockname()
    def use_r0gdb(self, flags=[]):
        if self.popen == None or self.payload != 'r0gdb' or self.r0gdb_cflags != flags:
            self.kill()
            if self.r0gdb_cflags != flags:
                self.build('prosper0gdb', flags)
                self.r0gdb_cflags = flags
                self.kstuff_cflags = None
                self.self_dumper_flags = None
            self.send_payload('prosper0gdb/payload.bin')
            self.connect_gdb()
            self.payload = 'r0gdb'
            return True
        return False
    def use_kstuff(self, flags1=[], flags2=[]):
        if self.popen == None or self.payload != 'kstuff' or self.r0gdb_cflags != flags1 or self.kstuff_cflags != flags2:
            self.kill()
            if self.r0gdb_cflags != flags1:
                self.build('prosper0gdb', flags1)
                self.r0gdb_cflags = flags1
                self.kstuff_cflags = None
                self.self_dumper_flags = None
            if self.kstuff_cflags != flags2:
                self.build('ps5-kstuff', flags2)
                self.kstuff_cflags = flags2
            self.send_payload('ps5-kstuff/payload-gdb.bin')
            self.connect_gdb()
            self.payload = 'kstuff'
            return True
        return False
    def use_self_dumper(self, flags1=[], flags2=[]):
        if self.popen == None or self.payload != 'self_dumper' or self.r0gdb_cflags != flags1 or self.self_dumper_flags != flags2:
            self.kill()
            if self.r0gdb_cflags != flags1:
                self.build('prosper0gdb', flags1)
                self.r0gdb_cflags = flags1
                self.kstuff_cflags = None
                self.self_dumper_flags = None
            if self.self_dumper_flags != flags2:
                self.build('ps5-self-dumper', flags2)
                self.self_dumper_flags = flags2
            self.send_payload('ps5-self-dumper/payload-gdb.bin')
            self.connect_gdb()
            self.payload = 'self_dumper'
            return True
        return False
    def build(self, payload, flags):
        assert not subprocess.call(('make', 'EXTRA_CFLAGS='+' '.join(flags), 'clean', 'all'), cwd='../../'+payload)
    def send_payload(self, path):
        with open('../../'+path, 'rb') as file:
            data = memoryview(file.read())
        while True:
            with socket.socket() as sock:
                sock.settimeout(5)
                print('Connecting to PS5...', end='')
                sys.stdout.flush()
                while True:
                    try: sock.connect((self.ps5_ip, self.ps5_port))
                    except socket.error:
                        sys.stdout.write('.')
                        sys.stdout.flush()
                        time.sleep(1)
                        continue
                    break
                sock.settimeout(None)
                while data:
                    try: chk = sock.send(data)
                    except socket.error: break
                    data = data[chk:]
                else:
                    print(' done')
                    self.payload_path = path
                    if self.payload_path.endswith('.bin'):
                        self.payload_path = self.payload_path[:-4]+'.elf'
                    return
                print(' error, retrying')
    def _monitor(self):
        alive = False
        while True:
            p = subprocess.Popen(('ping', '-W', '5', self.ps5_ip), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, preexec_fn=type(self._monitor)(signal.alarm, 5))
            q = p.communicate()[0]
            if p.wait() > 0 or b'64 bytes from ' not in q:
                if alive:
                    print()
                    print('##################################################################################')
                    print('# Cannot ping PS5. It has probably panicked or hung. Restart the PS5 to proceed. #')
                    print('##################################################################################')
                    alive = False
                q = self.popen
                if q is not None:
                    q.kill()
            else:
                alive = True
    def kill(self):
        self.popen.kill()
        self.popen = None
        self.stdio = None
    def _write(self, chk, tl=None):
        if tl is not None: self.stdio.settimeout(tl-time.time())
        else: self.stdio.settimeout(None)
        try: self.stdio.sendall(chk)
        except OSError:
            self.popen.kill()
            self.popen = None
            self.stdio = None
            raise DisconnectedException("write failed")
    def _read_until(self, ending, tl=None):
        q = b''
        while not q.endswith(ending):
            try:
                if tl is not None: self.stdio.settimeout(tl-time.time())
                else: self.stdio.settimeout(None)
                chk = self.stdio.recv(1)
            except OSError: chk = b''
            if not chk:
                self.popen.kill()
                self.popen = None
                self.stdio = None
                raise DisconnectedException("read failed")
            q += chk
        return q
    def _read_eval(self, tl=None):
        while True:
            ln = self._read_until(b'\n', tl)
            if ln.startswith(b'[[['):
                return eval(ln.decode('ascii'))[0][0][0]
    def connect_gdb(self):
        assert self.popen == None
        print('Connecting GDB... ', end='')
        sys.stdout.flush()
        self.stdio, stdio = socket.socketpair(socket.AF_UNIX)
        with stdio:
            self.popen = subprocess.Popen(('gdb', '../../'+self.payload_path, '-ex', 'target remote '+self.ps5_ip+':1234', '-ex', 'py\n'+rpc_server+'\nend'), stdin=stdio, stdout=stdio, bufsize=0, preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGINT]))
        self._read_until(token.encode('ascii')+b'\n')
        print('done')
    def execute(self, cmd, timeout=None):
        if timeout is not None: timeout += time.time()
        assert self.popen != None
        self._write(('gdb.execute('+repr(cmd)+', to_string=True)\n').encode(), timeout)
        return self._read_eval(timeout)
    def eval(self, expr, timeout=None, how='str'):
        if timeout is not None: timeout += time.time()
        assert self.popen != None
        self._write((how+'(gdb.parse_and_eval('+repr(expr)+'))\n').encode(), timeout)
        return self._read_eval(timeout)
    def ieval(self, expr, timeout=None):
        ans = self.eval(expr, timeout, 'int')
        if not isinstance(ans, int):
            self.kill()
            raise DisconnectedException(ans)
        return ans
    def kill(self):
        if self.popen == None: return
        try: self.execute('p (int)kill(1, 30)', 5)
        except DisconnectedException: return
        self.popen.kill()
        self.popen = None
        self.stdio = None

class SocketWorker:
    def __init__(self, gdb, data, title):
        self.data = self.prepare(data)
        self.sock, (self.host, self.port) = gdb.bind_socket()
        self.title = title
    def __enter__(self):
        self.sock.__enter__()
        self.thr = threading.Thread(target=self.run, daemon=True)
        self.thr.start()
        sys.stdout.write(self.title+'... ')
        sys.stdout.flush()
        return self.host, self.port
    def __exit__(self, tp, err, tb):
        try:
            if tp is not None:
                self.sock.close()
            self.thr.join()
            print()
        finally:
            self.sock.__exit__(tp, err, tb)
    def prepare(self, q):
        return q
    def op(self, sock):
        ...
    def run(self):
        with self.sock.accept()[0] as sock:
            total = 0
            while True:
                q = self.op(sock)
                if not q: break
                total += q
                s = str(total)
                s += '\b'*len(s)
                sys.stdout.write(s)
                sys.stdout.flush()

class BlobReceiver(SocketWorker):
    def op(self, sock):
        q = sock.recv(4096)
        self.data += q
        return len(q)

class BlobSender(SocketWorker):
    def prepare(self, data):
        return memoryview(data)
    def op(self, sock):
        q = sock.send(self.data[:65536])
        self.data = self.data[q:]
        return q

class R0GDB:
    def __init__(self, gdb, cflags=[]):
        self.gdb = gdb
        self.cflags = cflags
        self.trace_size = -1
    def trace_to_raw(self):
        self.gdb.execute('p r0gdb()')
        self.trace_size = -2
    def use_raw_fn(self, fn):
        @functools.wraps(fn)
        def wrapper(do_r0gdb=True, *args, **kwds):
            if self.trace_size not in ((-1, -2) if do_r0gdb else (-1,)):
                self.gdb.kill()
            if self.gdb.use_r0gdb(self.cflags):
                self.trace_size = -1
                fn(*args, **kwds)
            if self.trace_size == -1:
                if do_r0gdb:
                    self.gdb.execute('p r0gdb()')
                    self.trace_size = -2
        return wrapper
    def use_trace_fn(self, fn):
        @functools.wraps(fn)
        def wrapper(trace_size, *args, **kwds):
            if self.trace_size < -1:
                self.gdb.kill()
            if self.gdb.use_r0gdb(self.cflags):
                self.trace_size = -1
                fn(*args, **kwds)
            if trace_size > self.trace_size:
                if ' = void\n' not in self.gdb.execute('p r0gdb_trace('+str(trace_size)+')'):
                    self.gdb.kill()
                    raise DisconnectedException("r0gdb_trace failed")
                self.trace_size = trace_size
        return wrapper
    def do_trace(self, prog, rip, *args):
        assert self.gdb.eval('r0gdb_trace_reset()') == 'void'
        self.gdb.ieval('trace_prog = '+prog)
        self.gdb.ieval('$pc = %s'%rip)
        for i, j in zip(('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'rax'), args):
            self.gdb.ieval('$%s = %s'%(i, j))
        self.gdb.execute('stepi')
    def get_trace(self):
        ans = bytearray()
        with BlobReceiver(self.gdb, ans, 'dumping trace') as addr:
            assert not self.gdb.ieval('r0gdb_trace_send("%s", %d)'%addr)
        return bytes(ans)
    def trace(self, *args):
        self.do_trace(*args)
        return self.get_trace()
