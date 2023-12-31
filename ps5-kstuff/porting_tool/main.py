import sys, json, threading, functools, os.path, collections, tarfile, io, re, time

if 'linux' not in sys.platform:
    print('This tool only supports GNU/Linux! Use Docker or WSL on other OSes.')
    input('Press Enter to exit')
    exit(1)
elif len(sys.argv) not in (3, 4, 5):
    print('usage: main.py <database> <ps5 ip> [port for payload loader] [kernel data dump]')
    exit(0)

import gdb_rpc, traces

gdb = gdb_rpc.GDB(sys.argv[2]) if len(sys.argv) == 3 else gdb_rpc.GDB(sys.argv[2], int(sys.argv[3]))

with open(sys.argv[1]) as file:
    symbols = json.load(file)

available_symbols = set()

def die(*args):
    print(*args)
    exit(1)

def set_symbol(k, v):
    assert k not in symbols or symbols[k] == v
    if k not in symbols:
        print('offset found! %s = %s'%(k, hex(v) if isinstance(v, int) else v))
        symbols[k] = v
        with open(sys.argv[1], 'w') as file:
            json.dump(symbols, file)
        available_symbols.add(k)

if 'allproc' not in symbols:
    die('`allproc` is not defined')

R0GDB_FLAGS = ['-DMEMRW_FALLBACK', '-DNO_BUILTIN_OFFSETS']
SELF_DUMPER_FLAGS = ['-DMEMRW_FALLBACK']
KSTUFF_FLAGS = ['-DMEMRW_FALLBACK', '-DFIRMWARE_PORTING']

r0gdb = gdb_rpc.R0GDB(gdb, R0GDB_FLAGS)

def ostr(x):
    return str(x % 2**64)

def retry_on_error(f):
    @functools.wraps(f)
    def f1(*args):
        while True:
            try: ans = f(*args)
            except gdb_rpc.DisconnectedException:
                print('\nPS5 disconnected, retrying %s...'%f.__name__)
                continue
            if ans == None or (isinstance(ans, tuple) and None in ans):
                print('\nfailed to find some offsets related to %s, retrying...'%f.__name__)
                continue
            return ans
    return f1

derivations = []

def derive_symbol(f):
    derivations.append(f)
    return f

def derive_symbols(*names):
    def inner(f):
        derivations.append((f, names))
        return f
    return inner

@retry_on_error
def dump_kernel():
    if len(sys.argv) == 5 and os.path.exists(sys.argv[4]):
        with open(sys.argv[4], 'rb') as file:
            data = file.read()
        if int.from_bytes(data[8:16], 'little') == len(data) - 16:
            return data[16:], int.from_bytes(data[:8], 'little')
    gdb.use_r0gdb(R0GDB_FLAGS)
    kdata_base = gdb.ieval('kdata_base')
    gdb.eval('offsets.allproc = '+ostr(kdata_base + symbols['allproc']))
    if not gdb.ieval('rpipe'): gdb.eval('r0gdb_init_with_offsets()')
    local_buf = bytearray()
    with gdb_rpc.BlobReceiver(gdb, local_buf, 'dumping kdata') as addr:
        remote_fd = gdb.ieval('r0gdb_open_socket("%s", %d)'%addr)
        remote_buf = gdb.ieval('malloc(1048576)')
        one_second = gdb.ieval('(void*)(uint64_t[2]){1, 0}')
        total_sent = 0
        while total_sent < (134 << 20):
            chk0 = gdb.ieval('copyout(%d, %d, %d)'%(remote_buf, kdata_base+total_sent, min(1048576, (134 << 20) - total_sent)))
            if chk0 <= 0: break
            assert not gdb.ieval('r0gdb_sendall(%d, %d, %d)'%(remote_fd, remote_buf, chk0))
            total_sent += chk0
            #offset = 0
            #while offset < chk0:
            #    chk = gdb.ieval('(int)write(%d, %d, %d)'%(remote_fd, remote_buf+offset, chk0-offset))
            #    assert chk > 0
            #    offset += chk
            #    total_sent += chk
        # this loop is to detect panics while dumping
        while len(local_buf) != total_sent:
            gdb.eval('(int)nanosleep(%d)'%one_second)
        gdb.eval('(int)close(%d)'%remote_fd)
    if len(sys.argv) == 5:
        with open(sys.argv[4], 'wb') as file:
            file.write(kdata_base.to_bytes(8, 'little'))
            file.write(len(local_buf).to_bytes(8, 'little'))
            file.write(local_buf)
    return bytes(local_buf), kdata_base

def get_kernel(_cache=[]):
    if not _cache:
        _cache.append(dump_kernel())
    return _cache[0]

@derive_symbol
@retry_on_error
def idt():
    kernel, kdata_base = get_kernel()
    ks = bytes(kernel[i+2:i+4] == b'\x20\x00' and kernel[i+4] < 8 and kernel[i+5] in (0x8e, 0xee) and kernel[i+8:i+16] == b'\xff\xff\xff\xff\x00\x00\x00\x00' for i in range(0, len(kernel), 16))
    offset = ks.find(b'\1'*256)
    assert ks.find(b'\1'*256, offset+1) < 0
    return offset * 16

@derive_symbol
@retry_on_error
def gdt_array():
    kernel, kdata_base = get_kernel()
    ks = kernel[5::8]
    needle = b'\x00\x00\xf3\xf3\x9b\x93\xfb\xf3\xfb\x8b\x00\x00\x00' * 16
    offset = ks.find(needle)
    assert ks.find(needle, offset+1) < 0
    return offset * 8

@derive_symbol
@retry_on_error
def tss_array():
    kernel, kdata_base = get_kernel()
    gdt_array = symbols['gdt_array']
    tss_array = []
    for i in range(16):
        j = gdt_array + 0x68 * i + 0x48
        tss_array.append(int.from_bytes(kernel[j+2:j+5]+kernel[j+7:j+12], 'little'))
    assert tss_array == list(range(tss_array[0], tss_array[-1]+0x68, 0x68))
    return tss_array[0] - kdata_base

# XXX: relies on in-structure offsets, is it ok?
@derive_symbol
@retry_on_error
def pcpu_array():
    kernel, kdata_base = get_kernel()
    planes = [b''.join(kernel[j+0x34:j+0x38]+kernel[j+0x730:j+0x738] for j in range(i, len(kernel), 0x900)) for i in range(0, 0x900, 4)]
    needle = b''.join(i.to_bytes(4, 'little')*3 for i in range(16))
    indices = [i.find(needle) for i in planes]
    unique_indices = set(indices)
    assert len(unique_indices) == 2 and -1 in unique_indices
    unique_indices.discard(-1)
    i = unique_indices.pop()
    j = indices.index(i)
    indices[j] = -1
    assert set(indices) == {-1}
    assert planes[j].find(needle, i+1) < 0
    return (i // 12) * 0x900 + j * 4

def get_string_xref(name, offset):
    kernel, kdata_base = get_kernel()
    s = kernel.find((name+'\0').encode('ascii'))
    return kernel.find((kdata_base+s).to_bytes(8, 'little')) - offset

@derive_symbol
@retry_on_error
def sysentvec(): return get_string_xref('Native SELF', 0x48)

@derive_symbol
@retry_on_error
def sysentvec_ps4(): return get_string_xref('PS4 SELF', 0x48)

def deref(name, offset=0):
    kernel, kdata_base = get_kernel()
    return int.from_bytes(kernel[symbols[name]+offset:symbols[name]+offset+8], 'little') - kdata_base

@derive_symbol
@retry_on_error
def sysents(): return deref('sysentvec', 8)

@derive_symbol
@retry_on_error
def sysents_ps4(): return deref('sysentvec_ps4', 8)

# XXX: do we need to also find (calculate?) the header size?
@derive_symbol
@retry_on_error
def mini_syscore_header():
    kernel, kdata_base = get_kernel()
    gdb.use_r0gdb(R0GDB_FLAGS)
    remote_fd = gdb.ieval('(int)open("/mini-syscore.elf", 0)')
    remote_buf = gdb.ieval('malloc(4096)')
    assert gdb.ieval('(int)read(%d, %d, 4096)'%(remote_fd, remote_buf)) == 4096
    gdb.execute('set print elements 0')
    gdb.execute('set print repeats 0')
    ans = gdb.eval('((int)close(%d), {unsigned int[1024]}%d)'%(remote_fd, remote_buf))
    assert ans.startswith('{') and ans.endswith('}') and ans.count(',') == 1023, ans
    header = b''.join(int(i).to_bytes(4, 'little') for i in ans[1:-1].split(','))
    return kernel.find(header)

# https://github.com/cheburek3000/meme_dumper/blob/main/source/main.c#L80, guess_kernel_pmap_store_offset
@derive_symbol
@retry_on_error
def kernel_pmap_store():
    kernel, kdata_base = get_kernel()
    needle = (0x1430000 | (4 << 128)).to_bytes(24, 'little')
    i = 0
    ans = []
    while True:
        i = kernel.find(needle, i)
        if i < 0: break
        if any(kernel[i+24:i+32]) and kernel[i+24:i+28] == kernel[i+32:i+36] and not any(kernel[i+36:i+40]):
            ans.append(i - 8)
        i += 1
    return ans[-1]

@derive_symbol
@retry_on_error
def crypt_singleton_array():
    kernel, kdata_base = get_kernel()
    ks = kernel[6::8]
    ks1 = kernel[7::8]
    needle = b'\xff\x00\xff\xff\xff\x00\x00\xff\x00\xff\xff\x00\x00\xff\x00\x00\x00\x00\xff\x00\xff\x00'
    offset = ks.find(needle)
    assert ks.find(needle, offset+1) < 0
    assert ks1[offset:offset+len(needle)] == needle
    return offset * 8

def virt2phys(virt, phys, addr):
    #print(hex(virt), hex(phys), hex(addr))
    assert phys == virt % 2**32
    pml = phys
    for i in range(39, 3, -9):
        idx = (addr >> i) & 511
        pml_next = gdb.ieval('{void*}%d'%(pml+idx*8+virt-phys))
        if pml_next & 128:
            ans = (pml_next & (2**48 - 2**i)) | (addr & (2**i - 1))
            break
        pml = pml_next & (2**48 - 2**12)
    else:
        ans = pml | (addr & 4095)
    #print('->', hex(ans))
    return ans

@derive_symbol
@retry_on_error
def doreti_iret():
    gdb.use_r0gdb(R0GDB_FLAGS)
    kdata_base = gdb.ieval('kdata_base')
    gdb.eval('offsets.allproc = '+ostr(kdata_base + symbols['allproc']))
    if not gdb.ieval('rpipe'): gdb.eval('r0gdb_init_with_offsets()')
    idt = kdata_base + symbols['idt']
    tss_array = kdata_base + symbols['tss_array']
    #buf = gdb.ieval('{void*}%d'%(tss_array+0x1c+4*8))
    buf = gdb.ieval('kmalloc(2048)') + 2048
    for i in range(16):
        tss = tss_array + i * 0x68
        gdb.ieval('{void*}%d = %d'%(tss+0x1c+4*8, buf))
    gdb.ieval('{char}%d = 0'%(idt+1*16+4))
    gdb.ieval('{char}%d = 4'%(idt+13*16+4))
    ptr = gdb.ieval('{void*}({void*}(get_thread()+8)+0x200)+0x300')
    virt = gdb.ieval('{void*}%d'%ptr)
    phys = gdb.ieval('{void*}%d'%(ptr+8))
    buf_phys = virt2phys(virt, phys, buf)
    pages = set()
    while True:
        page = gdb.ieval('kmalloc(2048)') & -4096
        if page in pages: break
        pages.add(page)
    gdb.ieval('(void*)({void*[512]}%d = {%s})'%(page, ', '.join(map(str, ((i<<39)|135 for i in range(512))))))
    gdb.ieval('{void*}%d = %d'%(virt+8, virt2phys(virt, phys, page)|7))
    buf_alias = buf_phys | (1 << 39)
    #print(hex(buf), hex(buf_alias))
    gdb.eval('bind_to_all_available_cpus()')
    assert not gdb.ieval('(int)pthread_create(malloc(8), 0, hammer_thread, (uint64_t[2]){%d, malloc(65536)+65536})'%(buf_alias-32))
    assert not gdb.ieval('bind_to_some_cpu(0)')
    if 'Remote connection closed' in gdb.eval('jmp_setcontext(1ull<<50)'):
        raise gdb_rpc.DisconnectedException('jmp_setcontext')
    pc = gdb.ieval('$pc')
    gdb.kill()
    assert (pc >> 32) == 16
    pc |= (2**64 - 2**32)
    return pc - kdata_base

def do_use_r0gdb_raw():
    kdata_base = gdb.ieval('kdata_base')
    gdb.eval('offsets.allproc = '+ostr(kdata_base + symbols['allproc']))
    if not gdb.ieval('rpipe'): gdb.eval('r0gdb_init_with_offsets()')
    gdb.eval('offsets.doreti_iret = '+ostr(kdata_base + symbols['doreti_iret']))
    gdb.eval('offsets.add_rsp_iret = offsets.doreti_iret - 7')
    gdb.eval('offsets.swapgs_add_rsp_iret = offsets.add_rsp_iret - 3')
    gdb.eval('offsets.idt = '+ostr(kdata_base + symbols['idt']))
    gdb.eval('offsets.tss_array = '+ostr(kdata_base + symbols['tss_array']))

use_r0gdb_raw = r0gdb.use_raw_fn(do_use_r0gdb_raw)

@derive_symbols('push_pop_all_iret', 'rdmsr_start', 'pop_all_iret', 'justreturn')
@retry_on_error
def justreturn():
    use_r0gdb_raw()
    kdata_base = gdb.ieval('kdata_base')
    idt = kdata_base + symbols['idt']
    int244 = (gdb.ieval('{void*}%d'%(idt+244*16+6), 5) % 2**48) * 2**16 + gdb.ieval('{unsigned short}%d'%(idt+244*16), 5)
    print('single-stepping...')
    def step():
        gdb.execute('stepi', 15)
        print(hex(gdb.ieval('$pc')), hex(gdb.ieval('$rsp')))
    gdb.ieval('$pc = %d'%int244)
    step()
    step()
    # step until rdmsr
    rsp0 = gdb.ieval('$rsp')
    rax = gdb.ieval('$rax')
    rdx = gdb.ieval('$rdx')
    pc = gdb.ieval('$pc')
    while True:
        step()
        assert gdb.ieval('$rsp') == rsp0
        if gdb.ieval('$rax') != rax and gdb.ieval('$rdx') != rdx:
            break
        pc = gdb.ieval('$pc')
    rdmsr = pc
    assert gdb.ieval('$pc') == rdmsr + 2
    # step until the function call & through it
    while gdb.ieval('$rsp') == rsp0: step()
    while gdb.ieval('$rsp') != rsp0: step()
    pc = gdb.ieval('$pc')
    step()
    # check that we actually jumped (somewhere...)
    assert (gdb.ieval('$pc') - pc) % 2**64 >= 16
    justreturn = gdb.ieval('$pc') - 16
    gdb.ieval('{void*}$rsp = 0x1337133713371337')
    # step until ld_regs
    while gdb.ieval('$rdi') != 0x1337133713371337:
        pc = gdb.ieval('$pc')
        step()
    pop_all_iret = pc
    # sanity check on justreturn
    rsp0 = gdb.ieval('$rsp')
    gdb.ieval('$pc = %d'%justreturn)
    gdb.ieval('$rax = 0x4141414142424242')
    step()
    assert gdb.ieval('$rsp') == rsp0 - 8 and gdb.ieval('{void*}$rsp') == 0x4141414142424242
    return int244-kdata_base, rdmsr-kdata_base, pop_all_iret-kdata_base, justreturn-kdata_base

@derive_symbol
@retry_on_error
def wrmsr_ret():
    use_r0gdb_raw()
    kdata_base = gdb.ieval('kdata_base')
    gdb.ieval('$pc = %d'%(kdata_base+symbols['justreturn']))
    print('single-stepping...')
    while gdb.ieval('($eflags = 0x102, $rcx)') != 0x80b:
        gdb.execute('stepi')
        print(hex(gdb.ieval('$pc')), hex(gdb.ieval('$rsp')))
    gdb.execute('stepi')
    gdb.execute('stepi')
    wrmsr = gdb.ieval('$pc')
    try: gdb.execute('stepi')
    except gdb_rpc.DisconnectedException: pass
    else: assert False
    return wrmsr-kdata_base

def do_use_r0gdb_trace():
    do_use_r0gdb_raw()
    kdata_base = gdb.ieval('kdata_base')
    gdb.ieval('offsets.rdmsr_start = '+ostr(kdata_base+symbols['rdmsr_start']))
    gdb.ieval('offsets.wrmsr_ret = '+ostr(kdata_base+symbols['wrmsr_ret']))
    gdb.ieval('offsets.nop_ret = '+ostr(kdata_base+symbols['wrmsr_ret']+2))
    if 'rep_movsb_pop_rbp_ret' in symbols:
        gdb.ieval('offsets.rep_movsb_pop_rbp_ret = '+ostr(kdata_base+symbols['rep_movsb_pop_rbp_ret']))
    if 'cpu_switch' in symbols:
        gdb.ieval('offsets.cpu_switch = '+ostr(kdata_base+symbols['cpu_switch']))

use_r0gdb_trace = r0gdb.use_trace_fn(do_use_r0gdb_trace)

def use_self_dumper():
    if gdb.use_self_dumper(R0GDB_FLAGS, SELF_DUMPER_FLAGS):
        do_use_r0gdb_trace()
        kdata_base = gdb.ieval('kdata_base')
        gdb.ieval('offsets.mmap_self_fix_1_end = (offsets.mmap_self_fix_1_start = %s) + 2'%ostr(kdata_base + symbols['mmap_self_fix_1_start']))
        gdb.ieval('offsets.mmap_self_fix_2_end = (offsets.mmap_self_fix_2_start = %s) + 2'%ostr(kdata_base + symbols['mmap_self_fix_2_start']))
        gdb.ieval('offsets.sceSblAuthMgrSmIsLoadable2 = '+ostr(kdata_base + symbols['sceSblAuthMgrSmIsLoadable2']))
        assert 'void' == gdb.eval('set_sigsegv_handler()')

def use_kstuff():
    while not gdb.use_kstuff(R0GDB_FLAGS, KSTUFF_FLAGS):
        gdb.kill()
    do_use_r0gdb_raw()
    kdata_base = gdb.ieval('kdata_base')
    syscall_parasites = symbols['syscall_parasites'] if 'syscall_parasites' in available_symbols else []
    fself_parasites = symbols['fself_parasites'] if 'fself_parasites' in available_symbols else []
    unsorted_parasites = symbols['unsorted_parasites'] if 'unsorted_parasites' in available_symbols else []
    for k in available_symbols:
        if k not in ('pmap_activate_sw', 'shellcore_offsets') and not k.endswith('_parasites'):
            gdb.ieval('offsets.%s = %s'%(k, ostr(kdata_base + symbols[k])))
    gdb.ieval('offsets.nop_ret = '+ostr(kdata_base + symbols['wrmsr_ret'] + 2))
    gdb.ieval('offsets.justreturn_pop = '+ostr(kdata_base + symbols['justreturn'] + 8))
    gdb.ieval('offsets.mmap_self_fix_1_end = offsets.mmap_self_fix_1_start + 2')
    gdb.ieval('offsets.mmap_self_fix_2_end = offsets.mmap_self_fix_2_start + 2')
    parasites = syscall_parasites + fself_parasites + unsorted_parasites
    assert len(parasites) <= 100
    gdb.ieval('parasites_empty.lim_syscall = %d'%(len(syscall_parasites)))
    gdb.ieval('parasites_empty.lim_fself = %d'%(len(syscall_parasites) + len(fself_parasites)))
    gdb.ieval('parasites_empty.lim_total = %d'%(len(parasites)))
    regs = [7, 6, 2, 1, 8, 9, 0, 3, 5, 10, 11, 12, 13, 14, 15, None, None, None, 4]
    for i, (addr, reg) in enumerate(parasites):
        assert reg in range(16)
        gdb.ieval('(parasites_empty.parasites[%d].address = %d, parasites_empty.parasites[%d].reg = %d)'%(i, addr, i, regs.index(reg)))
    args = []
    if 'shellcore_offsets' in available_symbols:
        n = len(symbols['shellcore_offsets'])
        for addr, patch in symbols['shellcore_offsets']:
            patch = bytes.fromhex(patch)
            args.append('(void*)'+hex(addr))
            args.append('"'+''.join(map('\\x%02x'.__mod__, patch))+'"')
            args.append('(void*)'+str(len(patch)))
        gdb.ieval('(shellcore_patches = (void*[%d]){%s}, n_shellcore_patches = %d)'%(3*n, ', '.join(args), n))

def init_kstuff():
    assert 'void' == gdb.eval('kill_thread()')
    assert 'void' == gdb.eval('ignore_signals()')
    gdb.execute('cont')

@derive_symbol
@retry_on_error
def rep_movsb_pop_rbp_ret():
    use_r0gdb_trace(0)
    kdata_base = gdb.ieval('kdata_base')
    pc0 = gdb.ieval('$pc = (void*)dlsym(0x2001, "getpid")')
    ptr = gdb.ieval('ptr_to_leaked_rep_movsq = kmalloc(8)')
    gdb.ieval('trace_prog = leak_rep_movsq')
    gdb.execute('stepi')
    assert gdb.ieval('$pc') == pc0 + 12
    rep_movsq = gdb.ieval('{void*}%d'%ptr)
    r0gdb.trace_to_raw()
    # trace from rep movsq to nearby rep movsb
    rdi = rsi = gdb.ieval('($pc = %d, $rdi = $rsi = $rsp)'%rep_movsq) % 2**64
    while True:
        pc = gdb.ieval('($rcx = 1, $pc)')
        print(hex(pc), hex(rdi), hex(rsi))
        gdb.execute('stepi')
        rdi1 = gdb.ieval('$rdi') % 2**64
        rsi1 = gdb.ieval('$rsi') % 2**64
        if rdi1 == rdi + 1 and rsi1 == rsi + 1 and gdb.ieval('$rcx') == 0:
            break
        rdi = rdi1
        rsi = rsi1
    rep_movsb = pc
    # check epilogue
    gdb.ieval('{void*}$rsp = 0x1234')
    gdb.ieval('{void*}($rsp+8) = 0x5678')
    gdb.execute('stepi')
    gdb.execute('stepi')
    assert gdb.ieval('$rbp == 0x1234 && $rip == 0x5678')
    # set the offset now, so that the tracing does not need to be restarted
    gdb.ieval('offsets.rep_movsb_pop_rbp_ret = '+ostr(rep_movsb))
    return rep_movsb - kdata_base

@derive_symbols('cpu_switch', 'pmap_activate_sw')
@retry_on_error
def cpu_switch():
    use_r0gdb_trace(16777216)
    gdb.ieval('offsets.cpu_switch = 0')
    kdata_base = gdb.ieval('kdata_base')
    candidates = []
    gdb.ieval('call_trace_untrace_on_unaligned = 1')
    while len(candidates) != 1:
        del candidates[:]
        trace = traces.Trace(r0gdb.trace('trace_calls', '(void*)dlsym(0x2001, "_nanosleep")', '(uint64_t[2]){1, 0}', '0'))
        for i in range(1, len(trace)):
            if trace.is_jump(i-1) and trace[i].rsp not in range(trace[i-1].rsp-8, trace[i-1].rsp+9) and trace[i-1].rip >= 2**63 and trace[i].rip >= 2**63:
                candidates.append(i-1)
    gdb.ieval('call_trace_untrace_on_unaligned = 0')
    callee = candidates[0]
    assert trace[callee].rsp % 16 == 0
    caller1 = trace.find_caller(callee)
    assert trace[caller1].rsp % 16 == 8
    caller2 = trace.find_caller(caller1)
    assert trace[caller2].rsp % 16 == 0
    cpu_switch = trace[caller2+1].rip
    # set the offset now, so that the tracing does not need to be restarted
    gdb.ieval('offsets.cpu_switch = '+ostr(cpu_switch))
    return cpu_switch - kdata_base, trace[callee].rip - kdata_base

@derive_symbols('syscall_before', 'syscall_after')
@retry_on_error
def syscall_before():
    use_r0gdb_trace(16777216)
    kdata_base = gdb.ieval('kdata_base')
    trace = traces.Trace(r0gdb.trace('trace_skip_scheduler_only', '(void*)dlsym(0x2001, "getpid")'))
    sys_getpid = gdb.ieval('{void*}%d'%(kdata_base+symbols['sysents']+48*20+8))
    idx_getpid = trace.find_next_rip(0, sys_getpid)
    idx_syscall_after = trace.find_next_instr(idx_getpid-1)
    idx_syscall_before = idx_getpid - 1
    while sys_getpid in trace[idx_syscall_before]:
        idx_syscall_before -= 1
    return trace[idx_syscall_before].rip - kdata_base, trace[idx_syscall_after].rip - kdata_base

@derive_symbols('mov_rdi_cr3', 'mov_cr3_rax')
@retry_on_error
def mov_rdi_cr3():
    use_r0gdb_raw(do_r0gdb=False)
    kdata_base = gdb.ieval('kdata_base')
    thread = gdb.ieval('get_thread()')
    use_r0gdb_raw(do_r0gdb=True)
    gdb.ieval('$pc = '+ostr(kdata_base+symbols['pmap_activate_sw']))
    gdb.ieval('$rdi = '+ostr(thread))
    print('single-stepping...')
    def step():
        gdb.execute('stepi')
        print(hex(gdb.ieval('$pc')))
    step()
    while gdb.ieval('(void*)$rdi') == thread:
        gdb.ieval('$eflags = 0x102')
        pc = gdb.ieval('$pc')
        step()
    mov_rdi_cr3 = pc
    assert gdb.ieval('$pc') - mov_rdi_cr3 == 3
    cr3 = gdb.ieval('(void*)$rdi')
    assert cr3 < 2**39 and not cr3 % 4096
    while gdb.ieval('(void*)$rax') != cr3:
        step()
    # the next instruction is 3-byte, but not "mov cr3, rax"
    step()
    pc = gdb.ieval('$pc')
    while gdb.ieval('$pc') != pc + 3:
        gdb.ieval('$eflags = 0x102')
        pc = gdb.ieval('$pc')
        step()
    # this is probably the one, check that it crashes
    mov_cr3_rax = pc
    gdb.ieval('$pc = '+ostr(pc))
    gdb.ieval('$rax = 0')
    try: gdb.execute('stepi')
    except gdb_rpc.DisconnectedException: pass
    else: assert False, "not mov cr3, rax"
    return mov_rdi_cr3 - kdata_base, mov_cr3_rax - kdata_base

@derive_symbols('dr2gpr_start', 'gpr2dr_1_start', 'gpr2dr_2_start')
@retry_on_error
def dr2gpr_start():
    use_r0gdb_trace(16777216)
    kdata_base = gdb.ieval('kdata_base')
    gdb.ieval('offsets.syscall_after = '+ostr(kdata_base+symbols['syscall_after']))
    # enable the "has debug regs" flag
    td = gdb.ieval('get_thread()')
    pcb = gdb.ieval('{void*}%d'%(td+0x3f8))
    assert gdb.ieval('{int}%d'%(pcb+0x100)) == 24 # sanity check in case offsets have shifted
    gdb.ieval('{int}%d = 26'%(pcb+0x100))
    # trace nanosleep to get the 3rd argument to cpu_switch
    trace = traces.Trace(r0gdb.trace('trace_calls', '(void*)dlsym(0x2001, "_nanosleep")', '(uint64_t[2]){1, 0}', '0'))
    cpu_switch = trace.find_next_rip(0, kdata_base + symbols['cpu_switch'])
    assert td == trace[cpu_switch].rdi
    mtx = trace[cpu_switch].rdx
    # now trace the entirety of cpu_switch
    getpid = gdb.ieval('{void*}%d'%(kdata_base+symbols['sysents']+20*48+8))
    gdb.ieval('fncall_fn = '+ostr(kdata_base+symbols['cpu_switch']))
    gdb.ieval('(fncall_args[0] = fncall_args[1] = %d, fncall_args[2] = %d)'%(td, mtx))
    gdb.ieval('fncall_no_untrace = 1')
    gdb.ieval('sys_getpid = '+ostr(getpid))
    gdb.ieval('offsets.cpu_switch = 0')
    trace2 = traces.Trace(r0gdb.trace('getpid_to_fncall', '(void*)dlsym(0x2001, "getpid")'))
    gdb.ieval('offsets.cpu_switch = '+ostr(kdata_base + symbols['cpu_switch']))
    #globals()['huj'] = trace2
    cpu_switch = trace2.find_next_rip(0, kdata_base + symbols['cpu_switch'])
    # we've traced the dbreg get/set code, now find it using magic values in registers
    dr2gpr_start = j = trace2.find_next_reg(cpu_switch, 'r11', 0xffff4ff0)
    while not trace2.is_jump(dr2gpr_start-1): dr2gpr_start -= 1
    while trace2[j].r11 == 0xffff4ff0: j += 1
    gpr2dr_1_start = trace2.find_next_reg(j, 'r11', 0xffff4ff0)
    while trace2[gpr2dr_1_start].rcx != 0x400: gpr2dr_1_start += 1
    gpr2dr_2_start = trace2.find_next_reg(gpr2dr_1_start, 'rcx', 0xc0011024)
    while not trace2[gpr2dr_2_start].rdx: gpr2dr_2_start += 1
    dr2gpr_start = trace2[dr2gpr_start].rip
    gpr2dr_1_start = trace2[gpr2dr_1_start].rip
    gpr2dr_2_start = trace2[gpr2dr_2_start].rip
    # verify the newly-found offsets
    buf = gdb.ieval('malloc(48)')
    gdb.ieval('offsets.dr2gpr_start = '+ostr(dr2gpr_start))
    gdb.ieval('offsets.gpr2dr_1_start = '+ostr(gpr2dr_1_start))
    gdb.ieval('offsets.gpr2dr_2_start = '+ostr(gpr2dr_2_start))
    assert 'void' == gdb.eval('r0gdb_read_dbregs(%d)'%buf)
    regs = [gdb.ieval('{void*}%d'%(buf+8*i)) for i in range(6)]
    assert regs == [0, 0, 0, 0, 0xffff4ff0, 0x400]
    regs = expected = [0x123, 0x456, 0x789, 0xabc, 0, 0x455]
    for i, j in enumerate(regs): gdb.ieval('{void*}%d = %d'%(buf+8*i, j))
    assert 'void' == gdb.eval('r0gdb_write_dbregs(%d)'%buf)
    for i, j in enumerate(regs): gdb.ieval('{void*}%d = 0'%(buf+8*i))
    assert 'void' == gdb.eval('r0gdb_read_dbregs(%d)'%buf)
    regs = [gdb.ieval('{void*}%d'%(buf+8*i)) for i in range(6)]
    expected[4] = 0xffff4ff0
    assert regs == expected, ("dbregs do not match after readout", list(map(hex, regs)), list(map(hex, expected)))
    return dr2gpr_start - kdata_base, gpr2dr_1_start - kdata_base, gpr2dr_2_start - kdata_base

@derive_symbols('malloc', 'M_something')
@retry_on_error
def malloc():
    while True:
        use_r0gdb_trace(16777216)
        kdata_base = gdb.ieval('kdata_base')
        # use the ipv6 rthdr allocation to find malloc
        # 1224 is a valid size for rthdr, and prosper0gdb already has set_rthdr_size function that wraps the raw ioctl
        remote_sock = gdb.ieval('(int)socket(28, 2, 0)') # udpv6
        assert remote_sock >= 0
        trace = traces.Trace(r0gdb.trace('trace_skip_scheduler_only', 'set_rthdr_size', remote_sock, 1224))
        assert gdb.ieval('$rax') == 0
        malloc_calls = [i for i in range(len(trace)) if trace.is_jump(i) and trace[i+1].rsp == trace[i].rsp-8 and trace[i].rdi == 1224 and trace[i].rdx == 1]
        if len(malloc_calls) == 1: break
        gdb.kill()
    malloc_call = malloc_calls[0]
    malloc = trace[malloc_call+1].rip
    M_something = trace[malloc_call+1].rsi
    return malloc - kdata_base, M_something - kdata_base

@derive_symbol
@retry_on_error
def mprotect_fix_start():
    use_r0gdb_trace(16777216)
    kdata_base = gdb.ieval('kdata_base')
    buf = gdb.ieval('malloc(16384)')
    # get 2 traces to diff
    trace1 = traces.Trace(r0gdb.trace('trace_skip_scheduler_only', '(void*)dlsym(0x2001, "mprotect")', buf, 1, 3))
    trace2 = traces.Trace(r0gdb.trace('trace_skip_scheduler_only', '(void*)dlsym(0x2001, "mprotect")', buf, 1, 7))
    # determine the point of divergence
    i1 = trace1.find_next_rip(0, kdata_base + symbols['syscall_after'])
    i2 = trace2.find_next_rip(0, kdata_base + symbols['syscall_after'])
    j1 = trace1.find_last_callee_ret(trace1.find_last_callee_ret(i1))
    j2 = trace2.find_last_callee_ret(trace2.find_last_callee_ret(i2))
    k1 = trace1.find_caller(j1) + 1
    k2 = trace2.find_caller(j2) + 1
    while k1 < j1 and k2 < j2 and trace1[k1].rip == trace2[k2].rip:
        k1 = trace1.find_next_instr(k1)
        k2 = trace2.find_next_instr(k2)
    assert k1 < j1 and k2 < j2 and trace1[k1-1].rip == trace2[k2-1].rip
    return trace1[k1-1].rip - kdata_base

@derive_symbols('sigaction_fix_start', 'sigaction_fix_end')
@retry_on_error
def sigaction_fix_start():
    use_r0gdb_trace(16777216)
    kdata_base = gdb.ieval('kdata_base')
    buf = gdb.ieval(r'&"\x01"') # sa_handler = SIG_IGN
    tr = [
        traces.Trace(r0gdb.trace('trace_skip_scheduler_only', '(void*)dlsym(0x2001, "getpid")+7', i, buf, 0, 0, 0, 0, 416))
        for i in (15, 9, 17) # SIGTERM, SIGKILL, SIGSTOP
    ]
    i = [i.find_next_rip(0, kdata_base+symbols['syscall_after']) for i in tr]
    j = [i.find_caller(j-1)+1 for i, j in zip(tr, i)]
    k = None
    while len({i[j].rip for i, j in zip(tr, j)}) == 1:
        k = j
        j = [i.find_next_instr(j) for i, j in zip(tr, j)]
    assert k is not None
    source = tr[0][k[0]].rip
    while tr[0][k[0]].rip in (tr[1][k[1]].rip, tr[2][k[2]].rip):
        k = [i.find_next_instr(j) for i, j in zip(tr, k)]
    dst = tr[0][k[0]].rip
    return source - kdata_base, dst - kdata_base

def find_file_string(tail):
    kdata, kdata_base = get_kernel()
    q = kdata.find(tail+b'\0') - 18
    assert kdata.find(tail, q+19) < 0
    assert kdata[q:q+10] == b'W:\\Build\\'
    assert kdata[q+10:q+18].decode('latin-1').isnumeric()
    return q

@derive_symbol
@retry_on_error
def mmap_self_fix_2_start():
    use_r0gdb_trace(16777216)
    kdata_base = gdb.ieval('kdata_base')
    fd = gdb.ieval('(int)open("/system/common/lib/libScePlayerInvitationDialog.sprx", 0)')
    assert fd >= 0
    trace = traces.Trace(r0gdb.trace('trace_skip_scheduler_only', '(void*)dlsym(0x2001, "mmap")', 0, 16384, 1, 0x80001, fd, 0))
    gdb.ieval('(int)close(%d)'%fd)
    i = trace.find_next_rip(0, kdata_base + symbols['syscall_after'])
    for j in range(3):
        i = trace.find_last_callee_ret(i)
    j = trace.find_caller(i) + 1
    while j < i and trace[j+1].rip != trace[j].rip + 16:
        j = trace.find_next_instr(j)
    assert j < i
    return trace[j].rip - kdata_base

@derive_symbol
@retry_on_error
def mmap_self_fix_1_start():
    use_r0gdb_trace(16777216)
    kdata_base = gdb.ieval('kdata_base')
    gdb.ieval('offsets.mmap_self_fix_2_start = '+ostr(kdata_base+symbols['mmap_self_fix_2_start']))
    gdb.ieval('offsets.mmap_self_fix_2_end = '+ostr(kdata_base+symbols['mmap_self_fix_2_start']+2))
    fd = gdb.ieval('(int)open("/mini-syscore.elf", 0)')
    assert fd >= 0
    trace = traces.Trace(r0gdb.trace('fix_mmap_self', '(void*)dlsym(0x2001, "mmap")', 0, 16384, 1, 0x80001, fd, 0))
    gdb.ieval('(int)close(%d)'%fd)
    # find the function that returns a specific error code
    for i in range(len(trace)-1):
        if trace.is_jump(i) and trace[i+1].rsp == trace[i].rsp + 8 and trace[i].rax == 0x800f0d3a:
            break
    else: assert False
    i += 1
    # trace the successful path from there on r0gdb
    r0gdb.trace_to_raw()
    gdb.ieval('$pc = '+ostr(trace[i].rip))
    gdb.ieval('$rax = 0')
    while gdb.ieval('$pc') == trace[i].rip:
        i += 1
        gdb.execute('stepi')
    # we've found the source and destination, verify their relative offset
    source = trace[i-1].rip
    dst = gdb.ieval('$pc')
    assert dst == source + 2
    return source - kdata_base

@derive_symbol
@retry_on_error
def mdbg_call_fix():
    use_r0gdb_trace(16777216)
    kdata_base = gdb.ieval('kdata_base')
    # prepare mdbg_call arguments
    buf = gdb.ieval('malloc(1)')
    arg1 = gdb.ieval('(uint64_t)(uint64_t[4]){1, 0x12}')
    arg2 = gdb.ieval('(uint64_t)(uint64_t[8]){(int)getpid(), (void*)dlsym(0x2001, "getpid"), %d, 1}'%buf)
    arg3 = gdb.ieval('(uint64_t)(uint64_t[4]){}')
    # run mdbg_call with and without the debugger cred
    trace1 = traces.Trace(r0gdb.trace('trace_skip_scheduler_only', '(void*)dlsym(0x2001, "getpid")+7', arg1, arg2, arg3, 0, 0, 0, 573))
    gdb.ieval('{void*}({void*}({void*}(get_thread()+8)+0x40)+88) = 0x4800000000000036')
    trace2 = traces.Trace(r0gdb.trace('trace_skip_scheduler_only', '(void*)dlsym(0x2001, "getpid")+7', arg1, arg2, arg3, 0, 0, 0, 573))
    # find the inner mdbg_call funcion
    i = trace1.find_next_rip(0, kdata_base + symbols['syscall_after'])
    j = trace1.find_last_callee_ret(i-1)
    k1 = trace1.find_caller(j)+1
    k2 = trace2.find_next_rip(0, trace1[k1].rip)
    # trace until we find the function that returns different values (0 vs 1)
    while not (trace1[k1].rax == 0 and trace2[k2].rax == 1):
        k1 = trace1.find_next_instr(k1)
        k2 = trace2.find_next_instr(k2)
    assert trace1.is_jump(k1-1)
    assert trace2.is_jump(k2-1)
    k1 = trace1.find_caller(k1-1)
    k2 = trace1.find_caller(k2-1)
    assert trace1[k1].rip == trace2[k2].rip
    # trace the inner cred checking function to find the point of divergence
    while not (trace1[k1].rax == 0 and trace2[k2].rax == 1):
        k1 += 1
        k2 += 1
    assert trace1[k1].rip == trace2[k2].rip
    return trace1[k1].rip - kdata_base

@derive_symbols(
    'sceSblServiceMailbox',
    'sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize',
    'sceSblServiceMailbox_lr_verifyHeader',
    'sceSblAuthMgrSmIsLoadable2',
    'sceSblServiceMailbox_lr_loadSelfSegment',
    'sceSblServiceMailbox_lr_decryptSelfBlock',
)
@retry_on_error
def sceSblServiceMailbox():
    # we need about 20 MB of log memory, allocate 64 MB just to be sure
    use_r0gdb_trace(1<<26)
    kdata_base = gdb.ieval('kdata_base')
    # fill mmap_self offsets, 'coz we're tracing mmap_self for simplicity
    gdb.ieval('offsets.mmap_self_fix_1_end = (offsets.mmap_self_fix_1_start = %s) + 2'%ostr(kdata_base+symbols['mmap_self_fix_1_start']))
    gdb.ieval('offsets.mmap_self_fix_2_end = (offsets.mmap_self_fix_2_start = %s) + 2'%ostr(kdata_base+symbols['mmap_self_fix_2_start']))
    # open some library
    fd = gdb.ieval('(int)open("/system_ex/common_ex/lib/libSceNKWebKit.sprx", 0)')
    assert fd >= 0
    # now mmap and mlock first 64 KB of the first segment
    trace = traces.Trace(
        r0gdb.trace('fix_mmap_self', '(void*)dlsym(0x2001, "mmap")', 0, 65536, 1, 0x80001, fd, 0) +
        r0gdb.trace('fix_mmap_self', '(void*)dlsym(0x2001, "mlock")', gdb.ieval('(void*)$rax'), 65536)
    )
    # filter callers for each function being called
    lrs = collections.defaultdict(list)
    for i in range(1, len(trace)):
        if trace.is_jump(i-1) and trace[i].rsp == trace[i-1].rsp - 8:
            lrs[trace[i].rip].append(trace[i-1].rip)
    # expected callers for sceSblServiceMailbox:
    # * sceSblAuthMgrSmFinalize (happens sometimes but not always)
    # * verifyHeader
    # * sceSblAuthMgrSmIsLoadable2
    # * loadSelfSegment
    # * decryptSelfBlock (4 times in a row)
    candidates = [i for i, j in lrs.items() if len(j) in (7, 8) and len(set(j)) == len(j) - 3 and len(set(j[-4:])) == 1]
    assert candidates
    # the real mailbox call has rsi = rdx for all invocations. filter by that
    mailbox = [i for i in candidates if all(j.rsi == j.rdx for j in trace if j.rip == i)]
    assert len(mailbox) == 1
    mailbox, = mailbox
    lrs = lrs[mailbox]
    verifyHeader, sceSblAuthMgrSmIsLoadable2, loadSelfSegment, decryptSelfBlock = lrs[-7:-3]
    # for sceSblAuthMgrSmIsLoadable2 we need the function start, not the mailbox callsite
    sceSblAuthMgrSmIsLoadable2 = trace[trace.find_caller(trace.find_next_rip(0, sceSblAuthMgrSmIsLoadable2))+1].rip
    return (
        mailbox - kdata_base,
        lrs[0] + 5 - kdata_base if len(lrs) == 8 else None,
        verifyHeader + 5 - kdata_base,
        sceSblAuthMgrSmIsLoadable2 - kdata_base,
        loadSelfSegment + 5 - kdata_base,
        decryptSelfBlock + 5 - kdata_base,
    )

def run_make_fself(elf_data, auth_info):
    import make_fself
    elf = make_fself.ElfFile(ignore_shdrs=True)
    elf.load(io.BytesIO(elf_data))
    self = make_fself.SignedElfFile(elf, paid=int.from_bytes(auth_info[:8], 'little'), ptype=1, app_version=0, fw_version=0, auth_info=auth_info)
    self_file = io.BytesIO()
    self.save(self_file)
    return self_file.getvalue()

def dump_self(name, path):
    use_self_dumper()
    assert not gdb.ieval('($self_file_%s = &*(struct memfd[1]){dump_elf("%s")}, 0)'%(name, path))
    assert not gdb.ieval('($self_auth_info_%s = &*(struct memfd[1]){dump_elf_auth_info("%s")}, 0)'%(name, path))
    ba = bytearray()
    with gdb_rpc.BlobReceiver(gdb, ba, 'retrieving dumped files') as addr:
        remote_fd = gdb.ieval('r0gdb_open_socket("%s", %d)'%addr)
        assert remote_fd >= 0
        assert gdb.eval('send_tar_entry(%d, $self_file_%s, "binary.elf", (char*)0)'%(remote_fd, name))
        assert gdb.eval('send_tar_entry(%d, $self_auth_info_%s, "binary.elf.auth_info", (char*)0)'%(remote_fd, name))
        assert not gdb.ieval('r0gdb_sendall(%d, malloc(512), 512)'%remote_fd)
        gdb.ieval('(int)close(%d)'%remote_fd)
    files = {}
    for i in tarfile.open(fileobj=io.BytesIO(bytes(ba))):
        files[i.name] = ba[i.offset_data:i.offset_data+i.size]
    elf_data = files['binary.elf']
    auth_info = files['binary.elf.auth_info']
    assert elf_data and len(auth_info) == 0x88
    return elf_data, auth_info

def make_fself_and_upload(name, path):
    full_name = name
    name = name.split('.', 1)[0]
    fd = gdb.ieval('(int)open("/data/%s", 0)'%full_name)
    if fd >= 0:
        assert not gdb.ieval('(int)close(%d)'%fd)
        return True
    elf_data, auth_info = dump_self(name, path)
    self_data = run_make_fself(elf_data, auth_info)
    with gdb_rpc.BlobSender(gdb, self_data, 'writing fself file to /data/%s'%full_name) as addr:
        remote_fd = gdb.ieval('r0gdb_open_socket("%s", %d)'%addr)
        assert remote_fd >= 0
        file_fd = gdb.ieval('(int)open("/data/%s", 0x602, 0777)'%full_name)
        assert file_fd >= 0
        assert not gdb.ieval('r0gdb_sendfile(%d, %d)'%(remote_fd, file_fd))
        assert not gdb.ieval('(int)close(%d) | (int)close(%d)'%(remote_fd, file_fd))
    return False

def ensure_fselfs(fn):
    fn_run = False
    if gdb.popen == None:
        fn()
        fn_run = True
    if (not make_fself_and_upload('libSceLibcInternal.sprx', '/system/common/lib/libSceLibcInternal.sprx')
        or not make_fself_and_upload('libScePlayerInvitationDialog.sprx', '/system/common/lib/libScePlayerInvitationDialog.sprx')
        or not fn_run):
        fn()

@derive_symbol
@retry_on_error
def sceSblServiceMailbox_lr_decryptMultipleSelfBlocks():
    ensure_fselfs(lambda: use_r0gdb_trace(0))
    # set mailbox-related symbols
    kdata_base = gdb.ieval('kdata_base')
    for i in (
        'sceSblServiceMailbox',
        'sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize',
        'sceSblServiceMailbox_lr_verifyHeader',
        'sceSblAuthMgrSmIsLoadable2',
        'sceSblServiceMailbox_lr_loadSelfSegment',
        'sceSblServiceMailbox_lr_decryptSelfBlock',
        'mini_syscore_header',
    ):
        gdb.ieval('offsets.%s = %s'%(i, ostr(kdata_base + symbols[i])))
    gdb.ieval('offsets.mmap_self_fix_1_end = (offsets.mmap_self_fix_1_start = %s) + 2'%ostr(kdata_base + symbols['mmap_self_fix_1_start']))
    gdb.ieval('offsets.mmap_self_fix_2_end = (offsets.mmap_self_fix_2_start = %s) + 2'%ostr(kdata_base + symbols['mmap_self_fix_2_start']))
    #buf = gdb.ieval('malloc(1)')
    #n = 72
    #gdb.ieval('(uint64_t)({void*[%d]}%d = {void*[%d]}&offsets)'%(n, buf, n))
    #gdb.eval('set_offsets_403()')
    #gdb.ieval('(uint64_t)({void*[%d]}&offsets = {void*[%d]}%d)'%(n, n, buf))
    # map 64k of a fake self
    gdb.ieval('do_fself = 31')
    r0gdb.do_trace('trace_mailbox', '(void*)dlsym(0x2001, "mmap")', 0, 65536, 1, 0x80001, '(int)open("/data/libSceLibcInternal.sprx", 0)', 0)
    assert not (gdb.ieval('$eflags') & 1), gdb.ieval('$rax')
    # the latter check will hang. arm a SIGALRM to interrupt us, 'coz sending ^C will break the python repl
    gdb.execute('handle SIGALRM print stop nopass')
    buf = gdb.ieval('malloc(sizeof(struct sigaction))')
    assert not gdb.ieval('(int)sigaction(2, 0, %s)'%ostr(buf))
    assert not gdb.ieval('(int)sigaction(14, %s, 0)'%ostr(buf))
    assert not gdb.ieval('((int(*)(void))dlsym(2, "alarm"))(10)')
    # try to mlock it in one go. decryptMultipleSelfBlocks should get called
    gdb.ieval('do_fself = 63')
    r0gdb.do_trace('trace_mailbox', '(void*)dlsym(0x2001, "mlock")', '$rax', 65536)
    # check that the syscall hasn't completed normally
    assert not gdb.ieval('$pc == (void*)dlsym(0x2001, "mlock") + 12')
    # now get its lr
    lr = gdb.ieval('mailbox_lr[0]')
    assert lr and not gdb.ieval('mailbox_lr[1]')
    # the process is now fucked. panic now
    try: gdb.eval('{short}(get_thread()+14) = 0xdeb7')
    except gdb_rpc.DisconnectedException: pass
    return lr - kdata_base

@derive_symbols('copyin', 'copyout')
@retry_on_error
def copyin():
    use_r0gdb_trace(16777216)
    kdata_base = gdb.ieval('kdata_base')
    pipebuf = gdb.ieval('(void*)malloc(123)')
    assert not gdb.ieval('(int)pipe(%d)'%pipebuf)
    fd1 = gdb.ieval('{int}%d'%pipebuf)
    fd2 = gdb.ieval('{int}%d'%(pipebuf+4))
    gdb.ieval('jprog = (void*[1]){0}')
    trace1 = traces.Trace(r0gdb.trace('do_jprog', '(void*)dlsym(0x2001, "_write")', fd2, pipebuf, 123))
    trace2 = traces.Trace(r0gdb.trace('do_jprog', '(void*)dlsym(0x2001, "_read")', fd1, pipebuf, 123))
    candidates1 = [i for i in range(1, len(trace1)) if trace1.is_jump(i-1) and trace1[i].rsp == trace1[i-1].rsp - 8 and trace1[i].rdi == pipebuf and trace1[i].rdx == 123]
    assert len(candidates1) == 1
    copyin = trace1[candidates1[0]].rip
    kernel_buf = trace1[candidates1[0]].rsi
    candidates2 = [i for i in range(1, len(trace2)) if trace2.is_jump(i-1) and trace2[i].rsp == trace2[i-1].rsp - 8 and trace2[i].rdi == kernel_buf and trace2[i].rsi == pipebuf and trace2[i].rdx == 123]
    assert len(candidates2) == 1
    copyout = trace2[candidates2[0]].rip
    return copyin - kdata_base, copyout - kdata_base

def fetch_logs(cpu):
    uelf_base = gdb.ieval('uelf_bases[%d]'%cpu)
    offset = int(os.popen("nm ../uelf/uelf | grep ' log$'").read().split()[0], 16)
    gdb.execute('set print elements 0')
    gdb.execute('set print repeats 0')
    return [int(i, 16) for i in gdb.eval('{void*[512]}%d'%(uelf_base+offset)).strip()[1:-1].split(', ')]

def get_parasites(kdata_base):
    return sorted({(i - kdata_base, j) for k in map(fetch_logs, range(16)) for i, j in zip(k[::2], k[1::2]) if i})

@derive_symbol
@retry_on_error
def syscall_parasites():
    use_kstuff()
    init_kstuff()
    kdata_base = gdb.ieval('kdata_base')
    ans = get_parasites(kdata_base)
    assert len(ans) == 3
    return ans

@derive_symbols('loadSelfSegment_watchpoint', 'loadSelfSegment_epilogue', 'loadSelfSegment_watchpoint_lr', 'decryptSelfBlock_epilogue', 'decryptSelfBlock_watchpoint_lr', 'decryptMultipleSelfBlocks_epilogue', 'decryptMultipleSelfBlocks_watchpoint_lr')
@retry_on_error
def loadSelfSegment_watchpoint():
    ensure_fselfs(lambda: use_r0gdb_trace(1<<26))
    kdata_base = gdb.ieval('kdata_base')
    for i in (
        'sceSblServiceMailbox',
        'sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize',
        'sceSblServiceMailbox_lr_verifyHeader',
        'sceSblAuthMgrSmIsLoadable2',
        'sceSblServiceMailbox_lr_loadSelfSegment',
        'sceSblServiceMailbox_lr_decryptSelfBlock',
        'sceSblServiceMailbox_lr_decryptMultipleSelfBlocks',
        'kernel_pmap_store',
        'mini_syscore_header',
    ):
        gdb.ieval('offsets.%s = %s'%(i, ostr(kdata_base + symbols[i])))
    gdb.ieval('offsets.mmap_self_fix_1_end = (offsets.mmap_self_fix_1_start = %s) + 2'%ostr(kdata_base + symbols['mmap_self_fix_1_start']))
    gdb.ieval('offsets.mmap_self_fix_2_end = (offsets.mmap_self_fix_2_start = %s) + 2'%ostr(kdata_base + symbols['mmap_self_fix_2_start']))
    gdb.ieval('do_fself = 95')
    rt1 = r0gdb.trace('trace_mailbox', '(void*)dlsym(0x2001, "mmap")', 0, 65536, 1, 0x80001, '(int)open("/data/libSceLibcInternal.sprx", 0)', 0)
    assert not (gdb.ieval('$eflags') & 1)
    mapping = gdb.ieval('$rax')
    rt2 = r0gdb.trace('trace_mailbox', '(void*)dlsym(0x2001, "mlock")', mapping, 16384)
    rt3 = r0gdb.trace('trace_mailbox', '(void*)dlsym(0x2001, "mlock")', mapping, 65536)
    trace = traces.Trace(rt1+rt2+rt3)
    use_kstuff()
    init_kstuff()
    assert not any(map(any, map(fetch_logs, range(16))))
    fd = gdb.ieval('(int)open("/data/libSceLibcInternal.sprx", 0)')
    assert fd >= 0
    mapping = gdb.ieval('(void*)mmap(0, 65536, 1, 0x80001, %d, 0)'%fd)
    assert mapping != 2**64-1
    assert not gdb.ieval('(int)mlock(%d, 16384)'%mapping)
    assert not gdb.ieval('(int)mlock(%d, 65536)'%mapping)
    parasites = get_parasites(gdb.ieval('kdata_base'))
    parasite_set = {kdata_base + i[0] for i in parasites}
    watchpoints = set()
    rest = []
    for i, j in enumerate(('loadSelfSegment', 'decryptSelfBlock', 'decryptMultipleSelfBlocks')):
        k = trace.find_caller(trace.find_next_rip(0, kdata_base + symbols['sceSblServiceMailbox_lr_'+j] - 5)) + 1
        while trace.find_next_instr(k) == k + 1: k += 1
        ps = [i.rip-kdata_base for i in trace[k:trace.find_next_instr(k)] if i.rip in parasite_set]
        k = trace.find_next_instr(k)
        watchpoints.add(tuple(ps))
        lr = trace[k].rip - kdata_base
        k0 = k
        while k + 1 < len(trace) and not (trace.is_jump(k) and trace[k+1].rsp == trace[k].rsp + 8):
            k = trace.find_next_instr(k)
        while k > k0 and trace[k-1].rsp < trace[k].rsp:
            k -= 1
        assert trace[k-1].rsp == trace[k].rsp
        epilogue = trace[k].rip - kdata_base
        rest.append(epilogue)
        rest.append(lr)
    assert len(watchpoints) == 1
    return (min(next(iter(watchpoints))),)+tuple(rest)

@derive_symbol
@retry_on_error
def fself_parasites():
    ensure_fselfs(use_kstuff)
    init_kstuff()
    kdata_base = gdb.ieval('kdata_base')
    assert gdb.ieval('(int)dlopen("/data/libScePlayerInvitationDialog.sprx", 0)') > 0
    fd = gdb.ieval('(int)open("/data/libSceLibcInternal.sprx", 0)')
    assert fd >= 0
    mapping = gdb.ieval('(void*)mmap(0, 65536, 1, 0x80001, %d, 0)'%fd)
    assert mapping != 2**64-1
    gdb.ieval('{void*}%d'%mapping)
    assert not gdb.ieval('(int)mlock(%d, 16384)'%mapping)
    assert not gdb.ieval('(int)mlock(%d, 65536)'%mapping)
    assert not gdb.ieval('(int)munmap(%d, 65536)'%mapping)
    assert not gdb.ieval('(int)close(%d)'%fd)
    ans = get_parasites(kdata_base)
    assert len(ans) == 10
    return [(i, j) for i, j in ans if not (j == 10 and (i, 7) in ans)]

def elf_to_flat(data):
    assert data.startswith(b'\x7fELF') and len(data) >= 64
    ans = bytearray()
    phoff = int.from_bytes(data[32:40], 'little')
    phnum = int.from_bytes(data[56:58], 'little')
    assert len(data) >= phoff+56*phnum
    for i in range(phoff, phoff+56*phnum, 56):
        ptype = int.from_bytes(data[i:i+4], 'little')
        if ptype != 1: continue
        offset = int.from_bytes(data[i+8:i+16], 'little')
        vaddr = int.from_bytes(data[i+16:i+24], 'little')
        filesz = int.from_bytes(data[i+32:i+40], 'little')
        memsz = int.from_bytes(data[i+40:i+48], 'little')
        assert memsz >= filesz
        assert len(data) >= offset + filesz
        ans[vaddr:vaddr+filesz] = data[offset:offset+filesz]
        ans[vaddr+filesz:vaddr+memsz] = bytes(memsz-filesz)
    return ans

@derive_symbol
@retry_on_error
def shellcore_offsets():
    shellcore = elf_to_flat(dump_self('SceShellCore', '/system/vsh/SceShellCore.elf')[0])
    shellcore_txt = shellcore.decode('latin-1').replace('\n', '\u010a')
    def get_offsets(regexp):
        return [shellcore_txt.find(i) for i in re.compile(regexp).findall(shellcore_txt)]
    ans = []
    offset, = get_offsets(r'\x80\x3d....\x01\x75\u010a\x48\x89\xd1\x31\xd2\xe9....\xb8\x01\x00\xe9\x80\xc3\xcc{7}')
    target_fn = int.from_bytes(shellcore[offset+15:offset+19], 'little', signed=True)+offset+19
    ans.append((offset+14, '52eb086690'))
    ans.append((offset+25, (b'\xe8'+(target_fn-offset-30).to_bytes(4, 'little', signed=True)+b'\x58\xc3').hex()))
    offset, = get_offsets(r'\xcc{7}\x80\x3d....\x01\x75\x0d\x48\x89\xd1\xba\x01\x00\x00\x00\xe9....\xb8\x01\x00\xe9\x80\xc3')
    target_fn = int.from_bytes(shellcore[offset+25:offset+29], 'little', signed=True)+offset+29
    ans.append((offset+24, '31c050ebe3'))
    ans.append((offset, (b'\xe8'+(target_fn-offset-5).to_bytes(4, 'little', signed=True)+b'\x58\xc3').hex()))
    offset, = get_offsets(r'\x44\x89[\xe0\xf8]\xff\xc8\x83\xf8\x02\x0f\x83')
    ans.append((offset+8, 'eb04'))
    offsets = get_offsets(r'(\xe8....\x85\xc0\x0f\x88....\x49\x8b\x46\x20\x48\xba\x00\xff\x00\xff\x00\xff\x00\xff|\xe8....\x85\xc0\x0f\x84....\x0f\x88....\x49\x0f\x38)')
    assert len(offsets) == 2
    for i in offsets:
        if shellcore[i+8] == 0x88:
            ans.append((i+7, 'eb04'))
        else:
            ans.append((i+13, 'eb04'))
    offset, = get_offsets(r'(\x41\x39\xdc\x74.\x48\x8d\x3d....|\x3b\x84\x24....\x75.\x31\xc9\xeb.)')
    if shellcore[offset] == 0x41:
        ans.append((offset+3, 'eb'))
    else:
        ans.append((offset+7, '9090'))
    offset, = get_offsets(r'\x83\xbb....\x03\x0f\x84')
    ans.append((offset+7, '90e9'))
    offset, = get_offsets(r'(\x41\x81\xff\x60\x00\x02\x80\x0f\x85....\x80\x7c\x24.\x00\x74.|\x41\x81\xfd\x60\x00\x02\x80\x0f\x85....\x84\xc0\x74\x31)')
    if shellcore[offset+2] == 0xff:
        ans.append((offset+18, 'eb'))
    else:
        ans.append((offset+15, 'eb'))
    offset, = get_offsets(r'\x83\xfb\x01\x0f\x84....\x83\xfb\x02\x0f\x85....')
    target = int.from_bytes(shellcore[offset+5:offset+9], 'little', signed=True)+offset+9
    ans.append((offset+14, (target-offset-18).to_bytes(4, 'little', signed=True).hex()))
    for offset, data in ans:
        data = bytes.fromhex(data)
        shellcore[offset:offset+len(data)] = data
    offset, = get_offsets(r'\xeb.\x48\x8b\x32\x48\x89\xdf\xe8....\xeb.\x48\x8b\x02\x49\x8b\x37')
    target = int.from_bytes(shellcore[offset+9:offset+13], 'little', signed=True)+offset+13
    target2 = int.from_bytes(shellcore[offset+14:offset+15], 'little', signed=True)+offset+15
    cave1 = shellcore.find(b'\xcc'*14, offset)
    cave2 = shellcore.find(b'\xcc'*11, cave1+14)
    ans.append((cave1, (b'\xe8'+(target-cave1-5).to_bytes(4, 'little', signed=True)+b'\x31\xc9\xff\xc1\xe9'+(cave2-cave1-14).to_bytes(4, 'little', signed=True)).hex()))
    ans.append((cave2, (b'\x83\xf8\x02\x0f\x43\xc1\xe9'+(target2-cave2-11).to_bytes(4, 'little', signed=True)).hex()))
    ans.append((offset+8, (b'\xe9'+(cave1-offset-13).to_bytes(4, 'little', signed=True)).hex()))
    return ans

print(len(symbols), 'offsets currently known')
print(sum(sum(j not in symbols for j in i[1]) if isinstance(i, tuple) else (i.__name__ not in symbols) for i in derivations), 'offsets to be found')

for i in derivations:
    if isinstance(i, tuple):
        i, names = i
        if any(j not in symbols for j in names):
            print('Probing offsets `%s`'%'`, `'.join(names))
            try: value = i()
            except Exception:
                raise Exception("failed to derive `%s`, see above why"%'`, `'.join(names))
            assert len(value) == len(names)
            for i, j in zip(names, value):
                set_symbol(i, j)
        available_symbols |= set(names)
    elif i.__name__ not in symbols:
        print('Probing offset `%s`'%i.__name__)
        try: value = i()
        except Exception:
            raise Exception("failed to derive `%s`, see above why"%i.__name__)
        set_symbol(i.__name__, value)
    else:
        available_symbols.add(i.__name__)
