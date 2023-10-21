import sys, json, threading, functools, os.path

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

def die(*args):
    print(*args)
    exit(1)

def set_symbol(k, v):
    assert k not in symbols or symbols[k] == v
    if k not in symbols:
        print('offset found! %s = %s'%(k, hex(v)))
        symbols[k] = v
        with open(sys.argv[1], 'w') as file:
            json.dump(symbols, file)

if 'allproc' not in symbols:
    die('`allproc` is not defined')

R0GDB_FLAGS = ['-DMEMRW_FALLBACK', '-DNO_BUILTIN_OFFSETS']

r0gdb = gdb_rpc.R0GDB(gdb, R0GDB_FLAGS)

def ostr(x):
    return str(x % 2**64)

def retry_on_error(f):
    @functools.wraps(f)
    def f1(*args):
        while True:
            try: return f(*args)
            except gdb_rpc.DisconnectedException:
                print('\nPS5 disconnected, retrying %s...'%f.__name__)
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
            offset = 0
            while offset < chk0:
                chk = gdb.ieval('(int)write(%d, %d, %d)'%(remote_fd, remote_buf+offset, chk0-offset))
                assert chk > 0
                offset += chk
                total_sent += chk
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
    use_r0gdb_trace(16777216)
    kdata_base = gdb.ieval('kdata_base')
    gdb.ieval('jprog = (uint64_t[1]){0}')
    # use the ipv6 rthdr allocation to find malloc
    # 1224 is a valid size for rthdr, and prosper0gdb already has set_rthdr_size function that wraps the raw ioctl
    remote_sock = gdb.ieval('(int)socket(28, 2, 0)') # udpv6
    trace = traces.Trace(r0gdb.trace('do_jprog', 'set_rthdr_size', remote_sock, 1224))
    malloc_call, = (i for i in range(len(trace)) if trace.is_jump(i) and trace[i+1].rsp == trace[i].rsp-8 and trace[i].rdi == 1224 and trace[i].rdx == 1)
    malloc = trace[malloc_call+1].rip
    M_something = trace[malloc_call+1].rsi
    return malloc - kdata_base, M_something - kdata_base

@derive_symbol
@retry_on_error
def mprotect_fix_start():
    use_r0gdb_trace(16777216)
    kdata_base = gdb.ieval('kdata_base')
    gdb.ieval('jprog = (uint64_t[1]){0}')
    buf = gdb.ieval('malloc(16384)')
    # get 2 traces to diff
    trace1 = traces.Trace(r0gdb.trace('do_jprog', '(void*)dlsym(0x2001, "mprotect")', buf, 1, 3))
    trace2 = traces.Trace(r0gdb.trace('do_jprog', '(void*)dlsym(0x2001, "mprotect")', buf, 1, 7))
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
    elif i.__name__ not in symbols:
        print('Probing offset `%s`'%i.__name__)
        try: value = i()
        except Exception:
            raise Exception("failed to derive `%s`, see above why"%i.__name__)
        set_symbol(i.__name__, value)
