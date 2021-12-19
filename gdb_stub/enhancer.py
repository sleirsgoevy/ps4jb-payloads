import sys

nidmap = {}

if len(sys.argv) >= 4:
    with open(sys.argv[3]) as f:
        for l in f:
            nid, sym = l.split()
            nidmap[nid] = sym

with open(sys.argv[1], 'rb') as file: data = bytearray(file.read())

def align(n):
    global data
    data += bytes((-len(data)) % n)

phoff = int.from_bytes(data[32:40], 'little')
nphdr = int.from_bytes(data[56:58], 'little')

section_names = b''

align(16)
shoff = len(data)
nsections = 0

def section(name, kind, flags, addr, offset, size, link, info, entrysz, align=1):
    global section_names, data, nsections
    data += len(section_names).to_bytes(4, 'little')
    section_names += (name+'\0').encode('ascii')
    data += kind.to_bytes(4, 'little')
    data += flags.to_bytes(8, 'little')
    data += addr.to_bytes(8, 'little')
    off_off = len(data)
    data += offset.to_bytes(8, 'little')
    sz_off = len(data)
    data += size.to_bytes(8, 'little')
    data += link.to_bytes(4, 'little')
    data += info.to_bytes(4, 'little')
    data += align.to_bytes(8, 'little')
    data += entrysz.to_bytes(8, 'little')
    nsections += 1
    return off_off, sz_off

section('', 0, 0, 0, 0, 0, 0, 0, 0) # NULL

names = {}

def next_name(prefix):
    if prefix not in names: names[prefix] = 0
    ans = names[prefix]
    names[prefix] += 1
    return prefix if not ans else prefix + str(ans)

def guess_name(flags):
    if flags & 4: # X
        return '.text'
    elif flags & 1: # W
        return '.data'
    else:
        return '.rodata'

dynamic = None
sce_dynlibdata = None

inmem_sections = []
inmem_segments = []

text_addr = None
text_offset = None
text_filesz = None

eh_frame_hdr = None

for i in range(nphdr):
    phdr = data[phoff+56*i:phoff+56*(i+1)]
    kind = int.from_bytes(phdr[:4], 'little')
    addr = int.from_bytes(phdr[16:24], 'little')
    offset = int.from_bytes(phdr[8:16], 'little')
    filesz = int.from_bytes(phdr[32:40], 'little')
    memsz = int.from_bytes(phdr[40:48], 'little')
    flags = int.from_bytes(phdr[4:8], 'little')
    if kind == 1: # PT_LOAD
        inmem_segments.append((addr, offset, filesz))
        s_flags = 2 | (flags & 1) << 2 | (flags & 2) >> 1
        assert filesz <= memsz
        inmem_sections.append((addr, nsections))
        if s_flags & 4 and text_addr == None:
            text_addr = addr
            text_offset = offset
            text_filesz = filesz
        section(next_name(guess_name(s_flags)), 1, s_flags, addr, offset, filesz, 0, 0, 0)
        if filesz < memsz:
            inmem_sections.append((addr + filesz, nsections))
            section(next_name('.bss'), 8, s_flags, addr + filesz, 0, memsz - filesz, 0, 0, 0)
    elif kind == 2: # PT_DYNAMIC
        dynamic = (offset, filesz)
    elif kind == 0x6474e550: # GNU_EH_FRAME
        eh_frame_hdr = (addr, offset, filesz)
    elif kind == 0x61000000: # SCE_DYNLIBDATA
        sce_dynlibdata = offset

inmem_sections.sort()
inmem_segments.sort()

def guess_section(addr, sections=inmem_sections):
    l = -1
    h = len(sections)
    while h - l > 1:
        m = (h + l) // 2
        if sections[m][0] > addr:
            h = m
        else:
            l = m
    if l >= 0: return sections[l]
    return 0

dynsym = None
dynstr = None

def process_dynsym(b):
    assert len(b) % 24 == 0
    b = bytearray(b)
    for i in range(0, len(b), 24):
        value = int.from_bytes(b[i+8:i+16], 'little')
        if value != 0: # UND
            b[i+6:i+8] = guess_section(value)[1].to_bytes(2, 'little')
    return bytes(b)

def decode_nid(nid0):
    nid = nid0.decode('ascii').split('#', 1)[0]
    if nid in nidmap:
        return nidmap[nid].encode('ascii')
    else:
        return nid0

def decode_nids(b, oldnames):
    assert len(b) % 24 == 0
    newnames = b''
    b = bytearray(b)
    for i in range(0, len(b), 24):
        name = oldnames[int.from_bytes(b[i:i+4], 'little'):].split(b'\0', 1)[0]
        b[i:i+4] = len(newnames).to_bytes(4, 'little')
        newnames += decode_nid(name) + b'\0'
    return (bytes(b), newnames)

def parse_relaplt(data):
    ans = {}
    for i in range(0, len(data), 24):
        offset = int.from_bytes(data[i:i+8], 'little')
        info = int.from_bytes(data[i+8:i+16], 'little')
        addend = int.from_bytes(data[i+16:i+24], 'little')
        if (info & 0xffffffff) == 7:
            ans[offset] = info >> 32
    return ans

def plt_synthesise(dynsym, dynstr, text, text_addr, got):
    i = 0
    while True:
        jmp = text.find(b'\xff\x25', i)
        if jmp < 0 or jmp > len(text) - 6: break
        i = jmp + 6
        addr = text_addr + jmp + 6 + int.from_bytes(text[jmp+2:jmp+6], 'little')
        if addr in got:
            j = got[addr]
            name = dynstr[int.from_bytes(dynsym[24*j:24*j+4], 'little'):].split(b'\0', 1)[0]
            if not name: continue
            name += b'@plt'
            dynsym += len(dynstr).to_bytes(4, 'little')
            dynsym += b'\x02' # local func
            dynsym += b'\x02' # hidden
            dynsym += guess_section(text_addr + jmp)[1].to_bytes(2, 'little')
            dynsym += (text_addr + jmp).to_bytes(8, 'little')
            dynsym += b'\6\0\0\0\0\0\0\0'
            dynstr += name + b'\0'
    return dynsym, dynstr

def read_leb128(data, off, signed=False):
    ans = 0
    shift = 0
    while True:
        q = data[off]
        off += 1
        ans |= (q & 127) << shift
        shift += 7
        if ans < 128: break
    if signed: ans |= (-(ans >> (shift - 1))) << shift
    return ans, off

def efh_fetch_enc(data, off, how):
    if how == 1: return parse_leb128(data, off)
    elif how == 2: return int.from_bytes(data[off:off+2], 'little'), off+2
    elif how == 3: return int.from_bytes(data[off:off+4], 'little'), off+4
    elif how == 4: return int.from_bytes(data[off:off+8], 'little'), off+8
    elif how == 9: return parse_leb128(data, off, signed=True)
    elif how == 10: return int.from_bytes(data[off:off+2], 'little', signed=True), off+2
    elif how == 11: return int.from_bytes(data[off:off+4], 'little', signed=True), off+4
    elif how == 12: return int.from_bytes(data[off:off+8], 'little', signed=True), off+8
    elif how == 15: return None
    else: assert False

def efh_read_enc(data, off, off0, shift, how):
    ans, off2 = efh_fetch_enc(data, off, how % 16)
    how //= 16
    if how == 0: pass
    elif how == 1: ans += off + shift
    elif how == 3: ans += off0 + shift
    elif how == 15: pass
    else: assert False
    return ans, off2

def efh_parse(data, off, limit, shift):
    off0 = off
    assert data[off] == 1
    efpe = data[off+1]
    fdce = data[off+2]
    te = data[off+3]
    efp, off = efh_read_enc(data, off+4, off0, shift, efpe)
    fdc, off = efh_read_enc(data, off, off0, shift, fdce)
    max_addr = 0
    for i in range(fdc):
        initloc, off = efh_read_enc(data, off, off0, shift, te)
        addr, off = efh_read_enc(data, off, off0, shift, te)
        max_addr = max(max_addr, addr)
    assert off <= limit
    return efp, max_addr

def ef_parse(data, off, limit):
    while off + 4 <= limit:
        l = int.from_bytes(data[off:off+4], 'little')
        if l + off + 4 > limit: break
        off += l + 4
        if not l: break
    return off

if dynamic:
    section('.dynamic', 6, 0, 0, dynamic[0], dynamic[1], 0, 0, 0)
    assert dynamic[1] % 16 == 0
    dynsym_addr = None
    dynsym_sz = None
    dynstr_addr = None
    dynstr_sz = None
    reladyn_addr = None
    reladyn_sz = None
    relaplt_addr = None
    relaplt_sz = None
    for i in range(0, dynamic[1], 16):
        entry = data[dynamic[0]+i:dynamic[0]+i+16]
        tag = int.from_bytes(entry[:8], 'little')
        val = int.from_bytes(entry[8:], 'little')
        if tag == 0x61000039:
            dynsym_addr = val
        elif tag == 0x6100003f:
            dynsym_sz = val
        elif tag == 0x61000035:
            dynstr_addr = val
        elif tag == 0x61000037:
            dynstr_sz = val
        elif tag == 0x6100002f:
            reladyn_addr = val
        elif tag == 0x61000031:
            reladyn_sz = val
        elif tag == 0x61000029:
            relaplt_addr = val
        elif tag == 0x6100002d:
            relaplt_sz = val
    have_dynstr = dynstr_addr != None and dynstr_sz != None
    dynsym_sect = 0
    got_slots = None
    if relaplt_addr != None and relaplt_sz != None:
        got_slots = parse_relaplt(data[relaplt_addr+sce_dynlibdata:relaplt_addr+sce_dynlibdata+relaplt_sz])
    if dynsym_addr != None and dynsym_sz != None and sce_dynlibdata != None:
        dynsym_sect = nsections
        dynsym = process_dynsym(data[dynsym_addr+sce_dynlibdata:dynsym_addr+sce_dynlibdata+dynsym_sz])
        if have_dynstr and nidmap:
            dynsym, dynstr = decode_nids(dynsym, data[dynstr_addr+sce_dynlibdata:dynstr_addr+sce_dynlibdata+dynstr_sz])
        if have_dynstr and text_offset != None and got_slots:
            if dynstr == None: dynstr = data[dynstr_addr+sce_dynlibdata:dynstr_addr+sce_dynlibdata+dynstr_sz]
            dynsym, dynstr = plt_synthesise(dynsym, dynstr, data[text_offset:text_offset+text_filesz], text_addr, got_slots)
        dynsym_off, dynsym_sz = section('.dynsym', 11, 0, 0, 0, 0, nsections + 2 if have_dynstr else 0, 0, 24)
        symtab_off, symtab_sz = section('.symtab', 2, 0, 0, 0, 0, nsections + 2 if have_dynstr else 0, 0, 24)
    if have_dynstr and sce_dynlibdata != None:
        dynstr_off, dynstr_siz = section('.dynstr', 3, 0, 0, dynstr_addr + sce_dynlibdata, dynstr_sz, 0, 0, 0)
        strtab_off, strtab_siz = section('.strtab', 3, 0, 0, dynstr_addr + sce_dynlibdata, dynstr_sz, 0, 0, 0)
    if reladyn_addr != None and reladyn_sz != None and sce_dynlibdata != None:
        section('.rela.dyn', 4, 0, 0, reladyn_addr + sce_dynlibdata, reladyn_sz, dynsym_sect, 0, 24)
    if relaplt_addr != None and relaplt_sz != None and sce_dynlibdata != None:
        section('.rela.plt', 4, 0, 0, relaplt_addr + sce_dynlibdata, relaplt_sz, dynsym_sect, 0, 24)

if eh_frame_hdr != None:
    ef_start, ef_some_entry = efh_parse(data, eh_frame_hdr[1], eh_frame_hdr[1] + eh_frame_hdr[2], eh_frame_hdr[0] - eh_frame_hdr[1])
    ef_segment = guess_section(ef_start, inmem_segments)
    assert all(i in range(ef_segment[0], ef_segment[0]+ef_segment[2]) for i in (ef_start, ef_some_entry))
    ef_end = ef_parse(data, ef_some_entry + ef_segment[1] - ef_segment[0], ef_segment[1] + ef_segment[2])
    ef_length = ef_end - (ef_start + ef_segment[1] - ef_segment[0])
    section('.eh_frame_hdr', 1, 2, eh_frame_hdr[0], eh_frame_hdr[1], eh_frame_hdr[2], 0, 0, 0, 4)
    section('.eh_frame', 1, 2, ef_start, ef_start + ef_segment[1] - ef_segment[0], ef_length, 0, 0, 0, 8)

if nsections:
    shstrndx = nsections
    shstrtab_off, shstrtab_sz = section('.shstrtab', 3, 0, 0, 0, 0, 0, 0, 0)
    align(16)
    data[shstrtab_off:shstrtab_off+8] = len(data).to_bytes(8, 'little')
    data[shstrtab_sz:shstrtab_sz+8] = len(section_names).to_bytes(8, 'little')
    data += section_names

if dynsym != None:
    align(16)
    data[dynsym_off:dynsym_off+8] = data[symtab_off:symtab_off+8] = len(data).to_bytes(8, 'little')
    data[dynsym_sz:dynsym_sz+8] = data[symtab_sz:symtab_sz+8] = len(dynsym).to_bytes(8, 'little')
    data += dynsym

if dynstr != None:
    align(16)
    data[dynstr_off:dynstr_off+8] = data[strtab_off:strtab_off+8] = len(data).to_bytes(8, 'little')
    data[dynstr_siz:dynstr_siz+8] = data[strtab_siz:strtab_siz+8] = len(dynstr).to_bytes(8, 'little')
    data += dynstr

data[16:18] = b'\3\0' # ET_DYN, this is THE ONLY DESTRUCTIVE ACTION
data[40:48] = shoff.to_bytes(8, 'little')
data[58:64] = b'\x40\0' + nsections.to_bytes(2, 'little') + shstrndx.to_bytes(2, 'little')

with open(sys.argv[2], 'wb') as file: file.write(data)
