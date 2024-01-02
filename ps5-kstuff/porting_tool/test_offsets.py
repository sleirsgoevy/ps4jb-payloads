from main import *

use_kstuff()
buf = gdb.ieval('malloc(72*8)')
kdata_base = gdb.ieval('kdata_base')
gdb.ieval('offsets.mprotect_fix_end = '+ostr(kdata_base+symbols['mprotect_fix_start']+6))
gdb.ieval('offsets.pop_all_except_rdi_iret = '+ostr(kdata_base+symbols['pop_all_iret']+4))
gdb.execute('cont')
assert 'Remote connection closed' in gdb.execute('p (int)kill((int)getpid(), 9)')
