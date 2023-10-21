import collections

class Trace:
    Frame = collections.namedtuple('Frame', ['rip', 'cs', 'eflags', 'rsp', 'ss', 'rax', 'rcx', 'rdx', 'rbx', 'pad8', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'])
    def __init__(self, blob):
        data = [int.from_bytes(blob[i:i+8], 'little') for i in range(0, len(blob), 8)]
        self.instrs = [self.Frame(*data[i:i+21]) for i in range(0, len(data), 21)]
    def __getitem__(self, q):
        return self.instrs[q]
    def __len__(self):
        return len(self.instrs)
    def find_rip_all(self, rip):
        return [i for i, j in enumerate(self.instrs) if j.rip == rip]
    def find_next_rip(self, idx, rip):
        try: return next(i for i in range(idx, len(self.instrs)) if self[i].rip == rip)
        except StopIteration: return None
    def find_next_reg(self, idx, which_reg, value):
        getter = getattr(self.Frame, which_reg).__get__
        try: return next(i for i in range(idx, len(self.instrs)) if getter(self[i]) == value)
        except StopIteration: return None
    def find_next_any_reg(self, idx, value):
        try: return next(i for i, j in range(idx, len(self.instrs)) if getter(self[i]) == value)
        except StopIteration: return None
    def is_jump(self, idx):
        return idx + 1 < len(self) and (self[idx+1].rip - self[idx].rip) % 2**64 >= 16
    def find_caller(self, idx):
        rsp = self[idx].rsp
        while idx > 0:
            idx -= 1
            if self[idx].rsp == rsp + 8 and self[idx+1].rsp == rsp and self.is_jump(idx):
                return idx
            rsp = max(rsp, self[idx].rsp)
        return None
    def find_last_callee_ret(self, idx):
        idx0 = self.find_caller(idx) + 1
        while idx > idx0:
            idx -= 1
            if self[idx].rsp == self[idx+1].rsp - 8 and self.is_jump(idx):
                return idx
        return None
    def find_next_instr(self, idx):
        if idx + 1 < len(self):
            if self[idx+1].rsp == self[idx].rsp - 8 and self.is_jump(idx):
                return self.find_next_reg(idx+1, 'rsp', self[idx].rsp)
            else:
                return idx + 1
        return None
    def find_last_ret(self, idx):
        idx -= 1
        while idx >= 0 and not (self.is_jump(idx) and self[idx+1].rsp == self[idx].rsp + 8):
            idx -= 1
        return idx if idx >= 0 else None
