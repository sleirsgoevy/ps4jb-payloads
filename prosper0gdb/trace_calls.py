import sys

prev_rip = None
prev_rsp = None

call_stack = []
call_stack_2 = []

output = []

while True:
    try: l = input()
    except EOFError: break
    if not l:
        output.append(l)
        continue
    regs = {i: int(j, 16) for i, j in (q.split('=') for q in l.replace('  = ', '=').replace(' = ', '=').split())}
    if prev_rip is None:
        prev_rip = regs['rip']
        prev_rsp = regs['rsp']
        continue
    if regs['rip'] < prev_rip or regs['rip'] >= prev_rip+16:
        if regs['rsp'] == prev_rsp - 8:
            while call_stack and call_stack[-1] <= regs['rsp']:
                output.append('+ ret')
                call_stack.pop()
                q = call_stack_2.pop()
                output[q] += ' ('+str(len(output)-q)+')'
            call_stack_2.append(len(output))
            output.append('+ call')
            call_stack.append(regs['rsp'])
        elif regs['rsp'] == prev_rsp + 8:
            while call_stack and call_stack[-1] <= prev_rsp:
                output.append('+ ret')
                call_stack.pop()
                q = call_stack_2.pop()
                output[q] += ' ('+str(len(output)-q)+')'
    prev_rip = regs['rip']
    prev_rsp = regs['rsp']
    output.append(l)

for i in range(len(call_stack)):
    output.append('+ ret')
    q = call_stack_2.pop()
    output[q] += ' ('+str(len(output)-q)+')'

for i in output:
    print(i)
