%define SYS_dynlib_load_prx 594
if_equal cmpqibe, regs_stash+iret_rax, sysents+48*SYS_dynlib_load_prx, handle_dynlib_load_prx
