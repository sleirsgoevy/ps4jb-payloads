%define SYS_execve 59
%define SYS_dynlib_load_prx 594
%define SYS_get_self_auth_info 607
%define SYS_get_sdk_compiled_version 647
%define SYS_get_ppr_sdk_compiled_version 713
;if_equal cmpqibe, scratchpad+0xffff8, 1234, handle_fself_syscall
if_equal cmpqibe, regs_stash+iret_rax, sysents+48*SYS_execve, handle_fself_syscall
if_equal cmpqibe, regs_stash+iret_rax, sysents+48*SYS_dynlib_load_prx, handle_fself_syscall
if_equal cmpqibe, regs_stash+iret_rax, sysents+48*SYS_get_self_auth_info, handle_fself_syscall
if_equal cmpqibe, regs_stash+iret_rax, sysents+48*SYS_get_sdk_compiled_version, handle_fself_syscall
if_equal cmpqibe, regs_stash+iret_rax, sysents+48*SYS_get_ppr_sdk_compiled_version, handle_fself_syscall
