extern kdata_base

on_rip kdata_base-0x80284d, decrypt_rdi_only
on_rip kdata_base-0x3889ac, decrypt_rsi_only
on_rip kdata_base-0x38896c, decrypt_rsi_only

; fself stuff, library load
on_rip kdata_base-0x2cd28a, decrypt_rax_only
on_rip kdata_base-0x2cd150, decrypt_rax_only
on_rip kdata_base-0x2cc882, decrypt_rcx_only
on_rip kdata_base-0x2cc716, decrypt_rax_only

; fself stuff, library unload
on_rip kdata_base-0x990b10, decrypt_rdi_only
