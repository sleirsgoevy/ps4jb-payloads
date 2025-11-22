SECTIONS
{
    . = 0;
    .text : {
        *(.header);
        *(.text);
        *(.text.*);
        *(.rodata);
        *(.rodata.*);
        *(.data);
        *(.data.*);
        *(.bss);
        *(.bss.*);
        persist_start = .;
        *(.firmware_wakeup_table);
        *(.persist);
        *(.efi);
        *(.efistr);
    }
}
