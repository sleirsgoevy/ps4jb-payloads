import sys

with open(sys.argv[1], 'r+b') as file:
    assert file.read(5) == b'\xeb\x0bELF'
    file.seek(0)
    file.write(b'\xeb\x0bPLD')
    file.seek(64+56+16)
    vaddr = int.from_bytes(file.read(8), 'little')
    file.seek(64+56+32)
    filesz = (int.from_bytes(file.read(8), 'little') - vaddr).to_bytes(8, 'little')
    memsz = (int.from_bytes(file.read(8), 'little') - vaddr).to_bytes(8, 'little')
    file.seek(64+56+32)
    file.write(filesz)
    file.write(memsz)
