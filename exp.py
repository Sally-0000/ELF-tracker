from pwn import *
r = process(["/bin/bash", "./a.sh"])
r.recvuntil("Enter some text: \n")
r.sendline("A" * 256)
r.interactive()
