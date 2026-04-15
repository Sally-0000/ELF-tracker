from pwn import *
r = process(["/bin/bash", "./protect","poc"])
r.recvuntil("Enter some text: \n")
# r.sendline("A" * 256)
r.interactive()
