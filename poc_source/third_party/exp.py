from pwn import *
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
r = process([str(ROOT / "ELF_Tracker"), str(ROOT / "poc")])
r.recvuntil("Enter some text: \n")
# r.sendline("A" * 256)
r.interactive()
