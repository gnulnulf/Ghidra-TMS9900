#!/usr/bin/env python3
"""Verify Ghidra TMS9900 disassembly output against expected values."""
import re
import sys

# Ghidra's actual output syntax for addressing modes:
#   reg direct:       r0
#   *reg indirect:    *r1
#   *reg+ autoinc:    *r1+
#   @sym (no reg):    SYM@>0xADDR      (symbolic - no base register)
#   @sym(rN) indexed: @0xOFFSET(rN)    (indexed - with base register)

expected = {
    # ── Immediate / misc ──────────────────────────────────────────────────────
    0x0000: "LI r0,>0x1234",
    0x0004: "AI r0,>0x100",
    0x0008: "ANDI r0,>0xf0f",
    0x000C: "ORI r1,>0xf000",
    0x0010: "CI r0,>0x1334",
    0x0014: "STWP r5",
    0x0016: "STST r4",
    0x0018: "IDLE",
    0x001A: "RSET",
    0x001C: "RTWP",
    0x001E: "CKON",
    0x0020: "CKOF",
    0x0022: "LREX",
    0x0024: "LWPI >0x8300",
    0x0028: "LIMI >0x2",
    # ── Single operand ────────────────────────────────────────────────────────
    0x002C: "BLWP r0",
    0x002E: "B r0",
    0x0030: "X r1",
    0x0032: "CLR r3",
    0x0034: "NEG r0",
    0x0036: "INV r0",
    0x0038: "INC r1",
    0x003A: "INCT r2",
    0x003C: "DEC r1",
    0x003E: "DECT r2",
    0x0040: "BL r0",
    0x0042: "SWPB r0",
    0x0044: "SETO r0",
    0x0046: "ABS r0",
    # ── Shifts ───────────────────────────────────────────────────────────────
    0x0048: "SRA r0,0x1",
    0x004A: "SRL r1,0x2",
    0x004C: "SLA r2,0x3",
    0x004E: "SRC r3,0x4",
    # ── Jumps ─────────────────────────────────────────────────────────────────
    0x0050: "JMP >0x0052",
    0x0052: "JLT >0x0054",
    0x0054: "JLE >0x0056",
    0x0056: "JEQ >0x0058",
    0x0058: "JHE >0x005a",
    0x005A: "JGT >0x005c",
    0x005C: "JNE >0x005e",
    0x005E: "JNC >0x0060",
    0x0060: "JOC >0x0062",
    0x0062: "JNO >0x0064",
    0x0064: "JL >0x0066",
    0x0066: "JH >0x0068",
    0x0068: "JOP >0x006a",
    # ── Two operand register/register ─────────────────────────────────────────
    0x006A: "COC r2,r1",
    0x006C: "CZC r2,r1",
    0x006E: "XOR r2,r1",
    0x0070: "XOP r2,0x1",
    0x0072: "MPY r1,r2",
    0x0074: "DIV r1,r2",
    0x0076: "LDCR r2,0x8",
    0x0078: "STCR r2,0x8",
    # ── Two operand register direct ───────────────────────────────────────────
    0x007A: "MOV r0,r1",
    0x007C: "MOV r1,r2",
    0x007E: "MOVB r2,r3",
    0x0080: "A r0,r1",
    0x0082: "AB r2,r1",
    0x0084: "S r0,r1",
    0x0086: "SB r2,r1",
    0x0088: "C r0,r1",
    0x008A: "CB r2,r1",
    0x008C: "SZC r0,r1",
    0x008E: "SZCB r2,r1",
    0x0090: "SOC r0,r1",
    0x0092: "SOCB r2,r1",
    # ── Addressing modes: src ─────────────────────────────────────────────────
    0x0094: "MOV r1,r0",                      # reg direct
    0x0096: "MOV *r1,r0",                     # *reg indirect
    0x0098: "MOV *r1+,r0",                    # *reg+ autoincrement
    0x009A: "MOV SYM@>0x1234,r0",             # symbolic (no base reg)
    0x009E: "MOV @0x10(r2),r0",               # indexed (with base reg)
    # ── Addressing modes: dst ─────────────────────────────────────────────────
    0x00A2: "MOV r0,*r1",                     # *reg indirect dst
    0x00A4: "MOV r0,*r1+",                    # *reg+ autoincrement dst
    0x00A6: "MOV r0,@>0x5678",               # symbolic dst
    0x00AA: "MOV r0,@0x20(r3)",              # indexed dst
    # ── MOVB addressing ───────────────────────────────────────────────────────
    0x00AE: "MOVB *r2,r0",                    # byte *reg indirect
    0x00B0: "MOVB SYM@>0xff00,r1",           # byte symbolic
    # ── CLR addressing modes ──────────────────────────────────────────────────
    0x00B4: "CLR *r2",                        # *reg indirect
    0x00B6: "CLR *r2+",                       # *reg+ autoincrement
    0x00B8: "CLR SYM@>0xabcd",               # symbolic
    0x00BC: "CLR @0x1000(r4)",               # indexed
    # ── Mixed src+dst addressing ──────────────────────────────────────────────
    0x00C0: "MOV *r1,*r2",                    # *reg, *reg
    0x00C2: "MOV *r1+,*r2+",                  # *reg+, *reg+
    0x00C4: "MOV SYM@>0x100,@>0x200",        # sym, sym
    0x00CA: "MOV @0x10(r1),@0x20(r2)",       # indexed, indexed
}

# Parse Ghidra stdout
ghidra = {}
with open("ghidra_headless_stdout.txt") as f:
    for line in f:
        m = re.match(r'(0x[0-9A-Fa-f]{4})\s+(.+)', line.strip())
        if m:
            ghidra[int(m.group(1), 16)] = m.group(2).strip()

print("=== TMS9900 Disassembly Verification ===\n")
passed = failed = missing = 0

for addr in sorted(expected):
    exp = expected[addr]
    got = ghidra.get(addr, None)
    if got is None:
        print(f"  MISS  0x{addr:04X}  expected: {exp!r}")
        missing += 1
    elif exp.lower() == got.lower():
        passed += 1
    else:
        print(f"  FAIL  0x{addr:04X}  expected: {exp!r}")
        print(f"                    got:      {got!r}")
        failed += 1

total = len(expected)
print(f"\nResults: {passed} passed, {failed} failed, {missing} missing"
      f" out of {total} instructions")

if failed == 0 and missing == 0:
    print("ALL TESTS PASSED ✓")
    sys.exit(0)
else:
    print("SOME TESTS FAILED ✗")
    sys.exit(1)
