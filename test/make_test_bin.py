#!/usr/bin/env python3
"""Generate TMS9900 test binary covering all instruction forms and addressing modes."""

import struct

def w(val):
    return struct.pack('>H', val & 0xFFFF)

out = bytearray()
entries = []  # (addr, expected_disasm)

def emit(expected, *words):
    addr = len(out)
    entries.append((addr, expected))
    for wrd in words:
        out.extend(w(wrd))

# ── Format I: immediate-operand instructions ──────────────────────────────────
emit("LI r0,>0x1234",       0x0200, 0x1234)
emit("AI r0,>0x100",        0x0220, 0x0100)
emit("ANDI r0,>0xf0f",      0x0240, 0x0F0F)
emit("ORI r1,>0xf000",      0x0261, 0xF000)
emit("CI r0,>0x1334",       0x0280, 0x1334)
emit("STWP r5",             0x02A5)
emit("STST r4",             0x02C4)

# ── Misc / privileged ────────────────────────────────────────────────────────
emit("IDLE",                0x0340)
emit("RSET",                0x0360)
emit("RTWP",                0x0380)
emit("CKON",                0x03A0)
emit("CKOF",                0x03C0)
emit("LREX",                0x03E0)
emit("LWPI >0x8300",        0x02E0, 0x8300)
emit("LIMI >0x2",           0x0300, 0x0002)

# ── Single-operand (register direct) ─────────────────────────────────────────
emit("BLWP r0",             0x0400)
emit("B r0",                0x0440)
emit("X r1",                0x0481)
emit("CLR r3",              0x04C3)
emit("NEG r0",              0x0500)
emit("INV r0",              0x0540)
emit("INC r1",              0x0581)
emit("INCT r2",             0x05C2)
emit("DEC r1",              0x0601)
emit("DECT r2",             0x0642)
emit("BL r0",               0x0680)
emit("SWPB r0",             0x06C0)
emit("SETO r0",             0x0700)
emit("ABS r0",              0x0740)

# ── Shift instructions ────────────────────────────────────────────────────────
emit("SRA r0,0x1",          0x0810)
emit("SRL r1,0x2",          0x0921)
emit("SLA r2,0x3",          0x0A32)
emit("SRC r3,0x4",          0x0B43)

# ── Jump instructions ─────────────────────────────────────────────────────────
emit("JMP >0x0052",         0x1000)
emit("JLT >0x0054",         0x1100)
emit("JLE >0x0056",         0x1200)
emit("JEQ >0x0058",         0x1300)
emit("JHE >0x005a",         0x1400)
emit("JGT >0x005c",         0x1500)
emit("JNE >0x005e",         0x1600)
emit("JNC >0x0060",         0x1700)
emit("JOC >0x0062",         0x1800)
emit("JNO >0x0064",         0x1900)
emit("JL >0x0066",          0x1A00)
emit("JH >0x0068",          0x1B00)
emit("JOP >0x006a",         0x1C00)

# ── Two-operand register/register ─────────────────────────────────────────────
emit("COC r2,r1",           0x2042)
emit("CZC r2,r1",           0x2442)
emit("XOR r2,r1",           0x2842)
emit("XOP r2,0x1",          0x2C42)
emit("MPY r1,r2",           0x3881)
emit("DIV r1,r2",           0x3C81)
emit("LDCR r2,0x8",         0x3202)
emit("STCR r2,0x8",         0x3602)

# ── Two-operand register direct ───────────────────────────────────────────────
emit("MOV r0,r1",           0xC040)
emit("MOV r1,r2",           0xC081)
emit("MOVB r2,r3",          0xD0C2)
emit("A r0,r1",             0xA040)
emit("AB r2,r1",            0xB042)
emit("S r0,r1",             0x6040)
emit("SB r2,r1",            0x7042)
emit("C r0,r1",             0x8040)
emit("CB r2,r1",            0x9042)
emit("SZC r0,r1",           0x4040)
emit("SZCB r2,r1",          0x5042)
emit("SOC r0,r1",           0xE040)
emit("SOCB r2,r1",          0xF042)

addr_mode_start = len(out)
print(f"Addressing mode tests start at: 0x{addr_mode_start:04X}")

# ── Addressing mode tests ─────────────────────────────────────────────────────
# Layout: dst_T=[11:10], dst_R=[9:6], src_T=[5:4], src_R=[3:0]
# Modes:  0=reg direct, 1=*reg indirect, 2=@sym/indexed, 3=*reg+ autoincrement
# Base:   MOV word = 0xC000, MOVB = 0xD000
#         CLR = 0x04C0 (single operand, src field at [5:0])

MOV  = 0xC000
MOVB = 0xD000
CLR  = 0x04C0

def two_op(base, dst_T, dst_R, src_T, src_R):
    return base | (dst_T<<10) | (dst_R<<6) | (src_T<<4) | src_R

def one_op(base, T, R):
    return base | (T<<4) | R

# -- MOV: src addressing modes, dst = r0 (reg direct) -------------------------
emit("MOV r1,r0",           two_op(MOV,  0,0, 0,1))          # reg direct src
emit("MOV *r1,r0",          two_op(MOV,  0,0, 1,1))          # *reg indirect src
emit("MOV *r1+,r0",         two_op(MOV,  0,0, 3,1))          # *reg+ autoinc src
emit("MOV @>1234,r0",       two_op(MOV,  0,0, 2,0), 0x1234)  # @sym src
emit("MOV @>10(r2),r0",     two_op(MOV,  0,0, 2,2), 0x0010)  # @sym(r) indexed src

# -- MOV: dst addressing modes, src = r0 (reg direct) -------------------------
emit("MOV r0,*r1",          two_op(MOV,  1,1, 0,0))          # *reg indirect dst
emit("MOV r0,*r1+",         two_op(MOV,  3,1, 0,0))          # *reg+ autoinc dst
emit("MOV r0,@>5678",       two_op(MOV,  2,0, 0,0), 0x5678)  # @sym dst
emit("MOV r0,@>20(r3)",     two_op(MOV,  2,3, 0,0), 0x0020)  # @sym(r) indexed dst

# -- MOVB: byte mode addressing -----------------------------------------------
emit("MOVB *r2,r0",         two_op(MOVB, 0,0, 1,2))          # byte *reg indirect
emit("MOVB @>FF00,r1",      two_op(MOVB, 0,1, 2,0), 0xFF00)  # byte @sym

# -- CLR: single operand addressing modes -------------------------------------
emit("CLR *r2",             one_op(CLR, 1,2))                 # *reg indirect
emit("CLR *r2+",            one_op(CLR, 3,2))                 # *reg+ autoinc
emit("CLR @>ABCD",          one_op(CLR, 2,0), 0xABCD)         # @sym
emit("CLR @>1000(r4)",      one_op(CLR, 2,4), 0x1000)         # @sym(r) indexed

# -- Mixed src and dst addressing modes ---------------------------------------
emit("MOV *r1,*r2",         two_op(MOV,  1,2, 1,1))          # *reg, *reg
emit("MOV *r1+,*r2+",       two_op(MOV,  3,2, 3,1))          # *reg+, *reg+
emit("MOV @>100,@>200",     two_op(MOV,  2,0, 2,0), 0x0100, 0x0200)  # @sym, @sym
emit("MOV @>10(r1),@>20(r2)", two_op(MOV, 2,2, 2,1), 0x0010, 0x0020) # indexed,indexed

total = len(out)
print(f"Total binary size: {total} bytes (0x{total:04X})")

# Write expected file for verifier
with open("tms9900_expected.txt", "w") as f:
    for addr, exp in entries:
        f.write(f"0x{addr:04X}  {exp}\n")
print(f"Written: tms9900_expected.txt ({len(entries)} entries)")

with open("tms9900_test.bin", "wb") as f:
    f.write(out)
print("Written: tms9900_test.bin")
