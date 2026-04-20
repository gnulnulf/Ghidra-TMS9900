# Ghidra-TMS9900

Implements complete TMS9900 16-bit processor disassembly for Ghidra.

Install as a plugin using ghidra menu options

Instruction set coverage:
- Immediate operand:   LI, AI, ANDI, ORI, CI
- Workspace pointer:   STWP, STST, LWPI, LIMI
- Privileged/misc:     IDLE, RSET, RTWP, CKON, CKOF, LREX
- Single operand:      BLWP, B, X, CLR, NEG, INV, INC, INCT,
                       DEC, DECT, BL, SWPB, SETO, ABS
- Shift:               SRA, SRL, SLA, SRC
- Jump (13 variants):  JMP, JLT, JLE, JEQ, JHE, JGT, JNE,
                       JNC, JOC, JNO, JL, JH, JOP
- Two-operand Rx/Ry:   COC, CZC, XOR, XOP, MPY, DIV, LDCR, STCR
- Two-operand general: MOV, MOVB, A, AB, S, SB, C, CB,
                       SZC, SZCB, SOC, SOCB

Addressing mode coverage:
- Rn        register direct
- *Rn       register indirect
- *Rn+      register indirect autoincrement
- @sym      symbolic (absolute address)
- @sym(Rn)  indexed (base register + offset)
- All modes verified as both src and dst operands
- Mixed src+dst mode combinations verified

Test infrastructure (test/):
- make_test_bin.py    generates 208-byte test binary covering all forms
- DumpListing.py      Ghidra headless disassembly script
- verify_disasm.py    automated verifier
- tms9900_test.bin    compiled test binary (86 instructions)
- tms9900_expected.txt expected disassembly output

Verified: 86/86 instructions pass (100%) with Ghidra 11.4.2
