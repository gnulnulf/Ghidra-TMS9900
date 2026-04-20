#@category Analysis
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand

af      = currentProgram.getAddressFactory()
space   = af.getDefaultAddressSpace()
start   = space.getAddress(0x0000)
end     = space.getAddress(0x00CF)

addrSet = AddressSet(start, end)
cmd     = DisassembleCommand(addrSet, addrSet, True)
cmd.applyTo(currentProgram, monitor)

listing = currentProgram.getListing()
print("=== TMS9900 Disassembly ===")
it = listing.getInstructions(start, True)
while it.hasNext():
    instr = it.next()
    if instr.getAddress().compareTo(end) > 0:
        break
    print("0x%04X  %s" % (instr.getAddress().getOffset(), instr.toString()))
print("=== END ===")
