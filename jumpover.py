# This is a simple script that will basically nop out the current assembly selection by jumping from the start to the end.
# Simple but useful if certain blocks can be skipped entirely.

# @r3ck0_
# @category MyScripts
# @menupath MyScripts.JumpOver
# @toolbar python.png


from ghidra.app.plugin.assembler import Assemblers
from ghidra.program.disassemble import Disassembler

#TODO Add User Code Here

minAddr = currentSelection.getMinAddress()
maxAddr = currentSelection.getMaxAddress()
delta = maxAddr.getOffset() - minAddr.getOffset()

assembler = Assemblers.getAssembler(currentProgram)
new_bytes = assembler.assembleLine(minAddr, "JMP " + str(maxAddr.getOffset() + 1))

listing = currentProgram.getListing()
address_set = currentProgram.getAddressFactory().getAddressSet(minAddr, maxAddr)

for instruction in listing.getInstructions(address_set, True):
	listing.clearCodeUnits(instruction.getAddress(), instruction.getAddress().add(instruction.getLength() - 1), True)

currentProgram.getMemory().setBytes(minAddr, new_bytes)
Disassembler.getDisassembler(currentProgram, monitor, None).disassemble(minAddr, None)
