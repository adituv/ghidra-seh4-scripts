from ghidra.program.model.data import ArrayDataType
from ghidra.program.model.lang import OperandType
from ghidra.program.model.symbol import SourceType

func = getFunctionContaining(currentLocation.getAddress())
funcbody = func.getBody()

instr = getInstructionAt(func.getEntryPoint())
stackOffset = 0
scopeTable = 0
sehFoundState = 0

def defineScopeTable(addr):
	dtst = currentProgram.getDataTypeManager().getDataType("/chandler4.c/_EH4_SCOPETABLE")
	dtstr = currentProgram.getDataTypeManager().getDataType("/chandler4.c/_EH4_SCOPETABLE_RECORD")

	clearListing(addr, addr.add(15+12))
	
	createData(addr, dtst)
	createData(addr.add(16), ArrayDataType(dtstr, 1, 12))

while funcbody.contains(instr.getAddress()):
	mn = instr.getMnemonicString()
	
	if mn == u"PUSH":
		stackOffset = stackOffset + 4
	if mn == u"CALL" or mn == u"JMP":
		# control-flow instruction; probably not a function with inlined SEH4 prolog
		sehFoundState = 0
		break
	
	# Other than in sehFoundState == 0, on failing the next state transition,
	# continue without incrementing the instruction on purpose in case that instruction
	# is the push that's the start of the inlined SEH4 prolog
	if sehFoundState == 0:
		if mn == u"PUSH" and instr.getOperandType(0) == OperandType.SCALAR and instr.getOpObjects(0)[0].getSignedValue() == -2:
			sehFoundState = 1
	elif sehFoundState == 1:
		if mn == u"PUSH" and (instr.getOperandType(0) & OperandType.SCALAR != 0) and (instr.getOperandType(0) & OperandType.ADDRESS != 0):
			sehFoundState = 2
			scopeTable = instr.getOpObjects(0)[0].getUnsignedValue()
		else:
			sehFoundState = 0
			continue
	elif sehFoundState == 2:
		if mn == u"PUSH" and (instr.getOperandType(0) & OperandType.SCALAR != 0) and (instr.getOperandType(0) & OperandType.ADDRESS != 0):
			# __except_handler4 being pushed
			sehFoundState = 3
		else:
			sehFoundState = 0
			continue
	elif sehFoundState == 3:
		if mn == u"MOV" and (instr.getOperandType(1) & OperandType.ADDRESS != 0) and (instr.getOperandType(1) & OperandType.DYNAMIC != 0) and instr.getOpObjects(1)[0].getName() == "FS" and instr.getOpObjects(1)[1].getValue() == 0:
			# mov ???, FS:[0]
			# loading from ExceptionList.  This is the real important detection; the previous states
			# are just to get the scope table address, and to differentiate between SEH4 and other
			# exception mechanisms
			sehFoundState = 4
			break
		else:
			sehFoundState = 0
			continue
	instr = instr.getNext()

# Incorporate the remaining parts of the exception registration structure on the stack
stackOffset = stackOffset + 12
stackFrame = func.getStackFrame()
dtreg = currentProgram.getDataTypeManager().getDataType("/chandler4.c/_EH4_EXCEPTION_REGISTRATION_RECORD")

if sehFoundState == 4:
	if stackFrame.getLocalSize() < stackOffset:
		stackFrame.setLocalSize(stackOffset)
	
	stackOffset = -stackOffset
	for i in xrange(0, 0x18):
		stackFrame.clearVariable(stackOffset-i)
		stackFrame.createVariable("__seh4_registration", stackOffset, dtreg, SourceType.ANALYSIS)
		
	defineScopeTable(toAddr(scopeTable))
	createLabel(toAddr(scopeTable), "__seh4_scopetable", func, True, SourceType.ANALYSIS)
else:
	print("Inlined SEH4 prolog not found.")
