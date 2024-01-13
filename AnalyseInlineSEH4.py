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
	optype = instr.getOperandType(0)
	
	if mn == u"PUSH":
		stackOffset = stackOffset + 4
		if sehFoundState == 0:
			if instr.getOperandType(0) == OperandType.SCALAR and instr.getOpObjects(0)[0].getSignedValue() == -2:
				sehFoundState = 1
		elif sehFoundState == 1:
			if (optype & OperandType.SCALAR != 0) and (optype & OperandType.ADDRESS != 0):
				sehFoundState = 2
				scopeTable = instr.getOpObjects(0)[0].getUnsignedValue()
			else:
				sehFoundState = 0
				# Continue without incrementing the instruction on purpose
				# so that we can check for sehFoundState==0
				continue
		elif sehFoundState == 2:
			if (optype & OperandType.SCALAR != 0) and (optype & OperandType.ADDRESS != 0):
				sehFoundState = 3
			else:
				sehFoundState = 0
				# Continue without incrementing the instruction on purpose
				# so that we can check for sehFoundState==0
				continue
		else:
			sehFoundState = 0
			# Continue without incrementing the instruction on purpose
			# so that we can check for sehFoundState==0
			continue
	elif mn == u"MOV":
		if sehFoundState == 3:
			if (instr.getOperandType(1) & OperandType.ADDRESS != 0) and (instr.getOperandType(1) & OperandType.DYNAMIC != 0) and instr.getOpObjects(1)[0].getName() == "FS" and instr.getOpObjects(1)[1].getValue() == 0:
				sehFoundState = 4
				
				# This is good enough for now to assume that we have found an inlined SEH4 prolog
				break
		sehFoundState = 0
	elif mn == u"CALL" or mn == u"JMP":
		# Control flow is being transferred so we almost certainly don't have an inlined SEH4 prolog
		# TODO: handle explicit SEH4 prolog call
		sehFoundState = 0
		break
	else:
		sehFoundState = 0
	
	instr = instr.getNext()

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
