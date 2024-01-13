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
	
	if sehFoundState == 0:
		if mn == u"PUSH" and instr.getOperandType(0) == OperandType.SCALAR:
			# stack delta parameter
			sehFoundState = 1
	elif sehFoundState == 1:
		if mn == u"PUSH" and (instr.getOperandType(0) & OperandType.SCALAR != 0) and (instr.getOperandType(0) & OperandType.ADDRESS != 0):
			sehFoundState = 2
			scopeTable = instr.getOpObjects(0)[0].getUnsignedValue()
		else:
			sehFoundState = 0
			continue
	elif sehFoundState == 2:
		if mn == u"CALL":
			dest = instr.getOpObjects(0)[0]
			destFuncName = getFunctionAt(dest).getName()
			
			if destFuncName == "__SEH_prolog4" or destFuncName == "_SEH_prolog4" or destFuncName == "__SEH_prolog4_GS" or destFuncName == "_SEH_prolog4_GS":
				sehFoundState = 3
				break
			else:
				sehFoundState = 0
				continue
		else:
			sehFoundState = 0
			continue
	
	instr = instr.getNext()


stackFrame = func.getStackFrame()
dtreg = currentProgram.getDataTypeManager().getDataType("/chandler4.c/_EH4_EXCEPTION_REGISTRATION_RECORD")

if sehFoundState == 3:
	stackOffset = -stackOffset - 20
	for i in xrange(0, 0x18):
		stackFrame.clearVariable(stackOffset-i)
		stackFrame.createVariable("__seh4_registration", stackOffset, dtreg, SourceType.ANALYSIS)
		
	defineScopeTable(toAddr(scopeTable))
	createLabel(toAddr(scopeTable), "__seh4_scopetable", func, True, SourceType.ANALYSIS)
	
	setPreComment(func.getEntryPoint(), "This function uses SEH4.\n\tScope Table: {{@symbol {0:x}}}".format(scopeTable))
else:
	print("Inlined SEH4 prolog not found.")
