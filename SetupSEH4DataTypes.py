from ghidra.program.model.data import ArrayDataType, CategoryPath, DataTypeConflictHandler, FileDataTypeManager, FunctionDefinitionDataType, GenericCallingConvention, ParameterDefinitionImpl, PointerDataType, StructureDataType, TypedefDataType, UnionDataType

def getWin32Dtm():
	dtmservice = state.getTool().getService(ghidra.app.services.DataTypeManagerService)
	for dtm in dtmservice.getDataTypeManagers():
		if (dtm.__str__().startswith("FileDataTypeManager - windows_") and dtm.getName().endswith("_32")):
			return dtm
	return None

def makeFuncDef(ret, name, *params, **kwArgs):
	func_path = kwArgs.get("path") or CategoryPath("/")
	cconv = kwArgs.get("cconv") or GenericCallingConvention.unknown
	
	result = FunctionDefinitionDataType(func_path, name)
	result.setReturnType(ret)
	result.setArguments(map(lambda t: ParameterDefinitionImpl("", t, ""), params))
	result.setGenericCallingConvention(cconv)
	
	return result

def createSEH4Datatypes():
	seh_path = CategoryPath("/chandler4.c")
	
	dtm = currentProgram.getDataTypeManager()
	win32dtm = getWin32Dtm()
	win32_source = win32dtm.getSourceArchive(win32dtm.getUniversalID())
	
	dtvoid = dtm.getDataType("/void")
	
	dtbool = win32dtm.getDataType("/WinDef.h/BOOL")
	dtlong = win32dtm.getDataType("/winnt.h/LONG")
	dtulong = win32dtm.getDataType("/WinDef.h/ULONG")
	exception_disposition = win32dtm.getDataType("/excpt.h/_EXCEPTION_DISPOSITION")
	pexception_record = win32dtm.getDataType("/winnt.h/PEXCEPTION_RECORD")
	pexception_pointers = win32dtm.getDataType("/winnt.h/PEXCEPTION_POINTERS")
	pcontext = win32dtm.getDataType("/winnt.h/PCONTEXT")
	pvoid = win32dtm.getDataType("/winnt.h/PVOID")
	
	# dtbool.setSourceArchive(win32_source)
	# dtlong.setSourceArchive(win32_source)
	# dtulong.setSourceArchive(win32_source)
	# exception_disposition.setSourceArchive(win32_source)
	# pexception_record.setSourceArchive(win32_source)
	# pexception_pointers.setSourceArchive(win32_source)
	# pcontext.setSourceArchive(win32_source)
	# pvoid.setSourceArchive(win32_source)
	
	dtm.addDataType(dtbool, DataTypeConflictHandler.KEEP_HANDLER)
	dtm.addDataType(dtlong, DataTypeConflictHandler.KEEP_HANDLER)
	dtm.addDataType(dtulong, DataTypeConflictHandler.KEEP_HANDLER)
	dtm.addDataType(exception_disposition, DataTypeConflictHandler.KEEP_HANDLER)
	dtm.addDataType(pexception_record, DataTypeConflictHandler.KEEP_HANDLER)
	dtm.addDataType(pexception_pointers, DataTypeConflictHandler.KEEP_HANDLER)
	dtm.addDataType(pcontext, DataTypeConflictHandler.KEEP_HANDLER)
	dtm.addDataType(pvoid, DataTypeConflictHandler.KEEP_HANDLER)
	
	func_exception_filter_x86 = makeFuncDef(dtlong, "EXCEPTION_FILTER_X86", path=seh_path, cconv=GenericCallingConvention.cdecl)
	func_exception_handler_x86 = makeFuncDef(dtvoid, "EXCEPTION_HANDLER_X86", path=seh_path, cconv=GenericCallingConvention.cdecl)
	func_termination_handler_x86 = makeFuncDef(dtvoid, "TERMINATION_HANDLER_X86", dtbool)
	
	dtm.addDataType(func_exception_filter_x86, DataTypeConflictHandler.KEEP_HANDLER)
	dtm.addDataType(func_exception_handler_x86, DataTypeConflictHandler.KEEP_HANDLER)
	dtm.addDataType(func_termination_handler_x86, DataTypeConflictHandler.KEEP_HANDLER)
	
	pf_exception_filter_x86 = TypedefDataType(seh_path, "PEXCEPTION_FILTER_X86", PointerDataType(func_exception_filter_x86))
	pf_exception_handler_x86 = TypedefDataType(seh_path, "PEXCEPTION_HANDLER_X86", PointerDataType(func_exception_handler_x86))
	pf_termination_handler_x86 = TypedefDataType(seh_path, "PTERMINATION_HANDLER_X86", PointerDataType(func_termination_handler_x86))
	
	dtm.addDataType(pf_exception_filter_x86, DataTypeConflictHandler.KEEP_HANDLER)
	dtm.addDataType(pf_exception_handler_x86, DataTypeConflictHandler.KEEP_HANDLER)
	dtm.addDataType(pf_termination_handler_x86, DataTypeConflictHandler.KEEP_HANDLER)
	
	anonunion = UnionDataType(seh_path, "<AnonymousUnion_EH4_SCOPETABLE_RECORD>")
	anonunion.add(pf_exception_handler_x86, 4, "HandlerAddress", "")
	anonunion.add(pf_termination_handler_x86, 4, "FinallyFunc", "")
	
	dtm.addDataType(anonunion, DataTypeConflictHandler.KEEP_HANDLER)
	
	eh4_scopetable_record = StructureDataType(seh_path, "_EH4_SCOPETABLE_RECORD", 0)
	eh4_scopetable_record.add(dtulong, 4, "EnclosingLevel", "")
	eh4_scopetable_record.add(pf_exception_filter_x86, 4, "FilterFunc", "")
	eh4_scopetable_record.add(anonunion, 4, "u", "")
	
	dtm.addDataType(eh4_scopetable_record, DataTypeConflictHandler.KEEP_HANDLER)
	
	eh4_scopetable = StructureDataType(seh_path, "_EH4_SCOPETABLE", 0)
	eh4_scopetable.add(dtulong, 4, "GSCookieOffset", "")
	eh4_scopetable.add(dtulong, 4, "GSCookieXOROffset", "")
	eh4_scopetable.add(dtulong, 4, "EHCookieOffset", "")
	eh4_scopetable.add(dtulong, 4, "EHCookieXOROffset", "")
	eh4_scopetable.add(ArrayDataType(eh4_scopetable_record, 0, 0xc, dtm), 0, "ScopeRecord", "")
	
	dtm.addDataType(eh4_scopetable, DataTypeConflictHandler.KEEP_HANDLER)
	
	exception_registration_record = StructureDataType(seh_path, "_EXCEPTION_REGISTRATION_RECORD_IMPL", 0)
	pexception_registration_record = TypedefDataType(seh_path, "PEXCEPTION_REGISTRATION_RECORD_IMPL", PointerDataType(exception_registration_record))
	
	exception_registration_record.add(pexception_registration_record, 4, "Next", "")
	
	func__except_handler4 = makeFuncDef(exception_disposition, "__except_handler4", pexception_record, pexception_registration_record, pcontext, pvoid)
	
	exception_registration_record.add(PointerDataType(func__except_handler4), 4, "Handler", "")
	
	dtm.addDataType(exception_registration_record, DataTypeConflictHandler.KEEP_HANDLER)
	dtm.addDataType(pexception_registration_record, DataTypeConflictHandler.KEEP_HANDLER)
	dtm.addDataType(func__except_handler4, DataTypeConflictHandler.KEEP_HANDLER)
	
	eh4_exception_registration_record = StructureDataType(seh_path, "_EH4_EXCEPTION_REGISTRATION_RECORD", 0)
	eh4_exception_registration_record.add(pvoid, 4, "SavedESP", "")
	eh4_exception_registration_record.add(pexception_pointers, 4, "ExceptionPointers", "")
	eh4_exception_registration_record.add(exception_registration_record, 8, "SubRecord", "")
	eh4_exception_registration_record.add(PointerDataType(eh4_scopetable), 4, "EncodedScopeTable", "")
	eh4_exception_registration_record.add(dtulong, 4, "TryLevel", "")
	
	dtm.addDataType(eh4_exception_registration_record, DataTypeConflictHandler.KEEP_HANDLER)

createSEH4Datatypes()

pexception_registration_record = currentProgram.getDataTypeManager().getDataType("/chandler4.c/PEXCEPTION_REGISTRATION_RECORD_IMPL")
exceptionList = getSymbols("ExceptionList", None)[0].getAddress()
clearListing(exceptionList)
createData(exceptionList, pexception_registration_record)

