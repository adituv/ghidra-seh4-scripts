# SEH4 Ghidra Scripts

Python scripts to help automate analysis of SEH4 functions.  **Currently only supports 32-bit executables**.
The scripts are pretty hacky so I don't recommend using them except as reference.

* SetupSEH4DataTypes.py - defines the required datatypes, from chandler4.c in the Visual Studio crt source.
* AnalyseInlineSEH4.py - attemps to detect an inlined SEH4 prolog, and defines stack variable and scopetable for the registration

In future, AnalyseInlineSEH4 will do some sort of \_\_try/\_\_except/\_\_finally annotation, but it depends on
what is possible in Ghidra's API.