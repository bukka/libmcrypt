# Microsoft Developer Studio Generated NMAKE File, Based on PEGWIT32DLL.dsp
!IF "$(CFG)" == ""
CFG=PEGWIT32DLL - Win32 Debug
!MESSAGE No configuration specified. Defaulting to PEGWIT32DLL - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "PEGWIT32DLL - Win32 Release" && "$(CFG)" != "PEGWIT32DLL - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "PEGWIT32DLL.mak" CFG="PEGWIT32DLL - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "PEGWIT32DLL - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "PEGWIT32DLL - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "PEGWIT32DLL - Win32 Release"

OUTDIR=.\CLDLLRelease
INTDIR=.\CLDLLRelease
# Begin Custom Macros
OutDir=.\CLDLLRelease
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\PEGWIT32DLL.exe"

!ELSE 

ALL : "PEGWITDLL - Win32 Release" "$(OUTDIR)\PEGWIT32DLL.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"PEGWITDLL - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\pegwit.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\PEGWIT32DLL.exe"
	-@erase "$(OUTDIR)\PEGWIT32DLL.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\PEGWIT32DLL.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib /nologo /subsystem:console /pdb:none /map:"$(INTDIR)\PEGWIT32DLL.map" /machine:I386 /out:"$(OUTDIR)\PEGWIT32DLL.exe" 
LINK32_OBJS= \
	"$(INTDIR)\pegwit.obj" \
	".\DLLRelease\PEGWITDLL.lib"

"$(OUTDIR)\PEGWIT32DLL.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "PEGWIT32DLL - Win32 Debug"

OUTDIR=.\CLDLLDebug
INTDIR=.\CLDLLDebug
# Begin Custom Macros
OutDir=.\CLDLLDebug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\PEGWIT32DLL.exe"

!ELSE 

ALL : "PEGWITDLL - Win32 Debug" "$(OUTDIR)\PEGWIT32DLL.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"PEGWITDLL - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\pegwit.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\PEGWIT32DLL.exe"
	-@erase "$(OUTDIR)\PEGWIT32DLL.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MTd /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\PEGWIT32DLL.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib /nologo /subsystem:console /pdb:none /map:"$(INTDIR)\PEGWIT32DLL.map" /debug /machine:I386 /out:"$(OUTDIR)\PEGWIT32DLL.exe" 
LINK32_OBJS= \
	"$(INTDIR)\pegwit.obj" \
	".\DLLDebug\PEGWITDLL.lib"

"$(OUTDIR)\PEGWIT32DLL.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("PEGWIT32DLL.dep")
!INCLUDE "PEGWIT32DLL.dep"
!ELSE 
!MESSAGE Warning: cannot find "PEGWIT32DLL.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "PEGWIT32DLL - Win32 Release" || "$(CFG)" == "PEGWIT32DLL - Win32 Debug"
SOURCE=..\pegwit.c

"$(INTDIR)\pegwit.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!IF  "$(CFG)" == "PEGWIT32DLL - Win32 Release"

"PEGWITDLL - Win32 Release" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F .\PEGWITDLL.mak CFG="PEGWITDLL - Win32 Release" 
   cd "."

"PEGWITDLL - Win32 ReleaseCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F .\PEGWITDLL.mak CFG="PEGWITDLL - Win32 Release" RECURSE=1 CLEAN 
   cd "."

!ELSEIF  "$(CFG)" == "PEGWIT32DLL - Win32 Debug"

"PEGWITDLL - Win32 Debug" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F .\PEGWITDLL.mak CFG="PEGWITDLL - Win32 Debug" 
   cd "."

"PEGWITDLL - Win32 DebugCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F .\PEGWITDLL.mak CFG="PEGWITDLL - Win32 Debug" RECURSE=1 CLEAN 
   cd "."

!ENDIF 


!ENDIF 

