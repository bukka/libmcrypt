# Microsoft Developer Studio Generated NMAKE File, Based on PEGWITDLL.dsp
!IF "$(CFG)" == ""
CFG=PEGWITDLL - Win32 Debug
!MESSAGE No configuration specified. Defaulting to PEGWITDLL - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "PEGWITDLL - Win32 Release" && "$(CFG)" != "PEGWITDLL - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "PEGWITDLL.mak" CFG="PEGWITDLL - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "PEGWITDLL - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PEGWITDLL - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "PEGWITDLL - Win32 Release"

OUTDIR=.\DLLRelease
INTDIR=.\DLLRelease
# Begin Custom Macros
OutDir=.\DLLRelease
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\PEGWITDLL.dll"

!ELSE 

ALL : "PEGWITLIB - Win32 Release" "$(OUTDIR)\PEGWITDLL.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"PEGWITLIB - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\dll.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\PEGWITDLL.dll"
	-@erase "$(OUTDIR)\PEGWITDLL.exp"
	-@erase "$(OUTDIR)\PEGWITDLL.lib"
	-@erase "$(OUTDIR)\PEGWITDLL.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MT /W3 /GX /O2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "PEGWITDLL_EXPORTS" /D "DLL" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

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

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\PEGWITDLL.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib /nologo /dll /pdb:none /map:"$(INTDIR)\PEGWITDLL.map" /machine:I386 /def:"..\pegwitdll.def" /out:"$(OUTDIR)\PEGWITDLL.dll" /implib:"$(OUTDIR)\PEGWITDLL.lib" 
DEF_FILE= \
	"..\pegwitdll.def"
LINK32_OBJS= \
	"$(INTDIR)\dll.obj" \
	".\LIBRelease\PEGWITLIB.lib"

"$(OUTDIR)\PEGWITDLL.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "PEGWITDLL - Win32 Debug"

OUTDIR=.\DLLDebug
INTDIR=.\DLLDebug
# Begin Custom Macros
OutDir=.\DLLDebug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\PEGWITDLL.dll"

!ELSE 

ALL : "PEGWITLIB - Win32 Debug" "$(OUTDIR)\PEGWITDLL.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"PEGWITLIB - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\dll.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\PEGWITDLL.dll"
	-@erase "$(OUTDIR)\PEGWITDLL.exp"
	-@erase "$(OUTDIR)\PEGWITDLL.lib"
	-@erase "$(OUTDIR)\PEGWITDLL.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MTd /W3 /GX /Z7 /Od /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "PEGWITDLL_EXPORTS" /D "DLL" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

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

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\PEGWITDLL.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib /nologo /dll /pdb:none /map:"$(INTDIR)\PEGWITDLL.map" /debug /machine:I386 /def:"..\pegwitdll.def" /out:"$(OUTDIR)\PEGWITDLL.dll" /implib:"$(OUTDIR)\PEGWITDLL.lib" 
DEF_FILE= \
	"..\pegwitdll.def"
LINK32_OBJS= \
	"$(INTDIR)\dll.obj" \
	".\LIBDebug\PEGWITLIB.lib"

"$(OUTDIR)\PEGWITDLL.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("PEGWITDLL.dep")
!INCLUDE "PEGWITDLL.dep"
!ELSE 
!MESSAGE Warning: cannot find "PEGWITDLL.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "PEGWITDLL - Win32 Release" || "$(CFG)" == "PEGWITDLL - Win32 Debug"
SOURCE=..\dll.c

"$(INTDIR)\dll.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!IF  "$(CFG)" == "PEGWITDLL - Win32 Release"

"PEGWITLIB - Win32 Release" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F .\PEGWITLIB.mak CFG="PEGWITLIB - Win32 Release" 
   cd "."

"PEGWITLIB - Win32 ReleaseCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F .\PEGWITLIB.mak CFG="PEGWITLIB - Win32 Release" RECURSE=1 CLEAN 
   cd "."

!ELSEIF  "$(CFG)" == "PEGWITDLL - Win32 Debug"

"PEGWITLIB - Win32 Debug" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F .\PEGWITLIB.mak CFG="PEGWITLIB - Win32 Debug" 
   cd "."

"PEGWITLIB - Win32 DebugCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F .\PEGWITLIB.mak CFG="PEGWITLIB - Win32 Debug" RECURSE=1 CLEAN 
   cd "."

!ENDIF 


!ENDIF 

