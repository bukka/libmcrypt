# Microsoft Developer Studio Generated NMAKE File, Based on PEGWITWDLL.dsp
!IF "$(CFG)" == ""
CFG=PEGWITWDLL - Win32 Debug
!MESSAGE No configuration specified. Defaulting to PEGWITWDLL - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "PEGWITWDLL - Win32 Release" && "$(CFG)" != "PEGWITWDLL - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "PEGWITWDLL.mak" CFG="PEGWITWDLL - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "PEGWITWDLL - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "PEGWITWDLL - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "PEGWITWDLL - Win32 Release"

OUTDIR=.\GUIDLLRelease
INTDIR=.\GUIDLLRelease
# Begin Custom Macros
OutDir=.\GUIDLLRelease
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\PEGWITWDLL.exe"

!ELSE 

ALL : "PEGWITDLL - Win32 Release" "$(OUTDIR)\PEGWITWDLL.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"PEGWITDLL - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\PEGWIT.res"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\windowdll.obj"
	-@erase "$(OUTDIR)\PEGWITWDLL.exe"
	-@erase "$(OUTDIR)\PEGWITWDLL.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\PEGWIT.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\PEGWITWDLL.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib comdlg32.lib shell32.lib /nologo /subsystem:windows /pdb:none /map:"$(INTDIR)\PEGWITWDLL.map" /machine:I386 /out:"$(OUTDIR)\PEGWITWDLL.exe" 
LINK32_OBJS= \
	"$(INTDIR)\windowdll.obj" \
	"$(INTDIR)\PEGWIT.res" \
	".\DLLRelease\PEGWITDLL.lib"

"$(OUTDIR)\PEGWITWDLL.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "PEGWITWDLL - Win32 Debug"

OUTDIR=.\GUIDLLDebug
INTDIR=.\GUIDLLDebug
# Begin Custom Macros
OutDir=.\GUIDLLDebug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\PEGWITWDLL.exe"

!ELSE 

ALL : "PEGWITDLL - Win32 Debug" "$(OUTDIR)\PEGWITWDLL.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"PEGWITDLL - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\PEGWIT.res"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\windowdll.obj"
	-@erase "$(OUTDIR)\PEGWITWDLL.exe"
	-@erase "$(OUTDIR)\PEGWITWDLL.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MTd /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\PEGWIT.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\PEGWITWDLL.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib comdlg32.lib shell32.lib /nologo /subsystem:windows /pdb:none /map:"$(INTDIR)\PEGWITWDLL.map" /debug /machine:I386 /out:"$(OUTDIR)\PEGWITWDLL.exe" 
LINK32_OBJS= \
	"$(INTDIR)\windowdll.obj" \
	"$(INTDIR)\PEGWIT.res" \
	".\DLLDebug\PEGWITDLL.lib"

"$(OUTDIR)\PEGWITWDLL.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("PEGWITWDLL.dep")
!INCLUDE "PEGWITWDLL.dep"
!ELSE 
!MESSAGE Warning: cannot find "PEGWITWDLL.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "PEGWITWDLL - Win32 Release" || "$(CFG)" == "PEGWITWDLL - Win32 Debug"
SOURCE=..\PEGWIT.RC

!IF  "$(CFG)" == "PEGWITWDLL - Win32 Release"


"$(INTDIR)\PEGWIT.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\PEGWIT.res" /i "\CODE\PEGWIT\new1" /d "NDEBUG" $(SOURCE)


!ELSEIF  "$(CFG)" == "PEGWITWDLL - Win32 Debug"


"$(INTDIR)\PEGWIT.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\PEGWIT.res" /i "\CODE\PEGWIT\new1" /d "_DEBUG" $(SOURCE)


!ENDIF 

SOURCE=..\windowdll.c

"$(INTDIR)\windowdll.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!IF  "$(CFG)" == "PEGWITWDLL - Win32 Release"

"PEGWITDLL - Win32 Release" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F .\PEGWITDLL.mak CFG="PEGWITDLL - Win32 Release" 
   cd "."

"PEGWITDLL - Win32 ReleaseCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F .\PEGWITDLL.mak CFG="PEGWITDLL - Win32 Release" RECURSE=1 CLEAN 
   cd "."

!ELSEIF  "$(CFG)" == "PEGWITWDLL - Win32 Debug"

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

