# Microsoft Developer Studio Generated NMAKE File, Based on PEGWITW.dsp
!IF "$(CFG)" == ""
CFG=PEGWITW - Win32 Debug
!MESSAGE No configuration specified. Defaulting to PEGWITW - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "PEGWITW - Win32 Release" && "$(CFG)" != "PEGWITW - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "PEGWITW.mak" CFG="PEGWITW - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "PEGWITW - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "PEGWITW - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "PEGWITW - Win32 Release"

OUTDIR=.\GUIRelease
INTDIR=.\GUIRelease
# Begin Custom Macros
OutDir=.\GUIRelease
# End Custom Macros

ALL : "$(OUTDIR)\PEGWITW.exe"


CLEAN :
	-@erase "$(INTDIR)\binascw.obj"
	-@erase "$(INTDIR)\eliptic.obj"
	-@erase "$(INTDIR)\gettimeofday.obj"
	-@erase "$(INTDIR)\keyring.obj"
	-@erase "$(INTDIR)\lip.obj"
	-@erase "$(INTDIR)\onb.obj"
	-@erase "$(INTDIR)\onb_integer.obj"
	-@erase "$(INTDIR)\PEGWIT.res"
	-@erase "$(INTDIR)\pegwitw.obj"
	-@erase "$(INTDIR)\pgwecc.obj"
	-@erase "$(INTDIR)\protocols1.obj"
	-@erase "$(INTDIR)\rijndael-alg-fst.obj"
	-@erase "$(INTDIR)\sha256.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\window.obj"
	-@erase "$(OUTDIR)\PEGWITW.exe"
	-@erase "$(OUTDIR)\PEGWITW.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /FAcs /Fa"$(INTDIR)\\" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\PEGWITW.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib comdlg32.lib shell32.lib /nologo /subsystem:windows /pdb:none /map:"$(INTDIR)\PEGWITW.map" /machine:I386 /out:"$(OUTDIR)\PEGWITW.exe" 
LINK32_OBJS= \
	"$(INTDIR)\binascw.obj" \
	"$(INTDIR)\eliptic.obj" \
	"$(INTDIR)\gettimeofday.obj" \
	"$(INTDIR)\keyring.obj" \
	"$(INTDIR)\lip.obj" \
	"$(INTDIR)\onb.obj" \
	"$(INTDIR)\onb_integer.obj" \
	"$(INTDIR)\pegwitw.obj" \
	"$(INTDIR)\pgwecc.obj" \
	"$(INTDIR)\protocols1.obj" \
	"$(INTDIR)\rijndael-alg-fst.obj" \
	"$(INTDIR)\sha256.obj" \
	"$(INTDIR)\window.obj" \
	"$(INTDIR)\PEGWIT.res"

"$(OUTDIR)\PEGWITW.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "PEGWITW - Win32 Debug"

OUTDIR=.\GUIDebug
INTDIR=.\GUIDebug
# Begin Custom Macros
OutDir=.\GUIDebug
# End Custom Macros

ALL : "$(OUTDIR)\PEGWITW.exe"


CLEAN :
	-@erase "$(INTDIR)\binascw.obj"
	-@erase "$(INTDIR)\eliptic.obj"
	-@erase "$(INTDIR)\gettimeofday.obj"
	-@erase "$(INTDIR)\keyring.obj"
	-@erase "$(INTDIR)\lip.obj"
	-@erase "$(INTDIR)\onb.obj"
	-@erase "$(INTDIR)\onb_integer.obj"
	-@erase "$(INTDIR)\PEGWIT.res"
	-@erase "$(INTDIR)\pegwitw.obj"
	-@erase "$(INTDIR)\pgwecc.obj"
	-@erase "$(INTDIR)\protocols1.obj"
	-@erase "$(INTDIR)\rijndael-alg-fst.obj"
	-@erase "$(INTDIR)\sha256.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\window.obj"
	-@erase "$(OUTDIR)\PEGWITW.exe"
	-@erase "$(OUTDIR)\PEGWITW.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MTd /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /FAcs /Fa"$(INTDIR)\\" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\PEGWITW.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib comdlg32.lib shell32.lib /nologo /subsystem:windows /pdb:none /map:"$(INTDIR)\PEGWITW.map" /debug /machine:I386 /out:"$(OUTDIR)\PEGWITW.exe" 
LINK32_OBJS= \
	"$(INTDIR)\binascw.obj" \
	"$(INTDIR)\eliptic.obj" \
	"$(INTDIR)\gettimeofday.obj" \
	"$(INTDIR)\keyring.obj" \
	"$(INTDIR)\lip.obj" \
	"$(INTDIR)\onb.obj" \
	"$(INTDIR)\onb_integer.obj" \
	"$(INTDIR)\pegwitw.obj" \
	"$(INTDIR)\pgwecc.obj" \
	"$(INTDIR)\protocols1.obj" \
	"$(INTDIR)\rijndael-alg-fst.obj" \
	"$(INTDIR)\sha256.obj" \
	"$(INTDIR)\window.obj" \
	"$(INTDIR)\PEGWIT.res"

"$(OUTDIR)\PEGWITW.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("PEGWITW.dep")
!INCLUDE "PEGWITW.dep"
!ELSE 
!MESSAGE Warning: cannot find "PEGWITW.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "PEGWITW - Win32 Release" || "$(CFG)" == "PEGWITW - Win32 Debug"
SOURCE=..\binascw.c

"$(INTDIR)\binascw.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\eliptic.c

"$(INTDIR)\eliptic.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\gettimeofday.c

"$(INTDIR)\gettimeofday.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\keyring.c

"$(INTDIR)\keyring.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\lip.c

"$(INTDIR)\lip.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\onb.c

"$(INTDIR)\onb.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\onb_integer.c

"$(INTDIR)\onb_integer.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\PEGWIT.RC

!IF  "$(CFG)" == "PEGWITW - Win32 Release"


"$(INTDIR)\PEGWIT.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\PEGWIT.res" /i "\CODE\PEGWIT\new1" /d "NDEBUG" $(SOURCE)


!ELSEIF  "$(CFG)" == "PEGWITW - Win32 Debug"


"$(INTDIR)\PEGWIT.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\PEGWIT.res" /i "\CODE\PEGWIT\new1" /d "_DEBUG" $(SOURCE)


!ENDIF 

SOURCE=..\pegwitw.c

"$(INTDIR)\pegwitw.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\pgwecc.c

"$(INTDIR)\pgwecc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\protocols1.c

"$(INTDIR)\protocols1.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE="..\rijndael-alg-fst.c"

"$(INTDIR)\rijndael-alg-fst.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\sha256.c

"$(INTDIR)\sha256.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\window.c

"$(INTDIR)\window.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

