# Microsoft Developer Studio Generated NMAKE File, Based on PEGWIT32.dsp
!IF "$(CFG)" == ""
CFG=PEGWIT32 - Win32 Debug
!MESSAGE No configuration specified. Defaulting to PEGWIT32 - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "PEGWIT32 - Win32 Release" && "$(CFG)" != "PEGWIT32 - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "PEGWIT32.mak" CFG="PEGWIT32 - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "PEGWIT32 - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "PEGWIT32 - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "PEGWIT32 - Win32 Release"

OUTDIR=.\CLRelease
INTDIR=.\CLRelease
# Begin Custom Macros
OutDir=.\CLRelease
# End Custom Macros

ALL : "$(OUTDIR)\PEGWIT32.exe"


CLEAN :
	-@erase "$(INTDIR)\binascw.obj"
	-@erase "$(INTDIR)\eliptic.obj"
	-@erase "$(INTDIR)\gettimeofday.obj"
	-@erase "$(INTDIR)\keyring.obj"
	-@erase "$(INTDIR)\lip.obj"
	-@erase "$(INTDIR)\onb.obj"
	-@erase "$(INTDIR)\onb_integer.obj"
	-@erase "$(INTDIR)\pegwit.obj"
	-@erase "$(INTDIR)\pegwitw.obj"
	-@erase "$(INTDIR)\pgwecc.obj"
	-@erase "$(INTDIR)\protocols1.obj"
	-@erase "$(INTDIR)\rijndael-alg-fst.obj"
	-@erase "$(INTDIR)\sha256.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\PEGWIT32.exe"
	-@erase "$(OUTDIR)\PEGWIT32.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /FAcs /Fa"$(INTDIR)\\" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\PEGWIT32.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib /nologo /subsystem:console /pdb:none /map:"$(INTDIR)\PEGWIT32.map" /machine:I386 /out:"$(OUTDIR)\PEGWIT32.exe" 
LINK32_OBJS= \
	"$(INTDIR)\binascw.obj" \
	"$(INTDIR)\eliptic.obj" \
	"$(INTDIR)\gettimeofday.obj" \
	"$(INTDIR)\keyring.obj" \
	"$(INTDIR)\lip.obj" \
	"$(INTDIR)\onb.obj" \
	"$(INTDIR)\onb_integer.obj" \
	"$(INTDIR)\pegwit.obj" \
	"$(INTDIR)\pegwitw.obj" \
	"$(INTDIR)\pgwecc.obj" \
	"$(INTDIR)\protocols1.obj" \
	"$(INTDIR)\rijndael-alg-fst.obj" \
	"$(INTDIR)\sha256.obj"

"$(OUTDIR)\PEGWIT32.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "PEGWIT32 - Win32 Debug"

OUTDIR=.\CLDebug
INTDIR=.\CLDebug
# Begin Custom Macros
OutDir=.\CLDebug
# End Custom Macros

ALL : "$(OUTDIR)\PEGWIT32.exe"


CLEAN :
	-@erase "$(INTDIR)\binascw.obj"
	-@erase "$(INTDIR)\eliptic.obj"
	-@erase "$(INTDIR)\gettimeofday.obj"
	-@erase "$(INTDIR)\keyring.obj"
	-@erase "$(INTDIR)\lip.obj"
	-@erase "$(INTDIR)\onb.obj"
	-@erase "$(INTDIR)\onb_integer.obj"
	-@erase "$(INTDIR)\pegwit.obj"
	-@erase "$(INTDIR)\pegwitw.obj"
	-@erase "$(INTDIR)\pgwecc.obj"
	-@erase "$(INTDIR)\protocols1.obj"
	-@erase "$(INTDIR)\rijndael-alg-fst.obj"
	-@erase "$(INTDIR)\sha256.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\PEGWIT32.exe"
	-@erase "$(OUTDIR)\PEGWIT32.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MTd /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /FAcs /Fa"$(INTDIR)\\" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\PEGWIT32.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib /nologo /subsystem:console /pdb:none /map:"$(INTDIR)\PEGWIT32.map" /debug /machine:I386 /out:"$(OUTDIR)\PEGWIT32.exe" 
LINK32_OBJS= \
	"$(INTDIR)\binascw.obj" \
	"$(INTDIR)\eliptic.obj" \
	"$(INTDIR)\gettimeofday.obj" \
	"$(INTDIR)\keyring.obj" \
	"$(INTDIR)\lip.obj" \
	"$(INTDIR)\onb.obj" \
	"$(INTDIR)\onb_integer.obj" \
	"$(INTDIR)\pegwit.obj" \
	"$(INTDIR)\pegwitw.obj" \
	"$(INTDIR)\pgwecc.obj" \
	"$(INTDIR)\protocols1.obj" \
	"$(INTDIR)\rijndael-alg-fst.obj" \
	"$(INTDIR)\sha256.obj"

"$(OUTDIR)\PEGWIT32.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("PEGWIT32.dep")
!INCLUDE "PEGWIT32.dep"
!ELSE 
!MESSAGE Warning: cannot find "PEGWIT32.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "PEGWIT32 - Win32 Release" || "$(CFG)" == "PEGWIT32 - Win32 Debug"
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


SOURCE=..\pegwit.c

"$(INTDIR)\pegwit.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


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



!ENDIF 

