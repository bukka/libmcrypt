# Microsoft Developer Studio Generated NMAKE File, Based on PEGWITLIB.dsp
!IF "$(CFG)" == ""
CFG=PEGWITLIB - Win32 Debug
!MESSAGE No configuration specified. Defaulting to PEGWITLIB - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "PEGWITLIB - Win32 Release" && "$(CFG)" != "PEGWITLIB - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "PEGWITLIB.mak" CFG="PEGWITLIB - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "PEGWITLIB - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "PEGWITLIB - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "PEGWITLIB - Win32 Release"

OUTDIR=.\LIBRelease
INTDIR=.\LIBRelease
# Begin Custom Macros
OutDir=.\LIBRelease
# End Custom Macros

ALL : "$(OUTDIR)\PEGWITLIB.lib"


CLEAN :
	-@erase "$(INTDIR)\binascw.obj"
	-@erase "$(INTDIR)\eliptic.obj"
	-@erase "$(INTDIR)\gettimeofday.obj"
	-@erase "$(INTDIR)\keyring.obj"
	-@erase "$(INTDIR)\lip.obj"
	-@erase "$(INTDIR)\onb.obj"
	-@erase "$(INTDIR)\onb_integer.obj"
	-@erase "$(INTDIR)\pegwitw.obj"
	-@erase "$(INTDIR)\pgwecc.obj"
	-@erase "$(INTDIR)\protocols1.obj"
	-@erase "$(INTDIR)\rijndael-alg-fst.obj"
	-@erase "$(INTDIR)\sha256.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\PEGWITLIB.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\PEGWITLIB.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\PEGWITLIB.lib" 
LIB32_OBJS= \
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
	"$(INTDIR)\sha256.obj"

"$(OUTDIR)\PEGWITLIB.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "PEGWITLIB - Win32 Debug"

OUTDIR=.\LIBDebug
INTDIR=.\LIBDebug
# Begin Custom Macros
OutDir=.\LIBDebug
# End Custom Macros

ALL : "$(OUTDIR)\PEGWITLIB.lib"


CLEAN :
	-@erase "$(INTDIR)\binascw.obj"
	-@erase "$(INTDIR)\eliptic.obj"
	-@erase "$(INTDIR)\gettimeofday.obj"
	-@erase "$(INTDIR)\keyring.obj"
	-@erase "$(INTDIR)\lip.obj"
	-@erase "$(INTDIR)\onb.obj"
	-@erase "$(INTDIR)\onb_integer.obj"
	-@erase "$(INTDIR)\pegwitw.obj"
	-@erase "$(INTDIR)\pgwecc.obj"
	-@erase "$(INTDIR)\protocols1.obj"
	-@erase "$(INTDIR)\rijndael-alg-fst.obj"
	-@erase "$(INTDIR)\sha256.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\PEGWITLIB.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MTd /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\PEGWITLIB.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\PEGWITLIB.lib" 
LIB32_OBJS= \
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
	"$(INTDIR)\sha256.obj"

"$(OUTDIR)\PEGWITLIB.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("PEGWITLIB.dep")
!INCLUDE "PEGWITLIB.dep"
!ELSE 
!MESSAGE Warning: cannot find "PEGWITLIB.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "PEGWITLIB - Win32 Release" || "$(CFG)" == "PEGWITLIB - Win32 Debug"
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

