# Microsoft Developer Studio Project File - Name="PEGWITW" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=PEGWITW - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "PEGWITW.mak".
!MESSAGE 
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

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "PEGWITW - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "GUIRelease"
# PROP Intermediate_Dir "GUIRelease"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /FAcs /FD /c
# SUBTRACT CPP /YX
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib comdlg32.lib shell32.lib /nologo /subsystem:windows /pdb:none /map /machine:I386
# SUBTRACT LINK32 /debug

!ELSEIF  "$(CFG)" == "PEGWITW - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "GUIDebug"
# PROP Intermediate_Dir "GUIDebug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /FAcs /FD /GZ /c
# SUBTRACT CPP /YX
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib comdlg32.lib shell32.lib /nologo /subsystem:windows /pdb:none /map /debug /machine:I386

!ENDIF 

# Begin Target

# Name "PEGWITW - Win32 Release"
# Name "PEGWITW - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\binascw.c
# End Source File
# Begin Source File

SOURCE=..\eliptic.c
# End Source File
# Begin Source File

SOURCE=..\gettimeofday.c
# End Source File
# Begin Source File

SOURCE=..\keyring.c
# End Source File
# Begin Source File

SOURCE=..\lip.c
# End Source File
# Begin Source File

SOURCE=..\onb.c
# End Source File
# Begin Source File

SOURCE=..\onb_integer.c
# End Source File
# Begin Source File

SOURCE=..\PEGWIT.RC
# End Source File
# Begin Source File

SOURCE=..\pegwitw.c
# End Source File
# Begin Source File

SOURCE=..\pgwecc.c
# End Source File
# Begin Source File

SOURCE=..\protocols1.c
# End Source File
# Begin Source File

SOURCE="..\rijndael-alg-fst.c"
# End Source File
# Begin Source File

SOURCE=..\sha256.c
# End Source File
# Begin Source File

SOURCE=..\window.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\binascw.h
# End Source File
# Begin Source File

SOURCE=..\eliptic.h
# End Source File
# Begin Source File

SOURCE=..\field2n.h
# End Source File
# Begin Source File

SOURCE=..\keyring.h
# End Source File
# Begin Source File

SOURCE=..\lip.h
# End Source File
# Begin Source File

SOURCE=..\pegwitw.h
# End Source File
# Begin Source File

SOURCE=..\pgwecc.h
# End Source File
# Begin Source File

SOURCE=..\protocols.h
# End Source File
# Begin Source File

SOURCE=..\RC.H
# End Source File
# Begin Source File

SOURCE="..\rijndael-alg-fst.h"
# End Source File
# Begin Source File

SOURCE=..\sha256.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=..\PEGWIT.ICO
# End Source File
# End Group
# End Target
# End Project
