# LibMcrypt TODO list

## Build

### Autoconf
- modify version macro for `AC_PREREQ([2.69])`
- use `AC_CONFIG_HEADERS([config.h])` instead of `DEFS`
- use `AC_CONFIG_FILES(file..., cmds)` instead of `AC_OUTPUT(file...)`
  - `AC_OUTPUT` should be emtpy after that
  - it should also replace `AC_OUTPUT_COMMANDS`
- use m4 function for setting default modules
  - rewrite generation of output files
  - use in variables settings
  - try to use it in Automake `SUBDIR`
- use `AC_INCLUDES_DEFAULT` instead of part of `libdefs.h`
- check used particular types and some useful type (e.g. __int128)

### Automake
- limit the number of subdirs
  - try to generate one level list in AC
- make sure AM_CPPFLAGS are not rewritten by Module.inc

# Lib
- Use macros for `extern "C" {` and `}` when `__cplusplus` defined

## Modes

### Standard modes

#### OFB
- shift register seems to be unoptimal

#### FCS (Filtered counter scheme)
- check if it makes sense to implement

### Auth modes

#### CCM
- rewrite current implementation to match mcrypt one

#### GCM
- implement

## Secret Key

### Stream ciphers
- Find test vectors for PANAMA and WAKE and check the implementation.
