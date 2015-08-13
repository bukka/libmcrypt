# LibMcrypt TODO list

## Build
- modify version macro for `AC_PREREQ([2.69])`
- use `AC_CONFIG_HEADERS([config.h])` instead of `DEFS`
- use `AC_CONFIG_FILES(file..., cmds)` instead of `AC_OUTPUT(file...)`
  - `AC_OUTPUT` should be emtpy after that
  - it should also replace `AC_OUTPUT_COMMANDS`
- use m4 function for setting default modules
  - rewrite generation of output files
  - use in variables settings
  - try to use it in Automake `SUBDIR`


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
