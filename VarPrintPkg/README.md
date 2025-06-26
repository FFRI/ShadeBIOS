# VarPrintLib & VarPrintReader
In some system, you cannot use `Print(L"");` even if you try connecting all the controller handles.  
This library allows to print debug messages or status to the `VarPrint*` UEFI variables, allowing to get the variable contents and check them later.


## Features

#### VarPrintLib
- `VarPrint("hoge %d", someint)`: Writes debug msg (ascii format string) to `VarPrintVar` variable
    - Latest 8 `char[0x40]` msgs are stored
- `VarLogStatus(0xAA)`: Writes single byte to `VarLogStatus` variable
    - Latest 32 status are stored
- `VarPrintLargeBin(PtrToLargeData)`: Writes large binary data (up to 0x400 byte) to `VarLargeVar` variable
    - Only 1 data is stored
- `VarErase()`: Clear all messages and status

#### VarPrintReader
- UEFI app (execute via UEFI shell) to print var-printed messages/status/binaries.


## Installation
1. Setup EDK2
1. Copy VarPrintPkg to `edk2/`
1. Setup `edk2/Conf/target.txt`
    1. `ACTIVE_PLATFORM = VarPrintPkg/VarPrintPkg.dsc`
    1. `TARGET_ARCH = X64`
    1. `TOOL_CHAIN_TAG = GCC5`
1. `source edksetup.sh` & `build`

Then, setup just like the other EDK2 libraries, `#include <Library/VarPrintLib.h>`, and use library functions listed in Features.
Also, VarPrintReader.efi will be created (can be executed via UEFI shell).



## Author
Kazuki Matsuo. © FFRI Security, Inc. 2025

## License
Apache version 2.0
