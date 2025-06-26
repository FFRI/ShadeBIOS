# Module Loader
DXE module (ModuleLoaderDxe) that loads & executes DXE modules from USB stick.  
ModuleLoaderDxe was created to eliminate the need to r/w the SPI flash chip each time and to enable the execution of DXE modules via USB stick.


## Installation
1. Setup EDK2
1. Setup VarPrintLib
1. Copy ModuleLoaderPkg to `edk2/`
1. Setup `edk2/Conf/target.txt`
    1. `ACTIVE_PLATFORM = ModuleLoaderPkg/ModuleLoaderPkg.dsc`
    1. `TARGET_ARCH = X64`
    1. `TOOL_CHAIN_TAG = GCC5`
1. `source edksetup.sh` & `build` => ModuleLoaderDxe.efi is created
1. Install this DXE module to the system (Flash it in SPI flash, include in OROM, ...)


## Usage
1. Create `EFILOAD/` folder in USB root
1. Rename the DXE modules to `dxemod.efi`, `dxemod2.efi`, ..., `dxemod5.efi` and place it in `EFILOAD/` folder
1. Plug the USB stick to the target system which has ModuleLoaderDxe installed and boot
1. `dxemod5` is executed last


## Author
Kazuki Matsuo. © FFRI Security, Inc. 2025

## License
Apache version 2.0
