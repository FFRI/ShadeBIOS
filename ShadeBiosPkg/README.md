# Shade BIOS (stripped)
Most UEFI BIOS functionalities are lost after OS boot.
Therefore, UEFI malware finds it difficult to perform malicious activities (such as C2 communication) at runtime using only the BIOS code and relies on the kernel or userland.
Although they infect the BIOS, which has higher privileges than the OS, they are dependent on OS-level security and struggle to unleash the full potential of stealth.

Shade BIOS retains the BIOS after OS boot for OS-independent pure-BIOS malbehavior.
This work was presented at [Black Hat USA 2025](https://www.blackhat.com/us-25/briefings/schedule/#shade-bios-unleashing-the-full-stealth-of-uefi-malware-45786).
Please refer to the slides for an explanation of the inner workings.
For security reasons, this repository only contains the **STRIPPED** PoC code of Shade BIOS.
If you require the full source code, please contact us via email (research-feedback@ffri.jp).
Once your identity has been verified, I will send it directly to you.


## Components
- ShadeBiosDxe (DXE driver): Main DXE module that implements Shade BIOS
- ShadeBiosLoaderApp (UEFI app): This is used for ESP infection. First, it loads ShadeBiosDxe and subsequently executes bootmgfw.efi

## Installation & Usage
1. Prepare EDK2
1. Copy ShadeBiosPkg to `edk2/`
1. Setup `edk2/Conf/target.txt`
    1. `ACTIVE_PLATFORM = ShadeBiosPkg/ShadeBiosPkg.dsc`
    1. `TARGET_ARCH = X64`
    1. `TOOL_CHAIN_TAG = GCC5`
        1. VS cannot use inline assembly; thus, only GCC is supported
1. `source edksetup.sh` & `build` => ShadeBiosDxe.efi is created
1. Run this DXE module (Flash it in SPI flash, included in OROM, ...)

The malbehavior of Shade BIOS can be triggered automatically from the OS by hooking frequently used EFI Runtime Services such as `gRT->GetVariable()`.
In the current implementation, it is triggered by writing to the UEFI variable L`MyRtDxeTrig` such that the malbehavior can be executed on demand.
Writing to the UEFI variable is possible from the userland executable (requires admin priv), by calling such OS APIs as [SetFirmwareEnvironmentVariableExA](https://learn.microsoft.com/ja-jp/windows/win32/api/winbase/nf-winbase-setfirmwareenvironmentvariableexa).

Flashing the ROM each time is a tedious task. Therefore, I created ModuleLoaderPkg, a DXE module that reads and executes DXE modules from a USB stick. Using this module, you can simply place the `.efi` file in the USB and execute BIOS code on that machine.

**ShadeBios also works with ESP infection.**  
Place ShadeBiosDxe.efi at the root of the USB storage device and execute ShadeBiosLoaderApp on the UEFI shell.



## Debugging Tips
- Runtime BIOS code can be debugged by WinDbg! (`bcdedit /set bootdebug on`)
    - Just set `__asm__ __volatile__("int3");` in the source code, build it and execute it and WinDbg will break in
- No symbols are present; thus, if you do not know where you are when jumping to the different UEFI modules, only copy multiple bytes from RIP and search for those byte patterns using [UEFITool](https://github.com/LongSoft/UEFITool)
- If you want to check whether the ControllerHandle is properly configured, attempt checking the installed protocol on that handle referring to [IHANDLE](https://github.com/tianocore/edk2/blob/e489721275eafd89037c90df7cd99e0e511bb3ba/MdeModulePkg/Core/Dxe/Hand/Handle.h#L44) (`EFI_HANDLE` = `IHANDLE*`)



## How it works
You can find a detailed explanation of the mechanism if you refer to the presentation materials.
Here, I introduce the key events that occur in chronological order to assist in debugging or reading the source code.

#### Boot phase
1. DriverEntry
    1. Enable network stack (if you want to use it)
    1. Create partial identity map page tables
    1. Save gST/gBS/gRT for runtime to restore them
    1. Save(Copy) boot only UEFI variables that are set only during boot time
    1. Hook `gBS->GetMemoryMap` and `gRT->SetVariable` (SetVariable is for triggering the malbehavior)
1. GetMemoryMapHook (called multiple times during boot)
    1. Exec original `gBS->GetMemoryMap` and obtain memory map
    1. [Most Important] Modify the memory map
        1. StealMemoryForHeap: save some of EfiConventionalMemory to use as a Shade BIOS heap in runtime
        1. DisguiseMemoryMap: modify EfiBootServicesData/Code => EfiRuntimeServicesData/Code to retain BIOS environments
1. SetVirtualAddressMapEvent
    1. Convert global pointers that contain physical addresses to virtual address

#### Runtime phase
1. SetVariableHook
    1. If `VarName != MAGIC_VAR_NAME` then execute the original SetVariable and return
    1. Locate ntoskrnl.exe and get `nt!MmGetVirtualForPhysical` address
        1. This one kernel export must be used, but it cannot be the detection point for OS-level security (refer to slides)
    1. Steal some secrets from the target process
    1. ShadeBiosEnter()
        1. Modify gRT address from vir to phy address (as we perform partial identity mapping)
        1. Enable partial identity mapping
            1. Allows execution of physical address
            1. Cannot access userland virtual address while this is enabled
        1. Restore gBS and gST (some members are cleared after OS boot)
        1. Redirect allocation of EfiLoaderData/Code to EfiRuntimeServicesData/Code
        1. Initialize BIOS interrupt emulation (pseudo timer events)
        1. Disable external interrupts to prevent OS code execution
        1. Initialize Shade BIOS heap (prevent BIOS memory allocator from using OS memory)
    1. Hijacking Device Control
        1. If you want to use NIC, use HijackNicFromOS()
        1. Hijack functions perform the following in common:
            1. Get ControllerHandle of the target device
            1. `gBS->DisconnectController(ControllerHandle)` to reset the device
            1. `gBS->ConnectController(ControllerHandle)` to configure the device for BIOS to use
    1. Use UEFI protocols to access device
        1. C2 communications
            1. HttpInit/HttpSend
            1. Tcp4Init/Tcp4Send
        1. Disk access
            1. UsbInit/UsbWrite
            1. NtfsInit/NtfsWrite (WIP)
    1. ShadeBiosExit()
        1. Enable interrupts
        1. Switch back paging


## Author
Kazuki Matsuo. © FFRI Security, Inc. 2025

## License
Apache version 2.0
