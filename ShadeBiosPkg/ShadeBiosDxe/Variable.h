/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

#define EDKII_HTTP_TLS_CIPHER_LIST_VARIABLE  L"HttpTlsCipherList"
EFI_GUID gEdkiiHttpTlsCipherListGuid = \
  { 0x46ddb415, 0x5244, 0x49c7, { 0x93, 0x74, 0xf0, 0xe2, 0x98, 0xe7, 0xd3, 0x86 } };

#define EFI_TLS_CA_CERTIFICATE_VARIABLE  L"TlsCaCertificate"
EFI_GUID gEfiTlsCaCertificateGuid = \
  { 0xfd2340D0, 0x3dab, 0x4349, { 0xa6, 0xc7, 0x3b, 0x4f, 0x12, 0xb4, 0x8e, 0xae } };


/**

  Copy single boot-only variable to runtime variable with "_RT" appended at the VarName

**/
EFI_STATUS
EFIAPI
CopyToRtVar (
    IN  CHAR16    *VariableName,
    IN  EFI_GUID  *VendorGuid
    )
{
  EFI_STATUS Status;
  UINTN VarSize = 0;
  Status = gRT->GetVariable(
      VariableName,
      VendorGuid,
      NULL,
      &VarSize,
      NULL
      );
  if(Status!=EFI_BUFFER_TOO_SMALL) {
    Print(L"GetVariable(%s, size 0) failed %r\n", VariableName, Status);
    return Status;
  }

  VOID *VarData = NULL;
  Status = gBS->AllocatePool(
      EfiLoaderData,
      VarSize,
      &VarData
      );
  if(Status != EFI_SUCCESS) {
    Print(L"AllocatePool(VarSize:0x%x) failed %r\n", VarSize, Status);
    return Status;
  }

  UINT32 VarAttr = 0;
  Status = gRT->GetVariable(
      VariableName,
      VendorGuid,
      &VarAttr,
      &VarSize,
      VarData
      );
  if(Status != EFI_SUCCESS) {
    Print(L"GetVariable(%s, size 0x%x) failed %r\n", VariableName, VarSize, Status);
    gBS->FreePool(VarData);
    return Status;
  }

  VarAttr |= EFI_VARIABLE_RUNTIME_ACCESS;

  CHAR16 *NewVarName;
  UINTN NewVarSize = (StrLen(VariableName)+3+1)*sizeof(CHAR16);
  gBS->AllocatePool(
      EfiLoaderData,
      NewVarSize,
      (VOID**)&NewVarName
      );
  StrCpyS(NewVarName, NewVarSize, VariableName);
  StrCatS(NewVarName, NewVarSize, L"_RT");

  Status = gRT->SetVariable(
      NewVarName,
      VendorGuid,
      VarAttr,
      VarSize,
      VarData
      );
  if(Status != EFI_SUCCESS) {
    Print(L"SetVariable(%s) failed %r\n", NewVarName, Status);
    gBS->FreePool(NewVarName);
    gBS->FreePool(VarData);
    return Status;
  }

  Print(L"SetVariable(%s) %r\n", NewVarName, Status);

  gBS->FreePool(NewVarName);
  gBS->FreePool(VarData);
  return EFI_SUCCESS;
}



/**

  Save UEFI Variables which doesn't have EFI_VARIABLE_RUNTIME_ACCESS attributes
   * The boot-only variables that are created/set during DriverBinding->Supported/Start doesn't need to be saved
   * Variables that are only set before PC is shipped and doesn't have RT attr should be saved
   * This creates a copy of the variable with "_RT" appended at the VarName so that GetVariableHookRT can read it

**/
VOID
EFIAPI
SaveBootOnlyVariables(
    )
{
  CopyToRtVar(EFI_TLS_CA_CERTIFICATE_VARIABLE, &gEfiTlsCaCertificateGuid);
  CopyToRtVar(EDKII_HTTP_TLS_CIPHER_LIST_VARIABLE, &gEdkiiHttpTlsCipherListGuid);
}
