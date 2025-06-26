/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */



/**

  "NOP" function by this

**/
EFI_STATUS
EFIAPI
Ret(
    )
{
  return EFI_SUCCESS;
}



/**

  Adjust some functions for boot-only code to work at runtime

**/
EFI_STATUS
EFIAPI
CompatibilityRsrc(
    IN  VOID
    )
{
  EFI_STATUS Status;

  // "NOP" ConOut (SimpleTextOutputProtocol)
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut = gST->ConOut;
  for(int i=0; i<9; i++) {
    *(UINTN*)( (UINTN)ConOut+i*8 ) = (UINTN)Ret;
  }

  return EFI_SUCCESS;
}
