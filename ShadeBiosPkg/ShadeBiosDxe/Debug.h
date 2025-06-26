/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */


/**

  This would also enable display output in early phases
  so that you can Print()

**/
VOID
EFIAPI
ConnectAllControllers(
		)
{
	EFI_STATUS Status;
	EFI_HANDLE* handles = NULL;
	UINTN handleCount   = 0;
	Status = gBS->LocateHandleBuffer (
		AllHandles,
		NULL,
		NULL,
		&handleCount,
		&handles
		);

	for(UINTN i=0; i<handleCount; i++) {
	 Status = gBS->ConnectController(
			handles[i],
			NULL,
			NULL,
			TRUE
			);
	}
	gBS->FreePool(handles);
}



/**

  Interrupt Handler for debug

**/
VOID
EFIAPI
DebugInterruptHandler (
    IN  EFI_EXCEPTION_TYPE  InterruptType,
    IN  EFI_SYSTEM_CONTEXT  SystemContext
    )
{
  Print(L"========== (Exception 0x%x) ==========\n", InterruptType);
  EFI_SYSTEM_CONTEXT_X64* ctx = SystemContext.SystemContextX64;
  Print(L"rip: 0x%x\n", ctx->Rip);
  Print(L"rsp: 0x%x\n", ctx->Rsp);
  for(int i=0; i<0x80; i+=8) {
    UINT64 addr = ctx->Rsp+i;
    UINT64 data = *(UINT64*)addr;
    UINT64 data2 = *(UINT64*)(addr+8);
    i+=8;
    Print(L"  0x%x: 0x%x 0x%x\n", addr, data, data2);
  }
  Print(L"rcx: 0x%x, rdx: 0x%x, rax: 0x%x\n", ctx->Rcx, ctx->Rdx, ctx->Rax);
  Print(L"r8: 0x%x, r9: 0x%x, r10: 0x%x\n", ctx->R8, ctx->R9, ctx->R10);
  Print(L"rdi: 0x%x, rsi: 0x%x\n", ctx->Rdi, ctx->Rsi);
  Print(L"======================================\n");
  Print(L">> TxBuf: 0x%X\n", *(UINT64*)(ctx->Rsp+0xa8));

  while(1) {};

  // Tried to take input but was lazy...
  /*
   *EFI_INPUT_KEY key;
   *CHAR16 cmdline[30];
   *int offset=0;
   *BOOLEAN bDone = FALSE;
   *Print(L">>> ");
   *while(1) {
   *   if(!gSystemTable->ConIn->ReadKeyStroke(gSystemTable->ConIn, &key)) {
   *      if(bDone) {
   *         bDone = FALSE;
   *         if(offset>2) {
   *            UINT64 addr = StrHexToUint64(cmdline);
   *            Print(L"0x%x: 0x%x\n", addr, *(UINT64*)addr);
   *            Print(L">>> ");
   *            offset = 0;
   *            continue;
   *         }
   *         offset = 0;
   *         continue;
   *      }
   *      if(key.UnicodeChar == L'\r') {
   *         bDone = TRUE;
   *      }
   *      cmdline[offset++] = key.UnicodeChar;
   *   }
   *}
   */
}



/**

  Get Device Path of a given handle
    - Note: this will greatly increase the code size

**/
EFI_STATUS
EFIAPI
GetDevicePath(
    IN  EFI_HANDLE  handle
    )
{
  EFI_STATUS Status;

  EFI_DEVICE_PATH_PROTOCOL *dp = NULL;
  Status = gBS->HandleProtocol(
      handle,
      &gEfiDevicePathProtocolGuid,
      (VOID**)&dp
      );
  if(Status!=EFI_SUCCESS) {
    return Status;
  }

  CHAR16 *dpt = NULL;
  dpt = ConvertDevicePathToText(
      dp,
      FALSE,
      FALSE
      );
  __asm__ __volatile__("int3");
  Print(L"%p", dpt);
  return EFI_SUCCESS;
}
