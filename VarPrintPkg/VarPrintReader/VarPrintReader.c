/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/IoLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Guid/FileInfo.h>

#define BYTE unsigned char

CHAR16 VarPrintVarName[0x10] = L"VarPrintVar";
EFI_GUID VarPrintVarGuid = { 0xfaa21472, 0x6c7a, 0x4256, { 0x81, 0x67, 0xd8, 0xa0, 0x46, 0x60, 0x43, 0xf8 }}; // faa21472-6c7a-4256-8167-d8a0466043f8
UINTN VarPrintVarSize = 0x1000;
UINTN VarPrintVarLimit = 50;
UINT16 VarPrintVarOffset = 0;

CHAR16 VarLargeVarName[0x10] = L"VarLargeVar";
EFI_GUID VarLargeVarGuid = { 0xb5373006, 0x48da, 0x4c88, { 0x96, 0x22, 0xc3, 0xee, 0xe3, 0x42, 0x7e, 0x1b }}; // b5373006-48da-4c88-9622-c3eee3427e1b
UINTN VarLargeVarSize = 0x400;

CHAR16 VarStatusVarName[0x10] = L"VarStatusVar";
EFI_GUID VarStatusVarGuid = { 0xe905dcf9, 0x529b, 0x492c, { 0x89, 0xd5, 0x7a, 0xeb, 0x7d, 0xa9, 0xa1, 0x78 }}; // e905dcf9-529b-492c-89d5-7aeb7da9a178
UINTN VarStatusVarSize = 0x20;
UINT16 VarStatusVarOffset = 0;


/**
 * 
 * Print contents of VarPrint/VarLogStatus
 *
 **/
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
	EFI_STATUS Status;
	int i;
	char pbuf[0x1000] = {0};
	unsigned char sbuf[0x20];
	unsigned char lbuf[0x400] = {0};

	Print(L"VarPrintReader started\r\n");

	Status = gRT->GetVariable(
			VarPrintVarName,
			&VarPrintVarGuid,
			NULL,
			&VarPrintVarSize,
			(VOID*)&pbuf
			);
	if(Status!=EFI_SUCCESS) {
		Print(L"GetVariable failed (%r) (VarPrintVarSize: 0x%X)\r\n", Status, VarPrintVarSize);
	}
	else {
		Print(L"%s:\r\n", VarPrintVarName);
		for(i=0; i<VarPrintVarLimit; i++) {
			Print(L"[%d] %a\r\n", i, &pbuf[i*(VarPrintVarSize/VarPrintVarLimit)]);
		}
	}

	Status = gRT->GetVariable(
			VarStatusVarName,
			&VarStatusVarGuid,
			NULL,
			&VarStatusVarSize,
			(VOID*)&sbuf
			);
	if(Status!=EFI_SUCCESS) {
		Print(L"GetVariable failed (%r)\r\n", Status);
	}
	else {
		Print(L"%s:\r\n", VarStatusVarName);
		for(i=0; i<VarStatusVarSize; i++) {
			if(i!=0 && i%16==0) Print(L"\r\n");
			Print(L"%02X ", sbuf[i]);
		}
		Print(L"\r\n");
	}

  /*
	 *Status = gRT->GetVariable(
	 *    VarLargeVarName,
	 *    &VarLargeVarGuid,
	 *    NULL,
	 *    &VarLargeVarSize,
	 *    (VOID*)&lbuf
	 *    );
	 *if(Status!=EFI_SUCCESS) {
	 *  Print(L"GetVariable failed (%r)\r\n", Status);
	 *}
	 *else {
	 *  Print(L"%s:\r\n", VarLargeVarName);
	 *  for(i=0; i<VarLargeVarSize; i++) {
	 *    if(i!=0 && i%32==0) Print(L"\r\n");
	 *    Print(L"%02X ", lbuf[i]);
	 *  }
	 *  Print(L"\r\n");
	 *}
   */

	return EFI_SUCCESS;
}
