/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

#include "Library/VarPrintLib.h"

CHAR16 VarPrintVarName[0x10] = L"VarPrintVar";
EFI_GUID VarPrintVarGuid = { 0xfaa21472, 0x6c7a, 0x4256, { 0x81, 0x67, 0xd8, 0xa0, 0x46, 0x60, 0x43, 0xf8 }}; // faa21472-6c7a-4256-8167-d8a0466043f8
#define MAX_VARPRINTVAR_SIZE 0x1000
UINTN VarPrintVarSize = MAX_VARPRINTVAR_SIZE;
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
 * Erase VarPrintVar and VarStatusVar
 *
 **/
EFI_STATUS
EFIAPI
VarErase (
		VOID
		)
{
	EFI_STATUS Status;

	Status = gRT->SetVariable(
			VarPrintVarName,
			&VarPrintVarGuid,
			EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
			0,
			NULL
			);

	Status = gRT->SetVariable(
			VarPrintVarName,
			&VarPrintVarGuid,
			EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
			0,
			NULL
			);

	return Status;
}


/**
 * 
 * Write debug messages to VarPrintVar
 *   - Up to VarPrintVarLimit debug message is stored
 *     (Each message is VarPrintVarSize/VarPrintVarLimit length)
 *
 **/
EFI_STATUS
EFIAPI
VarPrint (
		IN CONST CHAR8  *fmt,
		...
		)
{
	EFI_STATUS Status;
	char buf[MAX_VARPRINTVAR_SIZE] = {0};
	char msg[81] = {0};   // MAX_VARPRINTVAR_SIZE/VarPrintVarLimit when changing!

	VA_LIST v1;
	VA_START(v1, fmt);
	AsciiVSPrint(msg, MAX_VARPRINTVAR_SIZE/VarPrintVarLimit, fmt, v1);
	VA_END(v1);

	Status = gRT->GetVariable(
			VarPrintVarName,
			&VarPrintVarGuid,
			NULL,
			&VarPrintVarSize,
			(VOID*)&buf
			);
	VarPrintVarSize = MAX_VARPRINTVAR_SIZE;

	if(VarPrintVarOffset>=VarPrintVarLimit) {
		VarPrintVarOffset=0;
	}
	CopyMem(&buf[(VarPrintVarSize/VarPrintVarLimit)*VarPrintVarOffset++], msg, VarPrintVarSize/VarPrintVarLimit);

	Status = gRT->SetVariable(
			VarPrintVarName,
			&VarPrintVarGuid,
			EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
			VarPrintVarSize,
			buf
			);
	return Status;
}


/**
 * 
 * Print large binary data 
 *
 **/
EFI_STATUS
EFIAPI
VarPrintLargeBin (
		IN  VOID  *bin
		)
{
	EFI_STATUS Status;

	Status = gRT->SetVariable(
			VarLargeVarName,
			&VarLargeVarGuid,
			EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
			VarLargeVarSize,
			bin
			);
	return Status;
}


/**
 * 
 * Log status to VarStatusVar
 *   - Up to VarStatusSize status is stored (0:old, VarStatusSize:new)
 *
 **/
EFI_STATUS
EFIAPI
VarLogStatus (
		IN unsigned char status
		)
{
	EFI_STATUS Status;
	unsigned char buf[0x20];
	int i;

	Status = gRT->GetVariable(
			VarStatusVarName,
			&VarStatusVarGuid,
			NULL,
			&VarStatusVarSize,
			(VOID*)&buf
			);
	VarStatusVarSize = 0x20;
	if(Status!=EFI_SUCCESS) {
		for(i=0; i<VarStatusVarSize; i++) {
			buf[i] = 0xFF;
		}
	}

	if(VarStatusVarOffset==0x20) {
		VarStatusVarOffset = 0;
	}
	buf[VarStatusVarOffset++] = status;

	Status = gRT->SetVariable(
			VarStatusVarName,
			&VarStatusVarGuid,
			EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
			VarStatusVarSize,
			buf
			);
	return Status;
}
