/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/IoLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseMemoryLib.h>



/**
 * 
 * Erase VarPrintVar and VarStatusVar
 *
 **/
EFI_STATUS
EFIAPI
VarErase (
		VOID
		);


/**
 * 
 * Print debug messages to UEFI variable
 *
 **/
EFI_STATUS
EFIAPI
VarPrint (
		IN CONST CHAR8  *fmt,
		...
		);


/**
 * 
 * Print large binary data 
 *
 **/
EFI_STATUS
EFIAPI
VarPrintLargeBin (
		IN  VOID  *bin
		);


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
		);
