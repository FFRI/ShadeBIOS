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
#include <Library/VarPrintLib.h>

#define BYTE unsigned char

EFI_FILE_PROTOCOL *gFileProtocol;

EFI_EVENT mSimpleFSProtocolInstalledEvent = NULL;



/**
 *
 * Load and execute dxemod image
 *
**/
EFI_STATUS
EFIAPI
ExecOrom(
    IN  EFI_HANDLE  ImageHandle,
    IN  BYTE*       FileContent,
    IN  UINTN       FileSize
    )
{
  EFI_STATUS Status;
  VarPrint("ExecOrom");

  EFI_HANDLE ImgHandle;
  Status = gBS->LoadImage (
      TRUE,
      ImageHandle,
      NULL,
      FileContent,
      FileSize,
      &ImgHandle
      );
  VarLogStatus(Status);

  Status = gBS->StartImage(
      ImgHandle,
      NULL,
      NULL
      );
  VarLogStatus(Status);

  return Status;
}


/**
 *
 * Read dxemod.efi
 *
**/
EFI_STATUS
EFIAPI
ModuleRead (
    IN   CHAR16  *FileName,
    OUT  BYTE   **RawFileContent,
    OUT  UINTN   *RawFileSize
  )
{
  EFI_STATUS Status;
  EFI_FILE_PROTOCOL *f;
  VarPrint("ModuleRead entry");

  // 1: Open FileProtocol
  Status = gFileProtocol->Open(
      gFileProtocol,
      &f,
      FileName,
      EFI_FILE_MODE_READ,
      0
      );
  VarLogStatus(Status);
  if(Status!=EFI_SUCCESS) {
    return Status;
  }
  
  // 2: Get File Size
  UINTN FileSize = 0;
  UINTN FileInfoSize = sizeof(EFI_FILE_INFO) + sizeof(CHAR16)*256;
  BYTE  TempBuf[FileInfoSize];
  Status = f->GetInfo(
      f,
      &gEfiFileInfoGuid,
      &FileInfoSize,
      TempBuf
      );
  VarLogStatus(Status);

  EFI_FILE_INFO *FileInfo = (EFI_FILE_INFO*)TempBuf;
  FileSize = FileInfo->FileSize;
  VarPrint("dxemod.efi size: 0x%X", FileSize);

  // 3: Read File Content
  Status = gBS->AllocatePool(
    EfiRuntimeServicesData,
    FileSize,
    (VOID**)RawFileContent
    );
  VarLogStatus(Status);

  Status = f->Read(
      f,
      &FileSize,
      *RawFileContent
      );
  VarLogStatus(Status);

  *RawFileSize = FileSize;

  VarPrint("Read done");

  f->Close(f);

  return Status;
}



/**
 *
 * Create `EFILOAD/` folder in USB root and place dxemod.efi, dxemod2.efi, ..., dxemod5.efi in there
 *
**/
VOID
EFIAPI
LoadModules(
		)
{
	EFI_STATUS Status;
  BYTE* FileContent = NULL;
  UINTN  FileSize = 0;
  Status = ModuleRead(L"EFILOAD\\dxemod.efi", &FileContent, &FileSize);
  if(Status==EFI_SUCCESS) {
    ExecOrom(gImageHandle, FileContent, FileSize);
  }
  gBS->FreePool(FileContent);
  FileContent = NULL;
  FileSize = 0;
  Status = ModuleRead(L"EFILOAD\\dxemod2.efi", &FileContent, &FileSize);
  if(Status==EFI_SUCCESS) {
    ExecOrom(gImageHandle, FileContent, FileSize);
  }
  gBS->FreePool(FileContent);
  FileContent = NULL;
  FileSize = 0;
  Status = ModuleRead(L"EFILOAD\\dxemod3.efi", &FileContent, &FileSize);
  if(Status==EFI_SUCCESS) {
    ExecOrom(gImageHandle, FileContent, FileSize);
  }
  gBS->FreePool(FileContent);
  FileContent = NULL;
  FileSize = 0;
  Status = ModuleRead(L"EFILOAD\\dxemod4.efi", &FileContent, &FileSize);
  if(Status==EFI_SUCCESS) {
    ExecOrom(gImageHandle, FileContent, FileSize);
  }
  gBS->FreePool(FileContent);
  FileContent = NULL;
  FileSize = 0;
  Status = ModuleRead(L"EFILOAD\\dxemod5.efi", &FileContent, &FileSize);
  if(Status==EFI_SUCCESS) {
    ExecOrom(gImageHandle, FileContent, FileSize);
  }
  gBS->FreePool(FileContent);
}



/**
 *
 * This will connect USB host controller
 *
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
	VarPrint("ConnectController done");
}



/**
 *
 * Get EFI_FILE_PROTOCOL of USB drive
 *   - Make sure USB drive contains EFILOAD/ folder
 *   - If USB driver found, return TRUE
 *
**/
BOOLEAN
EFIAPI
UsbInit (
    IN VOID
  )
{
  EFI_STATUS Status;
  EFI_HANDLE* handles = NULL;
  UINTN handleCount   = 0;

  Status = gBS->LocateHandleBuffer(
      ByProtocol,
      &gEfiSimpleFileSystemProtocolGuid,
      NULL,
      &handleCount,
      &handles
      );
  if(Status!=EFI_SUCCESS) {
    VarPrint("LocateHandleBuffer(SimpleFSProtocol) failed %r", Status);
    return 0;
  }

  VarLogStatus(Status);
  VarPrint("SimpleFileSystemProtocol %d handles found", handleCount);

  UINTN i;
  for(i=0; i<handleCount; i++) {
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* fs = NULL;

    Status = gBS->HandleProtocol(
        handles[i],
        &gEfiSimpleFileSystemProtocolGuid,
        (VOID**)&fs
        );

    Status = fs->OpenVolume(
        fs,
        &gFileProtocol
        );

    EFI_FILE_PROTOCOL* f = NULL;
    Status = gFileProtocol->Open(
        gFileProtocol,
        &f,
        L"EFILOAD",
        EFI_FILE_MODE_READ,
        0
        );

    if(Status == EFI_SUCCESS) {
      VarPrint("USB root fs found!!!");
      f->Close(f);
      return 1;
    }
    gFileProtocol->Close(gFileProtocol);
  }
  gBS->FreePool(handles);

  VarPrint("USB root fs NOT found");
  return 0;
}



/**
 * 
 * Init access to USB and load DXE modules
 *
 **/
EFI_STATUS
EFIAPI
DriverEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS Status = EFI_SUCCESS;

  VarErase();
  VarPrint("ModuleLoader Entry");
  VarLogStatus(0x01);

  gImageHandle = ImageHandle;

  if(!UsbInit()) {
    VarPrint("Usb not found => try connecting usb (all) controller");
		ConnectAllControllers();

		if(!UsbInit()) {
			VarPrint("Module Loader Failed");
      return Status;
		}
  }

	LoadModules();
  return Status;
}
