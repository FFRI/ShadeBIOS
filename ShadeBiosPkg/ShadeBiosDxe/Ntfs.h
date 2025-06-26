/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

#include <Guid/FileInfo.h>
#include <Protocol/LoadedImage.h>


//////////////////////////////////////////////////////////////////////////
///
/// Ntfs.h is work in progress.
/// Be careful not to mess with windows recovery partition otherwise
/// you have to reinstall windows.
///
//////////////////////////////////////////////////////////////////////////


/**

  Some BIOS contains NTFS Driver which is read-only so uninstall it

**/
EFI_STATUS
EFIAPI
UnloadExistingNtfsDriver (
  )
{
  EFI_STATUS Status;

  EFI_HANDLE *SimpleFSHandles = NULL;
  UINTN SimpleFSHandlesCount = 0;

  gBS->LocateHandleBuffer(
      ByProtocol,
      &gEfiSimpleFileSystemProtocolGuid,
      NULL,
      &SimpleFSHandlesCount,
      &SimpleFSHandles
      );

  for(UINTN i=0; i<SimpleFSHandlesCount; i++) {
    EFI_DEVICE_PATH_PROTOCOL *dp;
    gBS->HandleProtocol(
        SimpleFSHandles[i],
        &gEfiDevicePathProtocolGuid,
        (VOID**)&dp
        );
    CHAR16 *dpt = ConvertDevicePathToText(
        dp,
        FALSE,
        FALSE
        );
    Print(L"%s\n", dpt);
  }


  EFI_HANDLE *LoadedImageHandles = NULL;
  UINTN LoadedImageHandlesCount = 0;

  gBS->LocateHandleBuffer(
      ByProtocol,
      &gEfiLoadedImageProtocolGuid,
      NULL,
      &LoadedImageHandlesCount,
      &LoadedImageHandles
      );

  for(UINTN i=0; i<LoadedImageHandlesCount; i++) {
    EFI_DEVICE_PATH_PROTOCOL *dp;
    gBS->HandleProtocol(
        LoadedImageHandles[i],
        &gEfiDevicePathProtocolGuid,
        (VOID**)&dp
        );
    CHAR16 *dpt = ConvertDevicePathToText(
        dp,
        FALSE,
        FALSE
        );

    if(StrStr(dpt, L"768BEDFD-7B4B-4C9F-B2FF-6377E3387243")) { // AMI NTFS Driver Guid
      Print(L"AMI NTFS Driver found (%x) %s\n", LoadedImageHandles[i], dpt);
      EFI_LOADED_IMAGE_PROTOCOL *l;
      Status = gBS->HandleProtocol(
          LoadedImageHandles[i],
          &gEfiLoadedImageProtocolGuid,
          (VOID**)&l
          );
      if(Status != EFI_SUCCESS) {
        Print(L"HandleProtocol failed %r\n", Status);
        return Status;
      }
      Status = l->Unload(
          LoadedImageHandles[i]
          );
      if(Status != EFI_SUCCESS) {
        Print(L"LoadedImage->Unload failed %r\n", Status);
        return Status;
      }
      return EFI_SUCCESS;
    }
  }
  Print(L"AMI NTFS Driver NOT found\n");
  return EFI_NOT_FOUND;
}



/**

  [Omitted] Disable the device settings that the OS applied during runtime
    * OS uses their own device drivers to re-initialize the device so settings differs from what BIOS initialized during boot
    * Device settings are actually the device register values
    * We can reset the settings by calling DriverBindingProtocol->Stop() of the UEFI drivers that manages the device you want to reset
    * DriverBindingProtocol->Stop() is called by gBS->DisconnectController()

**/
VOID
EFIAPI
DisableOSNtfsSettings(
    IN  EFI_HANDLE  *NtfsControllerHandles,
    IN  UINTN       NtfsControllerHandlesCount
    )
{
}



/**

  Apply the device settings of BIOS to the device
    * BIOS initialize the device registers by DriverBindingProtocol->Start() of the UEFI drivers that manages that device
    * DriverBindingProtcol->Start() is called by gBS->ConnectController()

**/
VOID
EFIAPI
EnableBIOSNtfsSettings(
    IN  EFI_HANDLE  *NtfsControllerHandles,
    IN  UINTN       NtfsControllerHandlesCount
    )
{
  for(UINTN i=0; i<NtfsControllerHandlesCount; i++) {
    gBS->ConnectController(
       NtfsControllerHandles[i],
       NULL,
       NULL,
       TRUE
       );
  }
}



/**

  Get ControllerHandle of MMC host controller

**/
EFI_STATUS
EFIAPI
GetNtfsControllerHandles(
    OUT  EFI_HANDLE  **NtfsControllerHandles
    )
{
  EFI_STATUS Status;

  // 1EBE5AB9-2129-49E7-84D7-EEB9FCE5DEDD
  EFI_GUID EmmcCardInfoProtocolGuid = \
    { 0x1EBE5AB9, 0x2129, 0x49E7, { 0x84, 0xD7, 0xEE, 0xB9, 0xFC, 0xE5, 0xDE, 0xDD }};
  UINTN ControllerHandlesCount  = 0;
  Status = gBS->LocateHandleBuffer (
    ByProtocol,
    &EmmcCardInfoProtocolGuid,
    NULL,
    &ControllerHandlesCount,
    NtfsControllerHandles
    );
  return Status;
}



/**

  [Omitted] Overwrite the OS device settings to the BIOS device settings
    * Device registers are configured by OS so those should be overwritten by BIOS to use from BIOS

**/
VOID
EFIAPI
HijackNtfsFromOS(
    )
{
}



EFI_FILE_PROTOCOL *gFileProtocol;
/**

  Locate EFI_FILE_PROTOCOL
    - CheckFileName: Some known file name on NTFS (used for checking if its the right storage)

**/
EFI_STATUS
EFIAPI
NtfsInit (
    IN  CHAR16  *CheckFileName
  )
{
  EFI_STATUS Status;

  EFI_HANDLE *SimpleFsHandles = NULL;
  UINTN SimpleFsHandlesCount = 0;
  gBS->LocateHandleBuffer(
      ByProtocol,
      &gEfiSimpleFileSystemProtocolGuid,
      NULL,
      &SimpleFsHandlesCount,
      &SimpleFsHandles
      );

  for(UINTN i=0; i<SimpleFsHandlesCount; i++) {
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = NULL;

    gBS->HandleProtocol(
        SimpleFsHandles[i],
        &gEfiSimpleFileSystemProtocolGuid,
        (VOID**)&fs
        );

    fs->OpenVolume(
        fs,
        &gFileProtocol
        );

    EFI_FILE_PROTOCOL* f = NULL;
    Status = gFileProtocol->Open(
        gFileProtocol,
        &f,
        CheckFileName,
        EFI_FILE_MODE_READ,
        0
        );
    if(Status == EFI_SUCCESS) {
      // root fs ( C:\ ) found
      f->Close(f);
      f = NULL;
      return Status;
    }
  }

  return EFI_NOT_FOUND;
}



/**

  Write ascii str to NTFS file

**/
EFI_STATUS
EFIAPI
NtfsWrite (
    IN  CHAR16 *FileName,
    IN  char   *WriteData,
    IN  UINTN  WriteDataSize
  )
{
  EFI_STATUS Status;

  EFI_FILE_PROTOCOL* f = NULL;
  Status = gFileProtocol->Open(
    gFileProtocol,
    &f,
    FileName,
    EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
    0
    );
  if(Status != EFI_SUCCESS) {
    return Status;
  }

  Status = f->Write(
      f,
      &WriteDataSize,
      WriteData
      );
  if(Status != EFI_SUCCESS) {
    return Status;
  }

  f->Close(f);
  f = NULL;

  return EFI_SUCCESS;
}
