/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */



#include <Guid/FileInfo.h>

/**

  [Omitted] Disable the device settings that the OS applied during runtime
    * OS uses their own device drivers to re-initialize the device so settings differs from what BIOS initialized during boot
    * Device settings are actually the device register values
    * We can reset the settings by calling DriverBindingProtocol->Stop() of the UEFI drivers that manages the device you want to reset
    * DriverBindingProtocol->Stop() is called by gBS->DisconnectController()

**/
VOID
EFIAPI
DisableOSUsbSettings(
    IN  EFI_HANDLE  *UsbControllerHandles,
    IN  UINTN       UsbControllerHandlesCount
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
EnableBIOSUsbSettings(
    IN  EFI_HANDLE  *UsbControllerHandles,
    IN  UINTN       UsbControllerHandlesCount
    )
{
  //for(UINTN i=0; i<UsbControllerHandlesCount; i++) {  // TODO: 戻す
  for(int i=(int)UsbControllerHandlesCount-1; i>0; i--) {
    gBS->ConnectController(
       UsbControllerHandles[i],
       NULL,
       NULL,
       TRUE
       );
  }
}



/**

  Get ControllerHandle of USB host controller

**/
EFI_STATUS
EFIAPI
GetUsbControllerHandles(
    OUT  EFI_HANDLE  **UsbControllerHandles,
    OUT  UINTN       *UsbControllerHandlesCount
    )
{
  EFI_STATUS Status;

  EFI_GUID gEfiUsb2HcProtocolGuid = \
    { 0x3E745226, 0x9818, 0x45B6, { 0xA2, 0xAC, 0xD7, 0xCD, 0x0E, 0x8B, 0xA2, 0xBC } };
  *UsbControllerHandlesCount  = 0;
  Status = gBS->LocateHandleBuffer (
    ByProtocol,
    &gEfiUsb2HcProtocolGuid,
    NULL,
    UsbControllerHandlesCount,
    UsbControllerHandles
    );
  return Status;
}



/**

  [Omitted] Overwrite the OS device settings to the BIOS device settings
    * Device registers are configured by OS so those should be overwritten by BIOS to use from BIOS

**/
VOID
EFIAPI
HijackUsbFromOS(
    )
{
}



EFI_FILE_PROTOCOL *gFileProtocol;
/**

  Locate EFI_FILE_PROTOCOL of the USB device
    - CheckFileName: Some known file name on USB device (used for checking if its USB device or some other storage devices)

**/
EFI_STATUS
EFIAPI
UsbInit (
    IN  CHAR16  *CheckFileName
  )
{
  EFI_STATUS Status;

  EFI_HANDLE *SimpleFsHandles = NULL;
  UINTN SimpleFsHandlesCount = 0;

  // TODO debug ----
  EFI_HANDLE *UsbDeviceHandles = NULL;
  UINTN UsbDeviceHandlesCount = 0;
  __asm__ __volatile__("int3");
  gBS->LocateHandleBuffer(
      ByProtocol,
      &gEfiUsbIoProtocolGuid,
      NULL,
      &UsbDeviceHandlesCount,
      &UsbDeviceHandles
      );

  for(UINTN i=0; i<UsbDeviceHandlesCount; i++) {
    PVOID dummy = NULL;
    gBS->HandleProtocol(
        UsbDeviceHandles[i],
        &gEfiBlockIoProtocolGuid,
        (VOID**)&dummy
        );
    gBS->HandleProtocol(
        UsbDeviceHandles[i],
        &gEfiSimpleFileSystemProtocolGuid,
        (VOID**)&dummy
        );
  }
  // TODO debug ----
  
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
      // USB root fs found
      f->Close(f);
      f = NULL;
      return Status;
    }
  }

  return EFI_NOT_FOUND;
}



/**

  Write ascii str to USB file

**/
EFI_STATUS
EFIAPI
UsbWrite (
    IN  CHAR16 *FileName,
    IN  char   *WriteData,
    IN  UINTN  WriteDataSize
  )
{
  EFI_STATUS Status;

  EFI_FILE_PROTOCOL* f = NULL;
  __asm__ __volatile__("int3");
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
