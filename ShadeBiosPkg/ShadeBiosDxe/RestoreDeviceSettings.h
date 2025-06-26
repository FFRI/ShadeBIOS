/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

//////////////////////////////////////////////////////////////////////////
///
/// Shade BIOS use OS self repair to return the device settings and
/// does NOT use RestoreDeviceSettings.h in the current implementation.
/// Use this header to further experiment faster way to return the
/// device control to the OS.
///
//////////////////////////////////////////////////////////////////////////

UINT64 gOsDcbaap = 0;
VOID
SaveRestoreMmioRegisters(
    IN  BOOLEAN  bRestore
    )
{
  UINT64 PciConfigBase = 0xe00a8000;
  UINT64 MmioBase = (*(UINT32*)(PciConfigBase+0x10) & (UINT64)0xFFFFFFF0) | ((UINT64)(*(UINT32*)(PciConfigBase+0x14)) << 32);

  /*
   *UINT64 CapAddr = PciConfigBase + *(BYTE*)(PciConfigBase+0x34);
   *while(*(BYTE*)CapAddr != 0x5) { // Search for MSI Capability
   *   CapAddr = PciConfigBase + *(BYTE*)(CapAddr+0x1);
   *}
   *UINT16 MsgCtrl = *(UINT16*)(CapAddr+0x2);
   *UINT64 MsgAddr = *(UINT32*)(CapAddr+0x4) | ((UINT64)(*(UINT32*)(CapAddr+0x8)) << 32);
   *UINT32 MsgData = *(UINT32*)(CapAddr+0xC);
   */
  /*
   *UINT32 dboff = *(UINT32*)(MmioBase+0x14);
   *VOID* MmioCopy = NULL;
   *gBS->AllocatePool(
   *      EfiRuntimeServicesData,
   *      dboff,
   *      &MmioCopy
   *      );
   *CopyMem(MmioCopy, (VOID*)MmioBase, dboff);
   */
  BYTE   CapabilityLength = *(BYTE*)MmioBase;
  UINT64 OperationalBase  = MmioBase + CapabilityLength;

  /*
   *UINT32 dnctrl = *(UINT32*)(OperationalBase + 0x14);
   *UINT32 portpmsc  = *(UINT32*)(OperationalBase + 0x404 + (0x10 * (12-1)));
   */
  /*
   **(UINT32*)(OperationalBase + 0x14)                    = os_dnctrl;
   **(UINT32*)(OperationalBase + 0x404 + (0x10 * (12-1))) = os_portpmsc;
   */

  if(!bRestore) {
    // 1: Save DCBAAP
    gOsDcbaap = *(UINT32*)(OperationalBase+0x30) | ((UINT64)(*(UINT32*)(OperationalBase+0x34)) << 32);
  }
  else {
    // 1: Restore DCBAAP
    *(UINT32*)(OperationalBase + 0x30) = (gOsDcbaap&(UINT32)0xFFFFFFFF);
    *(UINT32*)(OperationalBase + 0x34) = (UINT32)(gOsDcbaap>>32);

    // 2: Stop xHC (Might make OS reinitialization faster?)
    UINT32 usbcmd = *(UINT32*)(OperationalBase);
    usbcmd &= (UINT32)0xFFFFFFFE; // Clear bit0 (R/S) to stop xHC
    *(UINT32*)(OperationalBase) = usbcmd;

    while(1) {
      UINT32 usbsts = *(UINT32*)(OperationalBase + 0x4);
      BOOLEAN HCHalted = (BOOLEAN)(usbsts & 1);
      if(HCHalted) break;
    }
  }

}



/**

  Restore device settings for OS

**/
/*
 *VOID
 *EFIAPI
 *RestoreDeviceSettings(
 *      )
 *{
 *
 *   //
 *   // Get FDO of USBXHCI.sys
 *   //
 *   EFI_GUID GUID_DEVINTERFACE_USB_HOST_CONTROLLER = \
 *      { 0x3ABF6F2D, 0x71C4, 0x462A, {0x8A, 0x92, 0x1E, 0x68, 0x61, 0xE6, 0xAF, 0x27} };
 *   CHAR16* SymbolicLinkList = NULL;
 *   IoGetDeviceInterfaces(
 *         &GUID_DEVINTERFACE_USB_HOST_CONTROLLER,
 *         NULL,
 *         0,
 *         &SymbolicLinkList
 *         );
 *
 *   UNICODE_STRING interfaceName;
 *   RtlInitUnicodeString(&interfaceName, SymbolicLinkList);
 *   
 *   PVOID fileobj;
 *   PVOID XhcDeviceObject;
 *   IoGetDeviceObjectPointer(
 *        &interfaceName,
 *        (0x000F0000L | 0x00100000L | 0x1FF),
 *        &fileobj,
 *        &XhcDeviceObject
 *        );
 *
 *   //
 *   // Get PDO(PCI) from FDO(XHC)
 *   //
 *   PDEVICE_OBJECT XhcPhysicalDeviceObject;
 *   XhcDeviceObject = IoGetDeviceAttachmentBaseRef(
 *         XhcDeviceObject
 *         );
 *
 *   //
 *   // Get DEVICE_RESET_INTERFACE_STANDARD from bus driver
 *   //
 *   KEVENT event;
 *   KeInitializeEvent(
 *         &event,
 *         0,
 *         FALSE
 *         );
 *
 *   PIRP Irp;
 *   IO_STATUS_BLOCK ioStatus;
 *   Irp = IoBuildDeviceIoControlRequest(
 *         IRP_MJ_PNP,
 *         XhcDeviceObject,
 *         NULL, 0,
 *         NULL, 0,
 *         TRUE,
 *         &event,
 *         &ioStatus
 *         );
 *
 *   PIO_STACK_LOCATION ioStack;
 *   ioStack = IoGetNextIrpStackLocation(Irp);
 *   ioStack->MinorFunction = IRP_MN_STOP_DEVICE;
 *   ioStack->Parameters.QueryInterface.InterfaceType = &GUID_DEVICE_RESET_INTERFACE_STANDARD;
 *   ioStack->Parameters.QueryInterface.Size = sizeof(DEVICE_RESET_INTERFACE_STANDARD);
 *   ioStack->Parameters.QueryInterface.Version = DEVICE_RESET_INTERFACE_VERSION;
 *   ioStack->Parameters.QueryInterface.Interface = (PINTERFACE)&resetInterface;
 *   ioStack->Parameters.QueryInterface.InterfaceSpecificData = NULL;
 *
 *   IoCallDriver(
 *         XhcDeviceObject,
 *         Irp
 *         );
 *
 *   KeWaitForSingleObject(
 *         &event,
 *         0,    // Executive
 *         0,    // KernelMode
 *         FALSE,
 *         NULL
 *         );
 *
 *
 *   //
 *   // Start xHC device
 *   //
 *   KEVENT event2;
 *   KeInitializeEvent(
 *         &event2,
 *         0,
 *         FALSE
 *         );
 *
 *   PIRP Irp2;
 *   IO_STATUS_BLOCK ioStatus2;
 *   Irp2 = IoBuildDeviceIoControlRequest(
 *         IRP_MJ_PNP,
 *         XhcDeviceObject,
 *         NULL, 0,
 *         NULL, 0,
 *         TRUE,
 *         &event2,
 *         &ioStatus2
 *         );
 *
 *   PIO_STACK_LOCATION ioStack2;
 *   ioStack2 = IoGetNextIrpStackLocation(Irp2);
 *   ioStack2->MinorFunction = IRP_MN_START_DEVICE;
 *
 *   IoCallDriver(
 *         XhcDeviceObject,
 *         Irp2
 *         );
 *
 *   KeWaitForSingleObject(
 *         &event2,
 *         0,    // Executive
 *         0,    // KernelMode
 *         FALSE,
 *         NULL
 *         );
 *}
 */



