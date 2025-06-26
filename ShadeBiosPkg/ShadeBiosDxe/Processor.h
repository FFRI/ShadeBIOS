/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */


///////////////////////////////////////////////////////////////////////////////////
///
/// Shade BIOS does NOT use this functionality in the current implementation.
/// Below are left out for experiment.
///
///////////////////////////////////////////////////////////////////////////////////


#include <Protocol/MpService.h>

EFI_GUID gEfiMpServicesProtocolGuid = \
  { 0x3fdda605, 0xa76e, 0x4f46, {0xad, 0x29, 0x12, 0xf4, 0x53, 0x1b, 0x3d, 0x08}};


/**

  Switch to BSP (DisableAP requires to be executed on BSP)

**/
VOID
SwitchToBsp(
		)
{
	KAFFINITY AffinityMask;
	for (UINTN i=0; i<KeQueryActiveProcessors(); i++) {
	  AffinityMask = (UINTN)1<<i;
	  KeSetSystemAffinityThreadEx(AffinityMask);

	  UINT32 IA32_APIC_BASE = 0;
	  __asm__ __volatile__("rdmsr" : "=a"(IA32_APIC_BASE) : "c"(0x1B));
	  BOOLEAN isBSP = (IA32_APIC_BASE >> 8) & 0x01;
	  if(isBSP) {
		 break;
	  }
	}
}



EFI_MP_SERVICES_PROTOCOL *gMpServicesProtocol;
UINTN gNumberOfProcessors = 0;
/**

  Disable Application Processors (Multi to Single Core)

**/
VOID
DisableAp(
		)
{
	gBS->LocateProtocol(
		 &gEfiMpServicesProtocolGuid,
		 NULL,
		 (VOID**)&gMpServicesProtocol
		 );

	UINTN NumberOfEnabledProcessors = 0;
	gMpServicesProtocol->GetNumberOfProcessors(
		 gMpServicesProtocol,
		 &gNumberOfProcessors,
		 &NumberOfEnabledProcessors
		 );

	for(UINTN i=1; i<=NumberOfEnabledProcessors; i++) {
	  gMpServicesProtocol->EnableDisableAP (
			gMpServicesProtocol,
			i,
			FALSE,
			NULL
			);
	}
}



/**

  Enable Application Processors (Single to Multi Core)

**/
VOID
EnableAp(
		)
{
	for(UINTN i=1; i<=gNumberOfProcessors; i++) {
	  gMpServicesProtocol->EnableDisableAP(
			gMpServicesProtocol,
			i,
			TRUE,
			NULL
			);
	}
}
