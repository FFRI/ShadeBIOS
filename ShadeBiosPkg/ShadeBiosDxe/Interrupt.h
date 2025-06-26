/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

/**

  Disable external interrupt by setting max value to CR8 (Task Priority Register) 
    * cli/sti are useless because BIOS code will use cli/sti and once sti is called, interrupt is enabled

**/
UINT64 gOrigTpr = 0xFF;
static inline
VOID
DisableExternalInterrupt(
		)
{
	__asm__ __volatile__("mov %%cr8, %%rax" : "=a"(gOrigTpr));
	__asm__ __volatile__("mov %%rax, %%cr8" : : "a"((UINT64)15));
}


/**

  Enable external interrupt

**/
static inline
VOID
EnableExternalInterrupt(
		)
{
	__asm__ __volatile__("mov %%rax, %%cr8" : : "a"(gOrigTpr));
}



/**
 *
 * Suppress RaiseTPL/RestoreTPL to return immediately
 *   * RestoreTPL triggers the UEFI event
 *   * These two functions don't touch CR8 (Task Priority Register)
 *
 **/
BYTE bOrigRaiseTPL;
BYTE bOrigRestoreTPL;
VOID
EFIAPI
SuppressTPL(
    BOOLEAN bRestore
    )
{
  if(!bRestore) {
    bOrigRaiseTPL   = *(BYTE*)(gBS->RaiseTPL);
    bOrigRestoreTPL = *(BYTE*)(gBS->RestoreTPL);
    *(BYTE*)(gBS->RaiseTPL)   = 0xC3;
    *(BYTE*)(gBS->RestoreTPL) = 0xC3;
  }
  else {
    *(BYTE*)(gBS->RaiseTPL)   = bOrigRaiseTPL;
    *(BYTE*)(gBS->RestoreTPL) = bOrigRestoreTPL;
  }
}





//////////////////////////////////////////////////////////////////////////
///
/// Shade BIOS does NOT modify IDT in the current implementation.
/// Below functions are not used, but left out for experiment.
///
//////////////////////////////////////////////////////////////////////////

#include <Protocol/Cpu.h>

typedef struct {
  IA32_IDT_GATE_DESCRIPTOR    Ia32IdtEntry;
  UINT32                      Offset32To63;
  UINT32                      Reserved;
} X64_IDT_GATE_DESCRIPTOR;



BYTE gBiosTimerIdtEntry[0x10] = {0};
BYTE gOsIdtEntry[0x10]        = {0};
/**

  Swap OS and BIOS IDT

**/
EFI_STATUS
EFIAPI
SwapIDT (
    IN  BOOLEAN  bRestore
    )
{
  // Initialize gBiosMsiIdtEntry first during boot
  if(gBiosTimerIdtEntry==0)
    return EFI_NOT_FOUND;

  IA32_DESCRIPTOR Idtr;
  AsmReadIdtr(&Idtr);
  /*UINTN IdtSize = Idtr.Limit + 1;*/
  UINTN Idt50EntryAddr = Idtr.Base + (0x10*0x50);
  __asm__ __volatile__("invlpg %0" :: "m"(Idt50EntryAddr));

  if(!bRestore) {
    CopyMem(gOsIdtEntry, (VOID*)Idt50EntryAddr, 0x10);
    PhysicalWrite(Idt50EntryAddr, (VOID*)gBiosTimerIdtEntry, 0x10);
  }
  else {
    PhysicalWrite(Idt50EntryAddr, gOsIdtEntry, 0x10);
  }

  return EFI_SUCCESS;
}


VOID
EFIAPI
SaveBiosIdt(
		)
{
  IA32_DESCRIPTOR Idtr;
  AsmReadIdtr(&Idtr);
  /*UINTN IdtSize = Idtr.Limit + 1;*/
  UINTN Idt50EntryAddr = Idtr.Base + (0x10*0x50);
  __asm__ __volatile__("invlpg %0" :: "m"(Idt50EntryAddr));

  CopyMem(gBiosTimerIdtEntry, (VOID*)Idt50EntryAddr, 0x10);
}



VOID
EFIAPI
CheckBiosIdt(
		)
{
	EFI_STATUS Status;

	EFI_CPU_ARCH_PROTOCOL *CpuArchProtocol = NULL;
	gBS->LocateProtocol(
			&gEfiCpuArchProtocolGuid,
			NULL,
			(VOID**)&CpuArchProtocol
			);
	for(UINTN i=0; i<256; i++) {
		Status = CpuArchProtocol->RegisterInterruptHandler(
				CpuArchProtocol,
				i,
				(VOID*)DebugInterruptHandler
				);
		if(Status!=EFI_SUCCESS) {
			Print(L"IDT[0x%x] already in use\n", i);
		}
	}
}



VOID
EFIAPI
SaveTimerIntHandler (
		)
{
	EFI_STATUS Status;

	EFI_CPU_ARCH_PROTOCOL *CpuArchProtocol = NULL;
	gBS->LocateProtocol(
			&gEfiCpuArchProtocolGuid,
			NULL,
			(VOID**)&CpuArchProtocol
			);
	for(UINTN i=0; i<256; i++) {
		Status = CpuArchProtocol->RegisterInterruptHandler(
				CpuArchProtocol,
				i,
				(VOID*)DebugInterruptHandler
				);
		if(Status!=EFI_SUCCESS) {
			Print(L"IDT[0x%x] already in use\n", i);
		}
	}
}
