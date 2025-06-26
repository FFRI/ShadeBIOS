/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

#define NTAPI __attribute__((__ms_abi__))
#define PAGELK         0x4B4C45474150
#define MSR_IA32_LSTAR 0xC0000082
#define NTSTATUS       long
#define HANDLE         void*

typedef UINT64 ULONG_PTR, *PULONG_PTR;
typedef ULONG_PTR SIZE_T, *PSIZE_T;

typedef
PVOID
(NTAPI *MMGETVIRTUALFORPHYSICAL)(
    UINT64 PhysicalAddress
    );
MMGETVIRTUALFORPHYSICAL MmGetVirtualForPhysical;



/**

  Get base address of ntoskrnl.exe

**/
QWORD
GetKernelBase(
    )
{
  QWORD KiSystemCall64Addr = AsmReadMsr64(MSR_IA32_LSTAR) & 0xFFFFFFFFFFFFF000;
  QWORD NtoskrnlBaseAddr   = KiSystemCall64Addr;

  while(1) {
    if(*(WORD*)NtoskrnlBaseAddr == MAGIC_MZ) {
      QWORD addr = NtoskrnlBaseAddr;
      for(; addr<NtoskrnlBaseAddr+0x400; addr+=8) {
        if(*(QWORD*)addr == PAGELK)
          return NtoskrnlBaseAddr;
      }
    }
    NtoskrnlBaseAddr -= 0x1000;
  }
  return 0;
}



//
// For Accessing Process 
//
typedef struct _EX_FAST_REF {
   UINT64 Value;
} EX_FAST_REF;

typedef struct _PEB_LDR_DATA {
  char tmp[0x20];                     // offset size
  LIST_ENTRY InMemoryOrderModuleList; // 0x20   0x10
} __attribute__((__packed__)) PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
  char tmp[0x3];                    // offset size
  struct {
    UINT8 tmp                : 1;
    UINT8 IsProtectedProcess : 1;
    UINT8 tmp2               : 6;
  } BitField;                       // 0x3    0x1
  char tmp2[0xc];                   // 0x4    0xc
  UINT64 ImageBaseAddress;          // 0x10   0x8
  PPEB_LDR_DATA Ldr;                // 0x18   0x8
  char tmp3[0x388];                 // 0x20   0x388
} __attribute__((__packed__)) PEB, *PPEB;

// Win10
/*
 *typedef struct _EPROCESS {
 *   char         tmp[0x28];           // offset size
 *   UINT64       DirectoryTableBase;  // 0x28   0x8
 *   char         tmp1[0x410];         // 0x30   0x410
 *   ULONG*       UniqueProcessId;     // 0x440  0x8
 *   LIST_ENTRY   ActiveProcessLinks;  // 0x448  0x10
 *   char         tmp2[0x60];          // 0x458  0x60
 *   EX_FAST_REF  Token;               // 0x4b8  0x8
 *   char         tmp3[0x90];          // 0x4c0  0x90
 *   PEB*         peb;                 // 0x550  0x8
 *   char         tmp4[0x50];          // 0x558  0x50
 *   char         ImageFileName[15];   // 0x5a8  0x15
 *   char         tmp5[0x473];         // 0x5bd  0x473
 *} __attribute__((__packed__)) EPROCESS, *PEPROCESS;
 */

// Win11
typedef struct _EPROCESS {
   char         tmp[0x28];           // offset size
   UINT64       DirectoryTableBase;  // 0x28   0x8
   char         tmp1[0x1A8];         // 0x30   0x1A8
   LIST_ENTRY   ActiveProcessLinks;  // 0x1D8  0x10
   char         tmp2[0xF8];          // 0x1E8  0xF8
   PEB*         peb;                 // 0x2E0  0x8
   char         tmp3[0x50];          // 0x2E8  0x50
   char         ImageFileName[15];   // 0x338  0x15
   char         tmp4[0x4CB];         // 0x34D  0x4CB
} __attribute__((__packed__)) EPROCESS, *PEPROCESS;

PEPROCESS PsInitialSystemProcess;

typedef
PEPROCESS
(NTAPI *PSGETCURRENTPROCESS)(
        );
PSGETCURRENTPROCESS PsGetCurrentProcess;



/**

  Get necessary ntoskrnl.exe exports

**/
VOID
ResolveNtosExport(
    )
{
  MmGetVirtualForPhysical = (MMGETVIRTUALFORPHYSICAL)GetExport(
      GetKernelBase(),
      "MmGetVirtualForPhysical"
      );

  //
  // For scanning process memory
  //
  PsInitialSystemProcess = *(EPROCESS**)GetExport(
      GetKernelBase(),
      "PsInitialSystemProcess"
      );

  PsGetCurrentProcess = (PSGETCURRENTPROCESS)GetExport(
      GetKernelBase(),
      "PsGetCurrentProcess"
      );
}



/**

  Switch CR3 to the target process dirbase
    - This allows access to that process memory

**/
UINTN gOrigCR3 = 0;
VOID
SetProcessContext(
    PEPROCESS targetProc,
    BOOLEAN bSetBack
    )
{
  PEPROCESS curProc = PsGetCurrentProcess();

  if(bSetBack) { // Set CR3 to original value
    curProc->DirectoryTableBase = gOrigCR3;
    __asm__ __volatile__("mov %%rax, %%cr3" : : "a"(gOrigCR3));
  }
  else { // Set DirBase CR3
    __asm__ __volatile__("mov %%cr3, %%rax" : "=a"(gOrigCR3));
    UINT64 ProcCr3 = targetProc->DirectoryTableBase;
    curProc->DirectoryTableBase = ProcCr3;
    __asm__ __volatile__("mov %%rax, %%cr3" : : "a"(ProcCr3));
  }
}
