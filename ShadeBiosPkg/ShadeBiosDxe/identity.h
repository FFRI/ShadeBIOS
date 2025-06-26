/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

BOOLEAN gIsPartialIdentity = FALSE; // TRUE if partial identity map is enabled
UINT64 gIdentityCR3;




/**

  Prepare identity map page tables (call this during boot)

**/
VOID
MakeIdentityPageTable (
    )
{
  // PML4 size = 8 Bytes (PML4E size) * 512 PML4Es = 4096(1 page size)
  //  Use AllocatePages to 4KB align the address
  EFI_PHYSICAL_ADDRESS pml4;   // pml4[512]
  gBS->AllocatePages(
      AllocateAnyPages,
      EfiRuntimeServicesCode,
      1,
      &pml4
      );

  EFI_PHYSICAL_ADDRESS pdp;   // pdp[512]
  gBS->AllocatePages(
      AllocateAnyPages,
      EfiRuntimeServicesCode,
      2,
      &pdp
      );

  // 1 PD contains 512 2MB pages (= can describe 1GB of phyical address)
  // => we need 64 PD
  // * Looks like some BIOS uses virtual address(?) so prepare 512 PD
  EFI_PHYSICAL_ADDRESS pd;   // ~~pd[64][512]~~ => pd[512][512]
  gBS->AllocatePages(
      AllocateAnyPages,
      EfiRuntimeServicesCode,
      512,  // 64
      &pd
      );

  // link page tables
  *(UINT64*)pml4 = (UINT64)pdp | 0x003;
  //for(UINT64 i=0; i<64; i++) {
  for(UINT64 i=0; i<512; i++) {
    *(UINT64*)(pdp+i*8) = ((UINT64)pd + i*8*512) | 0x003;
    for(UINT64 j=0; j<512; j++)
      *(UINT64*)(pd + i*8*512 + j*8) = (i*(UINT64)SIZE_1GB + j*(UINT64)SIZE_2MB) | 0x083;
  }

  gIdentityCR3 = (UINT64)pml4;
}



UINTN gMask = 0;
/**

  bit[12:M-1] of CR3 is the PML4 base addr and M can retrived from CPUID.80000008:EAX[0:7]

**/
UINTN
GetCr3Mask(
    )
{
  if(gMask != 0) {
    return gMask;
  }

  UINTN MaxPhyAddr = 0;
  UINTN rax, rbx, rcx, rdx;
  rax = 0x80000008;
  __asm__ __volatile__("cpuid" : "=a"(rax), "=b"(rbx), "=c"(rcx), "=d"(rdx) : "a"(rax));
  MaxPhyAddr = rax & 0xFF;
  gMask = (((UINTN)1 << MaxPhyAddr) - 1) & ~((UINTN)0xFFF);
  return gMask;
}



UINTN gOrigPml40;
PVOID gPml4BaseVaddr;
/**

  Enable partial identity mapping
    * Access to the lower 64GB (0x00000000_00000000 - 0x0000000F_FFFFFFFF) address will point to the physical address
    - EFI_ALREADY_STARTED: EnableIdentityMapping is already called

**/
static inline
EFI_STATUS
EFIAPI
EnablePartialIdentityMapping (
    )
{
  if(gIsPartialIdentity) {
    return EFI_ALREADY_STARTED;
  }

  UINTN OrigCR3 = 0;
  __asm__ __volatile__("mov %%cr3, %%rax" : "=a"(OrigCR3));
  UINTN Pml4BasePaddr = OrigCR3 & GetCr3Mask();
  gPml4BaseVaddr = (PVOID)MmGetVirtualForPhysical(Pml4BasePaddr);
  gOrigPml40 = *(UINTN*)gPml4BaseVaddr;

  __asm__ __volatile__("wbinvd");
  // Switch to Identity Paging
  CopyMem(gPml4BaseVaddr, (PVOID)gIdentityCR3, 8);

  gIsPartialIdentity = TRUE;
  return EFI_SUCCESS;
}



/**

  Disable partial identity mapping
    * Access to the lower 64GB (0x00000000_00000000 - 0x0000000F_FFFFFFFF) address will point to the userland virtual address
    - EFI_ALREADY_STARTED: Partial identity mappoing is already disabled

**/
static inline
EFI_STATUS
EFIAPI
DisablePartialIdentityMapping (
    )
{
  if(!gIsPartialIdentity) {
    return EFI_ALREADY_STARTED;
  }

  __asm__ __volatile__("wbinvd");
  // Switch back paging
  CopyMem(gPml4BaseVaddr, &gOrigPml40, 8);

  gIsPartialIdentity = FALSE;
  return EFI_SUCCESS;
}



/**

  Write Data directly to the physical memory (to bypass page attributes)

**/
VOID
PhysicalWrite(
    UINT64 VirtualAddress,
    BYTE*  Data,
    UINTN  DataSize  // should be less than a page size
    )
{
  UINTN cr3 = 0;
  UINTN mask = GetCr3Mask();
  __asm__ __volatile__("mov %%cr3, %%rax" : "=a"(cr3));
  UINTN Pml4BasePaddr = cr3 & mask;

  // Switch to Identity Paging
  EnablePartialIdentityMapping();

  VIRTUAL_ADDR_4KB vaddr;
  vaddr.value = VirtualAddress;

  IA32_PML4E *pml4e;
  IA32_PDPE  *pdpe;
  IA32_PDE   *pde;
  IA32_PTE   *pte;

  UINTN phy_base;
  BYTE* phy_addr;

  __asm__ __volatile__("invlpg %0" :: "m"(Pml4BasePaddr));
  pml4e = (IA32_PML4E*)(Pml4BasePaddr + 8*vaddr.PML4index);

  UINTN pdp_base = pml4e->value & mask;
  __asm__ __volatile__("invlpg %0" :: "m"(pdp_base));
  pdpe = (IA32_PDPE*)(pdp_base + 8*vaddr.PDPindex);

  if(pdpe->PageSize) {  // 1GB page
    VIRTUAL_ADDR_1GB vaddr_1gb;
    vaddr_1gb.value = VirtualAddress;
    mask &= ~((UINTN)0x3FFFFFFF);
    phy_base = pdpe->value & mask;
    phy_addr = (BYTE*)(phy_base + vaddr_1gb.Offset);
    goto CopyData;
  }

  UINTN pd_base = pdpe->value & mask;
  __asm__ __volatile__("invlpg %0" :: "m"(pd_base));
  pde = (IA32_PDE*)(pd_base + 8*vaddr.PDindex);

  if(pde->PageSize) {  // 2MB page
    VIRTUAL_ADDR_2MB vaddr_2mb;
    vaddr_2mb.value = VirtualAddress;
    mask &= ~((UINTN)0x1FFFFF);
    phy_base = pde->value & mask;
    phy_addr = (BYTE*)(phy_base + vaddr_2mb.Offset);
    goto CopyData;
  }

  // 4KB page
  UINTN pt_base = pde->value & mask;
  __asm__ __volatile__("invlpg %0" :: "m"(pt_base));
  pte = (IA32_PTE*)(pt_base + 8*vaddr.PTindex);
  
  phy_base = pte->value & mask;
  __asm__ __volatile__("invlpg %0" :: "m"(phy_base));
  phy_addr = (BYTE*)(phy_base + vaddr.Offset);

CopyData:
  UINTN i;
  for(i=0; i<DataSize; i++)
    phy_addr[i] = Data[i];

  // Switch back paging
  DisablePartialIdentityMapping();
}
