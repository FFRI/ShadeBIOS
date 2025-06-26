/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */


/**

  Enter Shade BIOS operation 
    * Allows boot-only BIOS code to run by,

**/
EFI_STATUS
EFIAPI
DisguiseMemoryMap (
    IN OUT  EFI_MEMORY_DESCRIPTOR  *MemoryMap,
    IN      UINTN                  MemoryMapSize,
    IN      UINTN                  DescriptorSize
    )
{
  UINTN MapEntries = MemoryMapSize / DescriptorSize;

  for(UINTN i=0; i<MapEntries; i++) {
    EFI_MEMORY_DESCRIPTOR *desc = (EFI_MEMORY_DESCRIPTOR*)( (UINTN)MemoryMap + (i*(DescriptorSize)) );
    UINTN start = desc->PhysicalStart;
    UINTN end   = start + desc->NumberOfPages*EFI_PAGE_SIZE;

    // Retain all BS region
    //   - Non-runtime DXE drivers
    //   - Boot Services (gBS)
    //   - All other non-runtime data
    if (desc->Type == EfiBootServicesCode) {
      desc->Type = EfiRuntimeServicesCode;
    }
    if (desc->Type == EfiBootServicesData) {
      desc->Type = EfiRuntimeServicesData;
    }
  }

  return EFI_SUCCESS;
}
