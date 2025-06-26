/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

#define HEAP_START_LIST_MAX_INDEX 10
#define MEMORY_MAP_SIGNATURE 0x70616d6d  // 'mmap'
                            
typedef struct {
  UINTN              Signature;
  LIST_ENTRY         Link;
  BOOLEAN            FromPages;
  EFI_MEMORY_TYPE    Type;
  UINT64             Start;
  UINT64             End;
  UINT64             VirtualStart;
  UINT64             Attribute;
} MEMORY_MAP;

UINT64 gHeapStartList[HEAP_START_LIST_MAX_INDEX] = {0};
LIST_ENTRY *gMemoryMap = NULL;
UINTN gMemoryMapBSDataRegionStart = 0; // Start addr of EfiBootServicesData that include gMemoryMap 
UINTN gMemoryMapBSDataRegionEnd   = 0; // End addr of EfiBootServicesData that include gMemoryMap 

EFI_ALLOCATE_POOL gOrigAllocatePool;
EFI_ALLOCATE_PAGES gOrigAllocatePages;




/**

  Not all MEMORY_MAP that has 'mmap' signature in memory is part of valid memory map.
  Identify if the map is part of valid memory map by iterating link list and checks
    - Does not contain map with same Type  =>  possibly free list
    - Is not short list  =>  possibly this is garbage

**/
BOOLEAN
EFIAPI
IsValidMemoryMap (
    IN  MEMORY_MAP  *map
    )
{
  BOOLEAN isValid = TRUE;

  int countLoaderCode = 0;
  int countEntryNo = 0;

  MEMORY_MAP *mapCopy = map;

  // Flink
  while(map->Signature == MEMORY_MAP_SIGNATURE) {
    if(map->Type == EfiLoaderCode) {
     countLoaderCode++;
      if(countLoaderCode > 5) {
        isValid = FALSE;
        break;
      }
    }
    else {
      countLoaderCode = 0;
    }
    countEntryNo++;
    map = CR(map->Link.ForwardLink, MEMORY_MAP, Link);
  }

  countLoaderCode = 0;
  map = mapCopy;

  // Blink
  if(isValid==TRUE) {
    while(map->Signature == MEMORY_MAP_SIGNATURE) {
      if(map->Type == EfiLoaderCode) {
      countLoaderCode++;
        if(countLoaderCode > 5) {
          isValid = FALSE;
          break;
        }
      }
      else {
        countLoaderCode = 0;
      }
      countEntryNo++;
      map = CR(map->Link.BackLink, MEMORY_MAP, Link);
    }
  }

  if(countEntryNo < 20) {
    isValid = FALSE;
  }

  return isValid;
}



/**

  Check if the memory region (map) is runtime heap which is stolen by StealMemoryForHeap

**/
BOOLEAN
EFIAPI
IsHeap(
    IN  MEMORY_MAP *map
    )
{
  BOOLEAN inHeapStartList = FALSE;
  int i;
  for(i=0; i<HEAP_START_LIST_MAX_INDEX; i++) {
    if(gHeapStartList[i] == 0)
      break;
    if(map->Start == gHeapStartList[i]) {
      inHeapStartList = TRUE;
      break;
    }
  }
  return inHeapStartList;
}



/**

  Get gMemoryMap (Head) from one of its MEMORY_MAP entries

**/
VOID
EFIAPI
GetMemoryMapHead(
    IN  MEMORY_MAP *map
    )
{
  while(map->Signature == MEMORY_MAP_SIGNATURE) {
    map = CR(map->Link.ForwardLink, MEMORY_MAP, Link);
  }
  gMemoryMap = &map->Link;
}



/**

  Don't let BIOS heap allocator use OS memory region
    * BIOS heap allocator search for usable memory from gMemoryMap link list
     * GetMemoryMap returns the 'copy' of MemoryMap. gMemoryMap in DxeCore is the actual memory map
   * Before InitHeap, some of EfiConventionalMemory is stolen from OS to use as a heap for runtime
   * Unlink all the other EfiConventionalMemory from gMemoryMap so that, BIOS allocator won't use them

**/
EFI_STATUS
EFIAPI
InitHeap(
    )
{
  // 1: Find gMemoryMap from EfiBootServicesData region given from GetMemoryMapHook
  //   - Cannot do this in GetMemoryMapHook because MemoryMap frequently changes and we need the latest memory map
  MEMORY_MAP *map = (MEMORY_MAP*)gMemoryMapBSDataRegionStart;
  while(!IsValidMemoryMap(map)) {
    map++;
    if((UINTN)map < gMemoryMapBSDataRegionEnd)
      return EFI_NOT_FOUND;
    if(map->Signature != MEMORY_MAP_SIGNATURE) {
      while(*(UINT32*)map != MEMORY_MAP_SIGNATURE) {
        map = (MEMORY_MAP*)((UINTN)map + 0x8);
      }
    }
  }
  GetMemoryMapHead(map); // gMemoryMap is set

  // 2: Disconnect non-heap EfiConventionalMemory region which is for OS 
  //   - Then, the BIOS memory allocator would not allocate OS memory region for AllocatePages/Pool
  map = CR(gMemoryMap->ForwardLink, MEMORY_MAP, Link);
  for(; map->Signature == MEMORY_MAP_SIGNATURE; map = CR(map->Link.ForwardLink, MEMORY_MAP, Link)) {
    if(map->Type != EfiConventionalMemory) {
      continue;
    }
    if(!IsHeap(map)) {
      map->Type = EfiReservedMemoryType; // Non Heap EfiConventionalMemory is for OS
    }
  }

  return EFI_SUCCESS;
}



/**

  [Omitted] Steal some EfiConventionalMemory for BIOS to use as a heap in runtime
    - EFI_NOT_FOUND: No EfiConventionalMemory was stealed (adjust memory range to steal)

**/
EFI_STATUS
EFIAPI
StealMemoryForHeap (
    IN OUT  EFI_MEMORY_DESCRIPTOR  *MemoryMap,
    IN      UINTN                  MemoryMapSize,
    IN      UINTN                  DescriptorSize
    )
{
  int HeapStartListIndex = 0;
  UINTN MapEntries = MemoryMapSize / DescriptorSize;

    // Save memory region that includes memory map for InitHeap
    // => omitted

    // Steal some EfiConventionalMemory for runtime BIOS heap
    // => omitted
}



/**

  gBS->AllocatePool(EfiLoaderData/Code) => gBS->AllocatePool(EfiRuntimeServicesData/Code)
    * Because EfiLoaderData/Code is now used by OS

**/
EFI_STATUS
EFIAPI
AllocatePoolHook(
    IN EFI_MEMORY_TYPE            PoolType,
    IN UINTN                      Size,
    OUT VOID                      **Buffer
    )
{
  if(PoolType==EfiLoaderData)
    PoolType = EfiRuntimeServicesData;
  if(PoolType==EfiLoaderCode)
    PoolType = EfiRuntimeServicesCode;
  return gOrigAllocatePool(PoolType, Size, Buffer);
}



/**

  gBS->AllocatePages(EfiLoaderData/Code) => gBS->AllocatePages(EfiRuntimeServicesData/Code)
    * Because EfiLoaderData/Code is now used by OS

**/
EFI_STATUS
EFIAPI
AllocatePagesHook(
    IN EFI_ALLOCATE_TYPE                   Type,
    IN EFI_MEMORY_TYPE                     MemoryType,
    IN UINTN                               Pages,
    IN OUT EFI_PHYSICAL_ADDRESS            *Memory
    )
{
  if(MemoryType==EfiLoaderData)
    MemoryType = EfiRuntimeServicesData;
  if(MemoryType==EfiLoaderCode)
    MemoryType = EfiRuntimeServicesCode;
  return gOrigAllocatePages(Type, MemoryType, Pages, Memory);
}



BOOLEAN gRedirectDone = FALSE;
/**

  Redirect EfiLoaderData/Code allocation to EfiRuntimeServicesData/Code
    * Because, EfiLoaderData/Code is now used by OS

**/
VOID
RedirectLoaderTypeAllocation() {
  if(!gRedirectDone) {
    gOrigAllocatePool  = gBS->AllocatePool;
    gOrigAllocatePages = gBS->AllocatePages;
    gBS->AllocatePool  = AllocatePoolHook;
    gBS->AllocatePages = AllocatePagesHook;
    gRedirectDone = TRUE;
  }
}
