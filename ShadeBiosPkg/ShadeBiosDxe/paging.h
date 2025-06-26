/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

typedef union {
  struct {
    UINTN Offset    : 12;
    UINTN PTindex   : 9;
    UINTN PDindex   : 9;
    UINTN PDPindex  : 9;
    UINTN PML4index : 9;
    UINTN Reserved  : 16;
  };
  UINT64 value;
} VIRTUAL_ADDR_4KB;

typedef union {
  struct {
    UINTN Offset    : 21;
    UINTN PDindex   : 9;
    UINTN PDPindex  : 9;
    UINTN PML4index : 9;
    UINTN Reserved  : 16;
  };
  UINT64 value;
} VIRTUAL_ADDR_2MB;

typedef union {
  struct {
    UINTN Offset    : 30;
    UINTN PDPindex  : 9;
    UINTN PML4index : 9;
    UINTN Reserved  : 16;
  };
  UINT64 value;
} VIRTUAL_ADDR_1GB;


typedef union {
  struct {
    UINT64    Present                  : 1;  // 0 = Not present in memory, 1 = Present in memory
    UINT64    ReadWrite                : 1;  // 0 = Read-Only, 1= Read/Write
    UINT64    UserSupervisor           : 1;  // 0 = Supervisor, 1=User
    UINT64    WriteThrough             : 1;  // 0 = Write-Back caching, 1=Write-Through caching
    UINT64    CacheDisabled            : 1;  // 0 = Cached, 1=Non-Cached
    UINT64    Accessed                 : 1;  // 0 = Not accessed, 1 = Accessed (set by CPU)
    UINT64    Ignored                  : 1;  // Ignored
    UINT64    PageSize                 : 1;  // IA32SDM p2922
    UINT64    Ignored2                 : 4;  // Ignored
    UINT64    PageTableBaseAddress     : 40; // Base Address
    UINT64    Ignored3                 : 11; // Ignored
    UINT64    Nx                       : 1;  // No Execute bit
  };
  UINT64    value;
} IA32_PAGE_NON_LEAF_ENTRY;
typedef IA32_PAGE_NON_LEAF_ENTRY IA32_PML4E;
typedef IA32_PAGE_NON_LEAF_ENTRY IA32_PDPE;
typedef IA32_PAGE_NON_LEAF_ENTRY IA32_PDE;

typedef union {
  struct {
    UINT64    Present                  : 1;  // 0 = Not present in memory, 1 = Present in memory
    UINT64    ReadWrite                : 1;  // 0 = Read-Only, 1= Read/Write
    UINT64    UserSupervisor           : 1;  // 0 = Supervisor, 1=User
    UINT64    WriteThrough             : 1;  // 0 = Write-Back caching, 1=Write-Through caching
    UINT64    CacheDisabled            : 1;  // 0 = Cached, 1=Non-Cached
    UINT64    Accessed                 : 1;  // 0 = Not accessed, 1 = Accessed (set by CPU)
    UINT64    Dirty                    : 1;  // 0 = Not dirty, 1 = Dirty (set by CPU)
    UINT64    Pat                      : 1;  // PAT
    UINT64    Global                   : 1;  // 0 = Not global, 1 = Global (if CR4.PGE = 1)
    UINT64    Ignored                  : 3;  // Ignored
    UINT64    PageTableBaseAddress     : 40; // Base Address
    UINT64    Ignored2                 : 7;  // Ignored
    UINT64    ProtectionKey            : 4;  // Protection key
    UINT64    Nx                       : 1;  // No Execute bit
  };
  UINT64    value;
} IA32_PTE;
