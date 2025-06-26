/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */


/**

  [Omitted] Get EPROCESS of the specified process name

**/
PEPROCESS
NTAPI
GetProcessByName(
		IN  char*  ProcessName
		)
{
}



/**

  [Omitted] Scan specific PE section of a process and look for SearchText
    - Run this before ShadeBiosEnter()

**/
EFI_STATUS
EFIAPI
ScanProcessMemory(
		IN   char*   ProcessName,
		IN   char*   SectionName,
		IN   char*   SearchText,
		IN   UINTN   DataOffsetFromSearchText,
		OUT  char*   DataAddr,
		OUT  UINTN*  DataLen
		)
{
}



/**

  [Omitted] Get running process list
    - Run this after ShadeBiosEnter()

**/
char**
NTAPI
GetProcessList(
		)
{
}
