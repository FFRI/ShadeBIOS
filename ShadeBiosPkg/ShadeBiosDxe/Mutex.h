/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

CHAR16 MutexVarName[0x10] = L"MutexVar";
UINTN MutexVarSize = 0x1;
// cbf69ff0-b5a3-4500-8b06-13ad0fa7854f
EFI_GUID MutexVarGuid = \
	{ 0xcbf69ff0, 0xb5a3, 0x4500, { 0x8b, 0x06, 0x13, 0xad, 0x0f, 0xa7, 0x85, 0x4f }};


/**

  Check if this driver is executed for the first time from power-on
   - return TRUE if this is the first time

**/
BOOLEAN
EFIAPI
CheckMutex (
    )
{
	BOOLEAN isFirstExecution = TRUE;
	EFI_STATUS Status = EFI_SUCCESS;
	BYTE mutex[1] = {0};
	Status = gRT->GetVariable(
			L"MutexVar",
			&MutexVarGuid,
			NULL,
			&MutexVarSize,
			(VOID*)&mutex
			);

	if(Status==EFI_NOT_FOUND) {
		mutex[0] = 0x1;
		gRT->SetVariable(
				L"MutexVar",
				&MutexVarGuid,
				EFI_VARIABLE_BOOTSERVICE_ACCESS,
				MutexVarSize,
				mutex
				);
	}
	else {
		isFirstExecution = FALSE;
		if(mutex[0] < 0xFF)
			mutex[0] += 1;
		gRT->SetVariable(
				L"MutexVar",
				&MutexVarGuid,
				EFI_VARIABLE_BOOTSERVICE_ACCESS,
				MutexVarSize,
				mutex
				);
	}

	return isFirstExecution;
}
