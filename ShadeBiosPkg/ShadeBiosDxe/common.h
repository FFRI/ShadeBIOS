/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

#define BYTE unsigned char

#define HANDLE_ERROR(status) \
  if(EFI_ERROR(status)) { \
    Print(L"error: %r at %a:%d\r\n", Status, __FILE__, __LINE__); \
    return status; \
  }

#define CR(Record, TYPE, Field) \
    ((TYPE *) ((CHAR8 *) (Record) - OFFSET_OF(TYPE, Field)))



/**

  Case-insensitive StrStr

**/
CHAR16*
StriStri(
    CHAR16* String,
    CHAR16* SearchString
    )
{
  CHAR16 buf1[256] = {0};
  CHAR16 buf2[256] = {0};

  int i;
  for(i=0; String[i]!='\0'; i++)
    buf1[i] = CharToUpper(String[i]);
  for(i=0; SearchString[i]!='\0'; i++)
    buf2[i] = CharToUpper(SearchString[i]);

  return StrStr(buf1, buf2);
}



/**

  "string...", "string" (same) then return FALSE

**/
BOOLEAN
AsciiStrCmpNonTerminated(
		IN  char*  Str1,  // Non Null-Terminated String
		IN  char*  Str2   // Null-Terminated String
		)
{
	for(UINTN i=0; i<AsciiStrLen(Str2); i++) {
		if(Str1[i]!=Str2[i])
			return TRUE;
	}
	return FALSE;
}



