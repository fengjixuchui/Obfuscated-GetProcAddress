#pragma once

#include <stdio.h>
#include <Shlwapi.h>
#include <winnt.h>

#define HASH_LEN 32	//Note : this isn't the length of the string returned by HashString
#define WINEXEC_HASH (PCHAR)"e01910faf6715546931ff0f259a8fdbb435135df24e4b8f1f339349d1dc28b86"

typedef UINT(WINAPI* PWinExec)(LPCSTR, UINT);

CHAR* HashString(CHAR*);
VOID EnumerateFunctions(HMODULE);
PVOID NewGetProcAdy(HMODULE, CHAR*);