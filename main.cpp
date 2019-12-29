//	The goal of this project is to circumvent GetProcAddress and the storage of the raw function names by using a different method
//	It iterates through the names of the specified API and compares their hash with the hardcoded one. If it matches, it is the function we are looking for

#include "main.h"

CHAR* HashString(CHAR* string)
{
	UCHAR hashArr[HASH_LEN] = { 0 };
	CHAR* szHash = (CHAR*)malloc(HASH_LEN*2+1);

	HashData((LPBYTE)string, strlen(string), (LPBYTE)hashArr, HASH_LEN);
	for (INT i = 0, j = 0; i < HASH_LEN; j=++i*2)
	{
		sprintf_s(szHash + j, (HASH_LEN * 2 + 1)-j, "%02x", hashArr[i]);
	}

	return szHash;
}

VOID EnumerateFunctions(HMODULE hLib)
{
	if (NULL == hLib)
		return;

	PIMAGE_NT_HEADERS pImage_Nt_Headers = (PIMAGE_NT_HEADERS)((BYTE*)hLib + ((PIMAGE_DOS_HEADER)hLib)->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pImage_Export_Directory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hLib + pImage_Nt_Headers->
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	BYTE** ppNames = (BYTE**)((INT)hLib + pImage_Export_Directory->AddressOfNames);
	WORD* pwOrdinals = (WORD*)((INT)hLib + pImage_Export_Directory->AddressOfNameOrdinals);
	BYTE** ppFunctions = (BYTE**)((INT)hLib + pImage_Export_Directory->AddressOfFunctions);

	printf("NumberOfNames : %d\nNumberOfFunction : %d\n", pImage_Export_Directory->NumberOfNames, pImage_Export_Directory->NumberOfFunctions);

	for (UINT i = 0; i < pImage_Export_Directory->NumberOfNames; i++)
	{
		CHAR* szFuncName = (CHAR*)((BYTE*)hLib + (INT)ppNames[i]);
		WORD wOrd = pwOrdinals[i];
		VOID* pFunc = (PVOID)((BYTE*)hLib + (INT)ppFunctions[wOrd]);
		CHAR* szFuncHash = HashString(szFuncName);
		printf("%-50s (%-3x) : [%p] : {%s}\n", szFuncName, wOrd, pFunc, szFuncHash);
	}
}

PVOID NewGetProcAdy(HMODULE hLib, CHAR* szHash)
{
	PVOID ret = NULL;
	if ((NULL == hLib) || (NULL == szHash) || 64 != strlen(szHash))
		return ret;

	PIMAGE_NT_HEADERS pImage_Nt_Headers = (PIMAGE_NT_HEADERS)((BYTE*)hLib + ((PIMAGE_DOS_HEADER)hLib)->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pImage_Export_Directory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hLib + pImage_Nt_Headers->
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	BYTE** ppNames = (BYTE**)((INT)hLib + pImage_Export_Directory->AddressOfNames);			// Retrieves the function name table
	WORD* pwOrdinals = (WORD*)((INT)hLib + pImage_Export_Directory->AddressOfNameOrdinals);	// Retrieves the function ord table
	BYTE** ppFunctions = (BYTE**)((INT)hLib + pImage_Export_Directory->AddressOfFunctions);	// Retrieves the function address table
	
	/*
		The function address table is organised in a different than the two others.
		The function name table is organised in alphabetical order.
		The function ordinal table is organised according to the function name table so that pwOrdinals[i] corresponds to right function name ppNames[i].
		But,
			the function address table is arranged in ascending order according to the ordinals.
			So ppFunctions[i] may or may not be the address of the function that has the name "ppNames[i]".
			This is caused by the three function "BaseThreadInitThunk", "InterlockedPushListSList" and "Wow64Transition" that have respectively the ordinals 0, 1 and 2.

		Note that this might change depending on the version of Windows (I am currently on Windows 10 v.1903)
	*/

	printf("\rSearching matching string for %s\n", szHash);
	for (UINT i = 0; i < pImage_Export_Directory->NumberOfNames; i++)
	{
		CHAR* szFuncName = (CHAR*)((BYTE*)hLib + (INT)ppNames[i]);
		WORD wOrd = pwOrdinals[i];
		VOID* pFunc = (PVOID)((BYTE*)hLib + (INT)ppFunctions[wOrd]);
		CHAR* szFuncHash = HashString(szFuncName);
		printf("\r%s", szFuncHash);

		if (!strcmp(szHash, szFuncHash))
		{
			printf("\r%s matches with %s\n", szHash, szFuncName);
			ret = pFunc;
			break;
		}
	}

	if (NULL == ret)
		printf("\rCouldn't find any matching function name for %s\n", szHash);

	return ret;
}

INT main()
{
	HMODULE hLib = GetModuleHandle("kernel32.dll");
	if (NULL == hLib)
		return -1;

	PVOID pFunc = NewGetProcAdy(hLib, WINEXEC_HASH);
	if (NULL == pFunc)
		return -2;

	if (31 > ((PWinExec)pFunc)("calc.exe", SW_SHOW))
		return -3;

	return 0;
}