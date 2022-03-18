#include "header.h"

#pragma comment(linker, "/entry:EntryMain") 
int EntryMain()
{
	CreateShellcode();
	return 0;
}

void CreateShellcode()
{
	HMODULE hMsvcrt = LoadLibraryA("msvcrt.dll");
	typedef int (__CRTDECL* FN_printf)(char const* const _Format, ...);
	FN_printf fn_printf;
	fn_printf = (FN_printf)GetProcAddress(hMsvcrt, "printf");

	HANDLE hBin = CreateFileA("sh.bin", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (hBin == INVALID_HANDLE_VALUE)
	{
		fn_printf("create file error:%d\n", GetLastError());
		return;
	}
	
	DWORD dwSize = (DWORD)ShellcodeEnd - (DWORD)ShellcodeStart;
	DWORD dwWriten;
	WriteFile(hBin, ShellcodeStart, dwSize, &dwWriten, NULL);

	CloseHandle(hBin);
}