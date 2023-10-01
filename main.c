/*
encpe - RC4 encrypt part of PE executable after compilation and self-decrypt on program execution
        2023 Srdjan Rajcevic [github.com/rsrdjan]

        Recipe taken from "Secure programming cookbook for C and C++", 2005 John Viega and Matt Messier
        (ported for win32)
*/

#include <stdio.h>
#include <windows.h>
#include <sys/stat.h>

void printUsage(PSTR programName)
{
    printf("Usage: %s filename offset len key_offset key_len\n", programName);
    printf("\tfilename:\tpath to PE executable\n");
    printf("\toffset:\t\toffset in file to start encryption\n");
    printf("\tlen:\t\tnumber of bytes to encrypt\n");
    printf("\tkey_offset:\toffset of key in file\n");
    printf("\tkey_len\t\tnumber of bytes that holds the key\n");
}

int main(int argc, char *argv[])
{

    LPCSTR fileName;
    HANDLE hFile; 
    HANDLE hFileMapping;
    LPVOID lpFileBase;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS peHeader;
    ULONG entry, offset, len, key_offset, key_len; 

    if (argc < 6)
    {
        printf("Not enough parameters.\n");
        printUsage(argv[0]);
        exit(1);
    }

    // Handle args

    fileName = argv[1];
    offset = strtoul(argv[2], 0, 0);
    len = strtoul(argv[3], 0, 0);
    key_offset = strtoul(argv[4], 0, 0);
    key_len = strtoul(argv[5], 0, 0);

    hFile = CreateFileA(fileName,
    GENERIC_ALL, 
    0, 
    NULL, 
    OPEN_EXISTING, 
    FILE_ATTRIBUTE_NORMAL, 
    0
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Cannot open file.\n");
        exit(1);
    }

    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_EXECUTE_READWRITE, 0, 0, NULL);

    if (hFileMapping == 0)
    {
        printf("Cannot open mapping object.\n");
        CloseHandle(hFile);
        exit(1);
    }

    lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    if(lpFileBase == 0)
    {
        printf("Cannot map view of file.\n");
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        exit(1);
    }

    // Traversing PE headers for entry point 
    
    dosHeader = (PIMAGE_DOS_HEADER) lpFileBase; 

    if(dosHeader->e_magic==IMAGE_DOS_SIGNATURE)
    {
        peHeader = (PIMAGE_NT_HEADERS) ((u_char*)dosHeader+dosHeader->e_lfanew);
        if(peHeader->Signature==IMAGE_NT_SIGNATURE)
        {
            entry = peHeader->OptionalHeader.AddressOfEntryPoint;
        }
    }

    // Setting offsets from the entry point
    
    offset += entry;
    key_offset += entry;

    printf("Entry point: 0x%08X Block offset: 0x%08X Key offset: 0x%08X\n",
            entry, offset, key_offset);
    printf("Encrypting %d bytes at 0x%08X with %d bytes at 0x%08X...\n",
        len, offset, key_len, key_offset);
    
    encpeEncDec((ULONG)lpFileBase + offset, len, (ULONG)lpFileBase + key_offset, key_len);
    printf("Done.\n");
    
    FlushFileBuffers(hFile);
    UnmapViewOfFile(lpFileBase);
    CloseHandle(hFile);

    return 0;
}