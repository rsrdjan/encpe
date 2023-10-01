/*
encpe - RC4 encrypt part of PE executable after compilation and self-decrypt on program execution
        2023 Srdjan Rajcevic [github.com/rsrdjan]

        Recipe taken from "Secure programming cookbook for C and C++", 2005 John Viega and Matt Messier
        (ported for win32)
*/
#pragma comment(lib, "bcrypt")
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#include <stdio.h>
#include <ntstatus.h>
#include <bcrypt.h>

int encpeEncDec(LPVOID buf, ULONG buf_len, LPVOID key, ULONG key_len)
{
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    ULONG numBytes = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD cbBlockLength, cbData, cbKeyObject, cbCypher;
    PBYTE pbKeyObject = NULL;
    LPVOID pbCypherText = NULL;

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, 
        BCRYPT_RC4_ALGORITHM, 
        NULL, 
        0)))
    {
        printf("Open alg provider failed.\n");
        exit(-1);
    }

    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, 
        BCRYPT_OBJECT_LENGTH, 
        (PBYTE)&cbKeyObject, 
        sizeof(DWORD), 
        &cbData, 
        0)))
    {
        printf("Calculate key object failed.\n");
        exit(-1);
    }

    pbKeyObject = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbKeyObject);
    if (pbKeyObject == NULL)
    {
        printf("Memory alloc for key object failed.\n");
        exit(-1);
    }

    if(!NT_SUCCESS(status = BCryptGenerateSymmetricKey(hAlg, 
        &hKey, 
        pbKeyObject, 
        cbKeyObject, 
        key, 
        sizeof(key), 
        0)))
    {
        printf("Key generator failed.\n");
        exit(-1);
    }

    if(!NT_SUCCESS(status = BCryptEncrypt(hKey, 
        buf, 
        strlen(buf), 
        NULL, 
        NULL, 
        0, 
        buf, 
        strlen(buf), 
        &numBytes, 
        0)))
    {
        printf("Encryption failed.\n");
        exit(-1);
    }
 
    if (hKey)
        BCryptDestroyKey(hKey);
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    
    return buf_len;

}
