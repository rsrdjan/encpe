/*
encpe - RC4 encrypt part of PE executable after compilation and self-decrypt on program execution
        2023 Srdjan Rajcevic [github.com/rsrdjan]

        Recipe taken from "Secure programming cookbook for C and C++", 2005 John Viega and Matt Messier
        (ported for win32)
*/
#include <windows.h>
#define ENCPE_START_BLOCK(label) void label(void) {}
#define ENCPE_END_BLOCK(label) void _##label(void) {}
#define ENCPE_BLOCK_LEN(label) (DWORD)_##label - (DWORD)label
#define ENCPE_BLOCK_ADDR(label) (LPVOID)label
#define ENCPE_START_KEY(label) void key_##label(void) {}
#define ENCPE_END_KEY(label) void _key_##label(void) {}
#define ENCPE_KEY_LEN(label) (DWORD)_key_##label - (DWORD)key_##label
#define ENCPE_KEY_ADDR(label) (LPVOID)key_##label
#define ENCPE_OFFSET(label) (ULONG)label - (ULONG)_start 
void _start(void){}
