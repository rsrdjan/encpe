/*
encpe - RC4 encrypt part of PE executable after compilation and self-decrypt on program execution
        2023 Srdjan Rajcevic [github.com/rsrdjan]

        Recipe taken from "Secure programming cookbook for C and C++", 2005 John Viega and Matt Messier
        (ported for win32)
*/
#include <stdio.h>
#include "encpe.h"

ENCPE_START_BLOCK(test)
void test_routine(void)
{
    printf("Decrypted!\n");
}
ENCPE_END_BLOCK(test)

ENCPE_START_KEY(test)
void bogus_routine(void)
{
    int a = 4;
    int b = 2033;
    int res = a + b;
    int c = 53454;
    int g = 276;
    int av = c - g;
}
ENCPE_END_KEY(test)

int main()
{
    
    #ifdef U_BUILD
    printf("(offsets from _start) offset: 0x%X len: 0x%X key: 0x%X len: 0x%X\n",
            ENCPE_OFFSET(ENCPE_BLOCK_ADDR(test)), ENCPE_BLOCK_LEN(test),
            ENCPE_OFFSET(ENCPE_KEY_ADDR(test)), ENCPE_KEY_LEN(test)
    );
    exit(0);
    #endif
    
    encpeEncDec(ENCPE_BLOCK_ADDR(test), ENCPE_BLOCK_LEN(test), ENCPE_KEY_ADDR(test), ENCPE_KEY_LEN(test));
    test_routine();
    return 0;
}