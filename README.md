# encpe
Portable Executable (PE) binary encryptor

RC4 encryption of Portable Executable (PE) binaries .text section with self-decryption on execution. Uses ENCPE_ macros to mark the code block for encryption and code block as key.

# Usage:

`encpe.exe filename offset len key_offset key_len`

        filename:       path to PE executable

        offset:         offset in file to start encryption
        
        len:            number of bytes to encrypt
        
        key_offset:     offset of key in file
        
        key_len         number of bytes that holds the key

For testing purposes `test.c` file is provided.  
Compile it with `cl.exe test.c encpe.c /DU_BUILD` and then run to get run-time offsets.  
Use offsets for encryption with encpe.exe:  
`encpe.exe test.exe 0x10 0x20 0x30 0x40`

Recipe taken from *"Secure programming cookbook for C and C++"*, 2005 John Viega and Matt Messier and ported for Win32.
