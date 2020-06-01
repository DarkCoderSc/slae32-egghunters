/*
	Jean-Pierre LESUEUR (@DarkCoderSc)
	jplesueur@phrozen.io
	https://www.phrozen.io/
	https://github.com/darkcodersc

	License: MIT

	---

	SLAE32 Level 3 : Linux x86-32 Egg Hunter Research.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <math.h>

unsigned int page_size = 0;
void *heap_map[3]; 
int heap_map_cursor = 0;

/*****************************************************************************************************

	Terminal Logging Icons

*****************************************************************************************************/
void info() {
	printf("[\033[34mi\033[39m] ");
}

void err() {
	printf("[\033[31mx\033[39m] ");
}

void success() {
	printf("[\033[32m+\033[39m] ");
}

void notice() {
	printf("[\033[33m!\033[39m] ");
}

/*****************************************************************************************************

	Important: after using scanf/fgets etc... it is important to flush stdin.
	In current Linux version I use, fflush(stdin) don't do the job.
	so I'm using bellow trick : https://stackoverflow.com/questions/16752759/fflush-doesnt-work

*****************************************************************************************************/
void clear_stdin() {	
	char c;
	while ((c = getchar()) != '\n' && c != EOF); 
}


/****************************************************************************************************

	Display menu.

****************************************************************************************************/
int displayMenu() {
	printf("\n------------------------------------\n");
	printf("What do you wan't to do?\n\n");

	printf("1) Place a new egg in memory.\n");
	printf("2) Search for an egg.\n");
	printf("3) ciao bella (quit). \n");
	printf("------------------------------------\n\n");

	int choice = 0;

	printf(">> ");
	scanf("%d", &choice);

	clear_stdin(); 

	printf("\n");

	return choice;
}

/****************************************************************************************************

	Place a new egg in memory.

	|EGG|EGG|CONTENT(OPCODE IN REAL LIFE)

****************************************************************************************************/
void hide_an_egg() {
	/*
		Allocate Memory (This is where our egg will be placed)
	*/	
	int mlen = 1024; // Allocate chunks of 1KiB of memory.

	info();
	printf("Allocating %d bytes on the Heap...\n", mlen);

	char *mem_str;

	mem_str = (char *) malloc(mlen);
	if (mem_str == NULL) {
		err();
		puts("Could not allocate memory!");

		return;
	}

	// Used to free allocated resource.
	heap_map[heap_map_cursor] = mem_str;
	heap_map_cursor++;

	success();
	printf("%d bytes allocated from 0x%x to 0x%x\n", mlen, (unsigned int) mem_str, (unsigned int)(mem_str+mlen));	

	info();
	printf("Choose your egg (4 bytes). Example: 3gg!\n\n");

	char egg[4 + 1]; // Include NULL terminated character

	int delta = (sizeof(egg) * 2) - 2; // Remove two NULL terminated character

	printf(">> ");
	fgets(egg, sizeof(egg), stdin);
	clear_stdin();
	printf("\n");

	strcat(mem_str, egg);
	strcat(mem_str, egg);

	/*
		Place our egg + fictive shellcode in that new region.
	*/	
	info();
	printf("Enter a maximum of %d bytes of data.\n\n", (mlen - delta));	

	printf(">> ");
	fgets((char *) (mem_str + delta), (mlen - delta), stdin);	
	printf("\n");	
}

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

	Search for an egg in memory and display it content (In real life opcode)

	Safely walk through memory page by page.

	// Scenario:
	if walk.address = str("EGG") then
		walk.next_address
		if walk.address = str("EGG") then
			walk.next_address			
			run(opcode(next_address)

****************************************************************************************************/
void egg_hunter() {
	char egg[4 + 1]; // Include NULL terminated character

	info();
	printf("Enter the egg to search on memory (4 bytes). Example: 3gg!\n\n");

	printf(">> ");
	fgets(egg, sizeof(egg), stdin);	
	clear_stdin();
	printf("\n");	

	/*
		Translate our egg in Little Endian hex encoded string.
		This is the pattern we will need to search in memory.
	*/
	char pattern[(sizeof(egg) * 2) -1];

	// This could be done in a cleaner way. Forgive me.
	snprintf(pattern, sizeof(pattern), "%x%x%x%x", 
						*(egg + 3),
						*(egg + 2),
						*(egg + 1),
						*egg
	);

	info();
	printf("Pattern to search in memory: 0x%s\n", pattern);

	/*
		Search for our egg then only print fictive shellcode part.
	*/
	info();
	printf("Scanning for our egg in memory...\n");

	unsigned int max_page = (pow(2, 32) / page_size); // 2^32 = Max memory size for 32bit systems.
	unsigned int page_cursor = 0;                     // Current memory page.
	unsigned int mem_cursor = 0;					  // Current memory cursor (relative to page_cursor).		
	_Bool found = 0;                                  // egg presence flag

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
			
				if (egg_hunt(ptr, pattern, 0 /* We already know memory address is valid */)) {								
					ptr++;
					///

					if (egg_hunt(ptr, pattern, 1 /* We want to test memory address */)) {
						ptr++;
						///						

						info();
						printf("We found the egg, content starting at address 0x%08x\n", (unsigned int) (ptr + 4));

						notice();
						printf("In real life, we would pass control to that address and it would execute valid OpCode.\n");
					
						success();
						printf("Dumping address content=[%s].\n", (char *) ptr);						

						found = 1;

						break;
					}
				}
			}

			if (found) 
				break;
		}
	}

	if (!found) {
		err();
		printf("Egg pattern \"%s\" not found in memory.\n", egg);
	}
}


/****************************************************************************************************

	Program Entry Point

****************************************************************************************************/
void main() {
	// Get current defined page size. On Linux it is generally 4kiB (4096).
	page_size = sysconf(_SC_PAGESIZE);

	for (;;) {		
		_Bool leave = 0;
		switch(displayMenu()) {
			case 1 :				
				if (heap_map_cursor >= (sizeof(heap_map) / sizeof(void*))) {
					err();
					puts("You can't place a new egg in memory. Reason: Limit Reached.");
				} else {
					hide_an_egg();
				}

				break;

			case 2 : 				
				egg_hunter();			

				break;

			case 3 :
				leave = 1;
				break;
		}

		if (leave)
			break;
	}

	/*
		Free allocated memory via malloc(...)
	*/
	for (int i = 0; i < heap_map_cursor; i++) 
		free(heap_map[i]);	

	return;
}