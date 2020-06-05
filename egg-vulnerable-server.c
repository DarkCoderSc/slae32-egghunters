/*
	Jean-Pierre LESUEUR (@DarkCoderSc)
	jplesueur@phrozen.io
	https://www.phrozen.io/
	https://github.com/darkcodersc

	License : MIT

	---

	SLAE32 Assignment 3 : Linux x86-32 Egg Hunter Research.

	---

	gcc egg-reallife.c -o egg-reallife -z execstack -no-pie -fno-stack-protector -pthread

	Warning: This C program is willingly vulnerable to buffer overflow which could led to remote code execution.
	         (!) Do not copy paste pieace of code without real caution (!)
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <ctype.h>

/****************************************************************************************************

	Server Thread Child Thread: Egg Host (cmd=1) for phase n°1.

	In our scenario this would be phase n°1.

	Imagine CacheMe() as a perfectly secured function to cache some data in memory. We have can cache
	up to 1KiB of data per thread. Far sufficient to host our real shellcode payload.

****************************************************************************************************/
void *CacheMe(void *param) {
	int client = (int)param; 

	char buffer[1024]; // Buffer that will contain our future egg + shellcod

	// Waiting for data from client.
	int result = recv(client, buffer, sizeof(buffer), 0);
	if (result <= 0) {
		printf("Could not receive data from client.\n");
	} else
		printf("Buffer successfully filled with %d bytes of data.\n", result);	

	///
	close(client);
}

/****************************************************************************************************

	Server Thread Child Thread: Buffer Overflow Location (cmd=2) for phase n°2.

	In our scenario this would be phase n°2.

	Image ExploitMe() as a function vulnerable to buffer overflow but with a small buffer. 
	However it is sufficient to place our egg hunter shellcode here to locate our second and real shellcode
	payload.

****************************************************************************************************/
void *ExploitMe(void *param) {
	char feedback[60];
	char buffer[200];
	///

	int client = (int)param; 

	int result = recv(client, buffer, sizeof(buffer), 0);

	printf("Received %d bytes for feedback.");

	strcpy(feedback, buffer); // who cares about security? :-P
}

/****************************************************************************************************

	Server Thread

	This server accept two commands:
		1. Cache some data in child thread stack (memory).
		2. Write data to an uncontrolled buffer (In our scenario, a fake rating system).

****************************************************************************************************/
void *Server() {
	printf("Server thread has started.\n");

	/*
		Create a new socket
	*/
	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == 0) {
		printf("Could not create socket");		
		
		pthread_exit(NULL);
	}

	printf("Socket created with handle:%d\n", s);

	/*
		Avoid error already in use.
	*/
	int optval = 1;
	int result = setsockopt(s, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &optval, sizeof(int));
	if (result == -1) {
		printf("Could not call setsockopt().");

		close(s);

		pthread_exit(NULL);
	}

	/*
		Bind socket to port.
	*/
	struct sockaddr_in saddr_in;

	saddr_in.sin_family      = AF_INET;
	saddr_in.sin_port        = htons(1403); // Listening on port 1403.
	saddr_in.sin_addr.s_addr = 16777343;    // Listenning on address 127.0.0.1.

	result = bind(s, (struct sockaddr*)&saddr_in, sizeof(struct sockaddr_in));
	if (result == -1) {
		printf("Could not bind socket.\n");

		close(s);

		pthread_exit(NULL);
	}
	printf("Socket successfully binded.\n");

	/*
		Start listening
	*/
	result = listen(s, 5);
	if (result == -1) {
		printf("Could not listen.\n");

		close(s);

		pthread_exit(NULL);
	}
	printf("Listening...\n");

	/*
		Wait for new clients to connect.
	*/	
	for (;;) {
		int client = accept(s, NULL, NULL);
		///

		if (client < 0)
			break;

		printf("New client connected our server with handle: %d\n", client);

		char cmd[1];		
		result = recv(client, cmd, sizeof(cmd), 0);
		if (result <= 0)
			continue;			

		if (!isdigit(*cmd)) {
			printf("Bad command format.\n");

			continue;
		}
		
		int icmd = atoi(cmd);

		printf("command=[%d]\n", icmd);

		pthread_t thread;	

		switch(icmd) {
			case 1: 
				pthread_create(&thread, NULL, CacheMe, (void *)client);

				break;
			case 2: 
				pthread_create(&thread, NULL, ExploitMe, (void *)client);

				break;

			default:
				close(client);
		}		
	}

	close(s);

	///
	pthread_exit(NULL);
}

/****************************************************************************************************

	Program Entry Point

****************************************************************************************************/
void main() {
	pthread_t thread;

	pthread_create(&thread, NULL, Server, NULL); // Create a new thread.

	pthread_join(thread, NULL); // Wait for thread to finish his task.	

	return;
}
