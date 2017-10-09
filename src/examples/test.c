#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{	
	//write (1, (char *) 0x10123420, 123);
	printf("hello\n");
	exit(2);
	return EXIT_SUCCESS;
}