#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{	
	//write (1, (char *) 0x10123420, 123);
	//printf("hello\n");
	//printf ("wait(exec()) = %d\n", wait (exec("test2")));
	//printf("%s %s %s %s\n", argv[0], argv[1], argv[2], argv[3]);
	// char input_buff[1024];
	// read(0, input_buff, 3);
	// printf("%s\n",input_buff);
	// printf("%d", *(int *)NULL);

	printf("%d\n",wait(exec("test2")));


	return EXIT_SUCCESS;
}