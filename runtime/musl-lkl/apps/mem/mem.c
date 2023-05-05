#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define IOCTL_CF_PRB		0x4004e203

int main(int argc, char **argv)
{
	char *buf;

	printf("malloc=%p\n", malloc);

	buf = (char*)malloc(10*sizeof(char));
	printf("buf = %p\n", buf);

	buf[0] = 'T';
	printf("Trying to write successfully!\n");

    return 0;
}

