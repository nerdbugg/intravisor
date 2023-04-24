#include <stdio.h>
#include "crt.h"
#include "hostcalls.h"

void print_a()
{
	for (int i = 0; i < 1500; i++) {
		host_write("a", 1);
	}

	host_save();

	for (int i = 0; i < 10; i++) {
		host_write("aA", 2);
	}

	while(1);
}

void print_b()
{
	for (int i = 0; i < 1500; i++) {
		host_write("b", 1);
		for(int i=0;i<10000;i++);
	}
	host_exit();
}

void print_c()
{
	for (int i = 0; i < 1500; i++) {
		host_write("c", 1);
		for(int i=0;i<10000;i++);
	}
	host_exit();
}

void hello_c()
{
	long tid_1 = host_pthread_create(print_b, NULL);
	long tid_2 = host_pthread_create(print_c, NULL);

	print_a();

	host_exit();
}
