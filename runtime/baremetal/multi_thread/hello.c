#include <stdio.h>
#include "crt.h"
#include "hostcalls.h"

#define MSG "checkpoint test with multi-thread... \n"

void print_a()
{
	for (int i = 0; i < 100; i++)
	{
		host_write("a", 1);
	}
	host_save();
	// for (int i = 0; i < 100; i++)
	for (;;)
	{
		host_write("a", 1);
	}
}

void print_b()
{
	for (int i = 0; i < 100; i++)
	{
		host_write("b", 1);
	}
	host_save();
	// for (int i = 0; i < 100; i++)
	for (;;)
	{
		host_write("b", 1);
	}
}

void print_c()
{
	for (int i = 0; i < 100; i++)
	{
		host_write("c", 1);
	}
	host_save();
	// for (int i = 0; i < 100; i++)
	for (;;)
	{
		host_write("c", 1);
	}
}

void hello_c()
{
	// char buf[32];
	long tid_1 = host_pthread_create(print_b, NULL);
	long tid_2 = host_pthread_create(print_c, NULL);
	// __asm__ __volatile__(
	// 	"addi t0, zero, 1;"
	// 	"ecall;"
	// );
	print_a();
	host_thread_join(tid_1);
	host_thread_join(tid_2);

	host_exit();
}
