#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"

void test_hello (void)
{
	struct thread *t = thread_current();
	strlcpy (t->name, "hello", sizeof t->name);
	printf("%s\n",t->name);
	timer_sleep(500);
}
