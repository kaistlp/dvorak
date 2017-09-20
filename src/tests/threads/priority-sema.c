/* Tests that the highest-priority thread waiting on a semaphore
   is the first to wake up. */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "devices/timer.h"

static thread_func priority_sema_thread;
static struct semaphore sema;

void
test_priority_sema (void) 
{
  int i;
  
  /* This test does not work with the MLFQS. */
  ASSERT (!thread_mlfqs);

  sema_init (&sema, 0);
  thread_set_priority (PRI_MIN);
  for (i = 0; i < 10; i++) 
    {
      int priority = PRI_DEFAULT - (i + 3) % 10 - 1;
      char name[16];
      snprintf (name, sizeof name, "priority %d", priority);
      thread_create (name, priority, priority_sema_thread, NULL);
    }
    
  for (i = 0; i < 10; i++) 
    {
      sema_up (&sema);
      //enum intr_level old_level;
      //old_level = intr_disable();
      msg ("Back in main thread.");
      //intr_set_level(old_level); 
    }
}

static void
priority_sema_thread (void *aux UNUSED) 
{
  //msg ("Thread %s sema down.", thread_name ());
  sema_down (&sema);
  msg ("Thread %s woke up.", thread_name ());
}
