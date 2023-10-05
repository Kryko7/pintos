#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"
#include "threads/synch.h"

typedef int pid_t;

struct file_desc
{
  int fd_num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};


void syscall_init (void);
// void close_by_owner(int);

#endif /* userprog/syscall.h */



