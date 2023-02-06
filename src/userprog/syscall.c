

#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "stdlib.h"
#include "threads/loader.h"


struct file_descriptor
{
  int fd_num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};

#define STDIN_FILENO 0
#define STDOUT_FILENO 1


// #define	PHYS_BASE ((void *) LOADER_PHYS_BASE)

struct list open_files; 

struct lock fs_lock;

int write(int fd, const void* buffer, unsigned size);
void exit(int status);
static void syscall_handler (struct intr_frame *);
static pid_t exec(const char *cmd_line);
static int wait(pid_t pid);
static int read(int fd, void *buffer, unsigned size);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file);
static int filesize(int fd);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);


/* Helper functions*/
static struct file_descriptor *get_open_file (int);
static void close_open_file (int);
bool is_valid_ptr(const void *);
static int allocate_fd (void);
void close_file_by_owner(tid_t);
static bool is_valid_uvaddr(const void *uvaddr);
// static inline bool is_user_vaddr (const void *vaddr);

extern bool running;

void
syscall_init (void) 
{
  // printf("syscall_init\n");
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&open_files);
  lock_init(&fs_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	uint32_t *esp = f->esp;
	if (!is_valid_ptr (esp) || !is_valid_ptr (esp + 1) ||
      !is_valid_ptr (esp + 2) || !is_valid_ptr (esp + 3))
    {
      exit (-1);
    } 
	else {
	uint32_t* args = ((uint32_t*) f->esp);
	int type = args[0];
	args++;

	switch (type)
	{
	case SYS_HALT:
	{
		shutdown_power_off();
		break;
	}
	
	case SYS_EXIT:
	{
		exit(args[0]);
    // int status = *((int *) f->esp + 1);
    // struct thread *t = thread_current();
    // t->status = status;
    // //process_exit();
    // thread_exit();
    // printf("%s: exit(%d)\n", t->name, status);
		break;
	}
	
	case SYS_EXEC:
	{
		f->eax = exec((const char*) args[0]);
		break;
	}

	case SYS_WAIT:
	{
		f->eax = process_wait(args[0]);
		break;
	}

	case SYS_CREATE:
	{
		f->eax = create((const char*) args[0], args[1]);
		break;
	}

	case SYS_REMOVE:
	{
		f->eax = remove((const char*) args[0]);
		break;
	}

	case SYS_OPEN:
	{
		f->eax = open((const char*) args[0]);
		break;
	}

	case SYS_FILESIZE:
	{
		f->eax = filesize(args[0]);
		break;
	}

	case SYS_READ:
	{
		f->eax = read(args[0], (void*) args[1], args[2]);
		break;
	}

	case SYS_WRITE:
	{
		int fd = args[0];
		void *buffer = (void *) args[1];
		unsigned size = args[2];

		f->eax = write(fd, buffer, size);
		break;
	}

	case SYS_SEEK:
	{
		seek(args[0], args[1]);
		break;
	}

	case SYS_TELL:
	{
		f->eax = tell(args[0]);
		break;
	}

  case SYS_CLOSE:
  {
    close(args[0]);
    break;
  }


	default:
		break;
	}
	}
}

// int write(int fd, const void* buffer, unsigned size)
// {
// 	char *buf = (char *)buffer;
// 	int _size = 0;

// 	if (fd == 1)
// 	{
// 		putbuf(buf, size);
// 		_size = size;
// 		return size;
// 	}
// 	else
// 	{
// 		return -1;
// 	}
// }

void
exit(int status)
{
	struct thread *cur = thread_current();
	struct child_status *child;
	struct thread *parent = thread_get_by_id(cur->parent_id);
	if(parent != NULL)
	{
		struct list_elem *e = list_tail(&parent->children);
		while ((e = list_prev(e)) != list_head(&parent->children))
		{
			child = list_entry(e, struct child_status, elem_child_status);
			if(child->child_id == cur->tid)
			{
				lock_acquire(&parent->lock_child);
				child->is_exit_called = true;
				child->child_exit_status = status;
        cond_signal(&parent->cond_child, &parent->lock_child);
				lock_release(&parent->lock_child);
			}
		}
	}
	thread_exit();
}

pid_t
exec (const char *cmd_line)
{
  tid_t tid;
  struct thread *cur = thread_current();

  if (!is_valid_ptr(cmd_line))
	exit(-1);

cur->child_load_status = 0;
tid = process_execute(cmd_line);
lock_acquire(&cur->lock_child);
while (cur->child_load_status == 0)
	cond_wait(&cur->cond_child, &cur->lock_child);
if (cur->child_load_status == -1)
	tid = -1;
lock_release(&cur->lock_child);
return tid;
}

bool
create (const char *file_name, unsigned size)
{
  bool status;

  if (!is_valid_ptr (file_name))
    exit (-1);

  lock_acquire (&fs_lock);
  status = filesys_create(file_name, size);  
  lock_release (&fs_lock);
  return status;
}



bool 
remove (const char *file_name)
{
  bool status;
  if (!is_valid_ptr (file_name))
    exit (-1);

  lock_acquire (&fs_lock);  
  status = filesys_remove (file_name);
  lock_release (&fs_lock);
  return status;
}

int
open (const char *file_name)
{
  struct file *f;
  struct file_descriptor *fd;
  int status = -1;
  
  if (!is_valid_ptr (file_name))
    exit (-1);

  lock_acquire (&fs_lock); 
 
  f = filesys_open (file_name);
  if (f != NULL)
    {
      fd = calloc (1, sizeof *fd);
      fd->fd_num = allocate_fd ();
      fd->owner = thread_current ()->tid;
      fd->file_struct = f;
      list_push_back (&open_files, &fd->elem);
      status = fd->fd_num;
    }
  lock_release (&fs_lock);
  return status;
}

int
filesize (int fd)
{
  struct file_descriptor *fd_struct;
  int status = -1;
  lock_acquire (&fs_lock); 
  fd_struct = get_open_file (fd);
  if (fd_struct != NULL)
    status = file_length (fd_struct->file_struct);
  lock_release (&fs_lock);
  return status;
}

int
read (int fd, void *buffer, unsigned size)
{
  struct file_descriptor *fd_struct;
  int status = 0; 

  if (!is_valid_ptr (buffer) || !is_valid_ptr (buffer + size - 1))
    exit (-1);

  lock_acquire (&fs_lock); 
  
  if (fd == STDOUT_FILENO)
    {
      lock_release (&fs_lock);
      return -1;
    }

  if (fd == STDIN_FILENO)
    {
      uint8_t c;
      unsigned counter = size;
      uint8_t *buf = buffer;
      while (counter > 1 && (c = input_getc()) != 0)
        {
          *buf = c;
          buffer++;
          counter--; 
        }
      *buf = 0;
      lock_release (&fs_lock);
      return (size - counter);
    } 
  
  fd_struct = get_open_file (fd);
  if (fd_struct != NULL)
    status = file_read (fd_struct->file_struct, buffer, size);

  lock_release (&fs_lock);
  return status;
}

int
write (int fd, const void *buffer, unsigned size)
{
  struct file_descriptor *fd_struct;  
  int status = 0;

  if (!is_valid_ptr (buffer) || !is_valid_ptr (buffer + size - 1))
    exit (-1);

  lock_acquire (&fs_lock); 

  if (fd == STDIN_FILENO)
    {
      lock_release(&fs_lock);
      return -1;
    }

  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, size);
      lock_release(&fs_lock);
      return size;
    }
 
  fd_struct = get_open_file (fd);
  if (fd_struct != NULL)
    status = file_write (fd_struct->file_struct, buffer, size);
  lock_release (&fs_lock);
  return status;
}


void 
seek (int fd, unsigned position)
{
  struct file_descriptor *fd_struct;
  lock_acquire (&fs_lock); 
  fd_struct = get_open_file (fd);
  if (fd_struct != NULL)
    file_seek (fd_struct->file_struct, position);
  lock_release (&fs_lock);
  return ;
}


unsigned 
tell (int fd)
{
  struct file_descriptor *fd_struct;
  int status = 0;
  lock_acquire (&fs_lock); 
  fd_struct = get_open_file (fd);
  if (fd_struct != NULL)
    status = file_tell (fd_struct->file_struct);
  lock_release (&fs_lock);
  return status;
}

void 
close (int fd)
{
  struct file_descriptor *fd_struct;
  lock_acquire (&fs_lock); 
  fd_struct = get_open_file (fd);
  if (fd_struct != NULL && fd_struct->owner == thread_current ()->tid)
    close_open_file (fd);
  lock_release (&fs_lock);
  return ; 
}


struct file_descriptor *
get_open_file (int fd)
{
  struct list_elem *e;
  struct file_descriptor *fd_struct; 
  e = list_tail (&open_files);
  while ((e = list_prev (e)) != list_head (&open_files)) 
    {
      fd_struct = list_entry (e, struct file_descriptor, elem);
      if (fd_struct->fd_num == fd)
	return fd_struct;
    }
  return NULL;
}

void
close_open_file (int fd)
{
  struct list_elem *e;
  struct list_elem *prev;
  struct file_descriptor *fd_struct; 
  e = list_end (&open_files);
  while (e != list_head (&open_files)) 
    {
      prev = list_prev (e);
      fd_struct = list_entry (e, struct file_descriptor, elem);
      if (fd_struct->fd_num == fd)
	{
	  list_remove (e);
          file_close (fd_struct->file_struct);
	  free (fd_struct);
	  return ;
	}
      e = prev;
    }
  return ;
}


/* The kernel must be very careful about doing so, because the user can
 * pass a null pointer, a pointer to unmapped virtual memory, or a pointer
 * to kernel virtual address space (above PHYS_BASE). All of these types of
 * invalid pointers must be rejected without harm to the kernel or other
 * running processes, by terminating the offending process and freeing
 * its resources.
 */
bool
is_valid_ptr (const void *usr_ptr)
{
  struct thread *cur = thread_current ();
  //static inline bool is_valid = is_user_vaddr(usr_ptr);
  if (usr_ptr != NULL && is_valid_uvaddr (usr_ptr))
    {
      return (pagedir_get_page (cur->pagedir, usr_ptr)) != NULL;
    }
  return false;
}

// static inline bool
// is_user_vaddr (const void *vaddr) 
// {
//   return vaddr < PHYS_BASE;
// }

static bool
is_valid_uvaddr (const void *uvaddr)
{
  return (uvaddr != NULL && is_user_vaddr (uvaddr));
}

int
allocate_fd ()
{
  static int fd_current = 1;
  return ++fd_current;
}

void
close_file_by_owner (tid_t tid)
{
  struct list_elem *e;
  struct list_elem *next;
  struct file_descriptor *fd_struct; 
  e = list_begin (&open_files);
  while (e != list_tail (&open_files)) 
    {
      next = list_next (e);
      fd_struct = list_entry (e, struct file_descriptor, elem);
      if (fd_struct->owner == tid)
      {
        list_remove (e);
        file_close (fd_struct->file_struct);
              free (fd_struct);
      }
      e = next;
    }
}