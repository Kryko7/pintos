

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




#define STDIN_FILENO 0
#define STDOUT_FILENO 1


// #define	PHYS_BASE ((void *) LOADER_PHYS_BASE)

struct list open_files; 

struct lock fs_lock;

int syscall_write(int fd, const void* buffer, unsigned size);
void syscall_exit(int status);
static void syscall_handler (struct intr_frame *);
static pid_t syscall_exec(const char *cmd_line);
static int syscall_wait(pid_t pid);
static int syscall_read(int fd, void *buffer, unsigned size);
static bool syscall_create(const char *file, unsigned initial_size);
static bool syscall_remove(const char *file);
static int syscall_open(const char *file);
static int syscall_filesize(int fd);
static void syscall_seek(int fd, unsigned position);
static unsigned syscall_tell(int fd);
static void syscall_close(int fd);


/* Helper functions*/
static struct file_desc *get_open_file (int);
static void close_open_file (int);
bool is_valid_ptr(const void *);
static int allocate_fd (void);
// void close_by_owner(tid_t);
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
      syscall_exit (-1);
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
		// syscall_exit(args[0]);
    int status = *((int *) f->esp + 1);
    struct thread *t = thread_current();
    t->status = status;
    //process_exit();
    thread_exit();
    // printf("%s: exit(%d)\n", t->name, status);
		break;
	}
	
	case SYS_EXEC:
	{
    const char *cmd_line = (const char *) args[0];
		f->eax = syscall_exec(cmd_line);
		break;
	}

	case SYS_WAIT:
	{
    pid_t pid = (pid_t) args[0];
		f->eax = process_wait(pid);
		break;
	}

	case SYS_CREATE:
	{
    const char *file = (const char *) args[0];
    unsigned initial_size = (unsigned) args[1];
		f->eax = syscall_create(file, initial_size);
		break;
	}

	case SYS_REMOVE:
	{
    const char *file = (const char *) args[0];
		f->eax = syscall_remove(file);
		break;
	}

	case SYS_OPEN:
	{
    const char *file = (const char *) args[0];
		f->eax = syscall_open(file);
		break;
	}

	case SYS_FILESIZE:
	{
    int fd = (int) args[0];
		f->eax = syscall_filesize(fd);
		break;
	}

	case SYS_READ:
	{
    int fd = (int) args[0];
    void *buffer = (void *) args[1];
    unsigned size = (unsigned) args[2];
		f->eax = syscall_read(fd, buffer, size);
		break;
	}

	case SYS_WRITE:
	{
		int fd = args[0];
		void *buffer = (void *) args[1];
		unsigned size = args[2];

		f->eax = syscall_write(fd, buffer, size);
		break;
	}

	case SYS_SEEK:
	{
    int fd = (int) args[0];
    unsigned position = (unsigned) args[1];
		syscall_seek(fd, position);
		break;
	}

	case SYS_TELL:
	{
    int fd = (int) args[0];
		f->eax = syscall_tell(fd);
		break;
	}

  case SYS_CLOSE:
  {
    int fd = (int) args[0];
    syscall_close(fd);
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
syscall_exit(int status)
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
syscall_exec (const char *cmd_line)
{
  tid_t tid;
  struct thread *cur = thread_current();

  if (!is_valid_ptr(cmd_line))
	  syscall_exit(-1);

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
syscall_create (const char *file_name, unsigned size)
{
  bool status;

  if (!is_valid_ptr (file_name))
    syscall_exit (-1);

  lock_acquire (&fs_lock);
  status = filesys_create(file_name, size);  
  lock_release (&fs_lock);
  return status;
}



bool 
syscall_remove (const char *file_name)
{
  bool status;
  if (!is_valid_ptr (file_name))
    syscall_exit (-1);

  lock_acquire (&fs_lock);  
  status = filesys_remove (file_name);
  lock_release (&fs_lock);
  return status;
}

int
syscall_open (const char *file_name)
{
  struct file *f;
  struct file_desc *fd;
  int status = -1;
  
  if (!is_valid_ptr (file_name))
    syscall_exit (-1);

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
syscall_filesize (int fd)
{
  struct file_desc *fd_struct;
  int status = -1;
  lock_acquire (&fs_lock); 
  fd_struct = get_open_file (fd);
  if (fd_struct != NULL)
    status = file_length (fd_struct->file_struct);
  lock_release (&fs_lock);
  return status;
}

int
syscall_read (int fd, void *buffer, unsigned size)
{
  struct file_desc *fd_struct;
  int status = 0; 

  if (!is_valid_ptr (buffer) || !is_valid_ptr (buffer + size - 1))
    syscall_exit (-1);

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
syscall_write (int fd, const void *buffer, unsigned size)
{
  struct file_desc *fd_struct;  
  int status = 0;

  if (!is_valid_ptr (buffer) || !is_valid_ptr (buffer + size - 1))
    syscall_exit (-1);

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
syscall_seek (int fd, unsigned position)
{
  struct file_desc *fd_struct;
  lock_acquire (&fs_lock); 
  fd_struct = get_open_file (fd);
  if (fd_struct != NULL)
    file_seek (fd_struct->file_struct, position);
  lock_release (&fs_lock);
  return ;
}


unsigned 
syscall_tell (int fd)
{
  struct file_desc *fd_struct;
  int status = 0;
  lock_acquire (&fs_lock); 
  fd_struct = get_open_file (fd);
  if (fd_struct != NULL)
    status = file_tell (fd_struct->file_struct);
  lock_release (&fs_lock);
  return status;
}

void 
syscall_close (int fd)
{
  struct file_desc *fd_struct;
  lock_acquire (&fs_lock); 
  fd_struct = get_open_file (fd);
  if (fd_struct != NULL && fd_struct->owner == thread_current ()->tid)
    close_open_file (fd);
  lock_release (&fs_lock);
  return ; 
}


struct file_desc *
get_open_file (int fd)
{
  struct list_elem *e;
  struct file_desc *fd_struct; 
  e = list_tail (&open_files);
  while ((e = list_prev (e)) != list_head (&open_files)) 
    {
      fd_struct = list_entry (e, struct file_desc, elem);
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
  struct file_desc *fd_struct; 
  e = list_end (&open_files);
  while (e != list_head (&open_files)) 
    {
      prev = list_prev (e);
      fd_struct = list_entry (e, struct file_desc, elem);
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




/*
  * Checks if the pointer is valid
  * Returns true if the pointer is valid
  * Returns false if the pointer is invalid
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


/*
  * Checks if the pointer is valid
  * Returns true if the pointer is valid
  * Returns false if the pointer is invalid
*/
static bool
is_valid_uvaddr (const void *uvaddr)
{
  return (uvaddr != NULL && is_user_vaddr (uvaddr));
}


/*
  * aloocates a new file descriptor
*/
int
allocate_fd ()
{
  static int fd_cur = 1;
  fd_cur++;
  return fd_cur;
}

// void
// close_by_owner (tid_t tid)
// {
//   struct list_elem *e;
//   struct list_elem *next;
//   struct file_descriptor *fd_struct; 
//   e = list_begin (&open_files);
//   while (e != list_tail (&open_files)) 
//     {
//       next = list_next (e);
//       fd_struct = list_entry (e, struct file_descriptor, elem);
//       if (fd_struct->owner == tid)
//       {
//         list_remove (e);
//         file_close (fd_struct->file_struct);
//               free (fd_struct);
//       }
//       e = next;
//     }
// }