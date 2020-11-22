#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  // printf ("system call!\n");
  thread_exit ();
  // if (!is_user_vaddr(f->esp))
  //   exit(-1);
  // switch (*(int *)f->esp)
  // {
  // case SYS_HALT:
  // {
  //   // 实现系统调用halt
  //   halt();
  //   break;
  // }
  // case SYS_EXIT:
  // {
  //   // 实现系统调用void exit(int status);
  //   int status = *((int *)f->esp+1);
  //   exit(status);
  //   break;
  // }
  // case SYS_EXEC:
  // {
  //   char *file_name = (char *)(*((int *)f->esp+1));
  //   f->eax = exec(file_name);
  //   break;
  // }
  // case SYS_WAIT:
  // {
  //   // pid_t就是int
  //   pid_t pid = *((int *)f->esp+1);
  //   f->eax = wait(pid);
  //   break;
  // }

  // case SYS_CREATE:
  // {
  //   char * file = (char *)(*((int *)f->esp+1));
  //   unsigned int initial_size = *((int *)f->esp+2);
  //   f->eax = create(file, initial_size);
  //   break;
  // }
  // case SYS_REMOVE:
  // {
  //   char * file = (char *)(*((int *)f->esp+1));
  //   f->eax = remove(file);
  //   break;
  // }
  // case SYS_OPEN:
  // {
  //   char * file = (char *)(*((int *)f->esp+1));
  //   f->eax = open(NULL);
  //   break;
  // }
  // case SYS_FILESIZE:
  // {
  //   int fd = *((int *)f->esp + 1);
  //   f->eax = filesize(fd);
  //   break;
  // }
  // case SYS_READ:
  // {
  //   int fd = *((int *)f->esp+1);
  //   void * buffer = (void *)(*((int *)f->esp+2));
  //   unsigned int length = *((unsigned *)f->esp+3);
  //   f->eax = read(fd,buffer,length);
  //   break;
  // }
  // case SYS_WRITE:
  // {
  //   int fd = *((int *)f->esp+1);
  //   void * buffer = (void *)(*((int *)f->esp+2));
  //   unsigned size = *((unsigned *)f->esp+3);
  //   // 运行你编写的系统调用函数。
  //   // 一旦系统调用要返回一个值，将它保存在eax中
  //   f->eax = write(fd,buffer,size);
  //   break;
  // }
  // case SYS_SEEK:
  // {
  //   int fd = *((int *)f->esp+1);
  //   unsigned int position = *((int *)f->esp+2);
  //   seek(fd,position);
  //   break;
  // }
  // case SYS_TELL:
  // {
  //   int fd = *((int *)f->esp + 1);
  //   f->eax = tell(fd);
  //   break;
  // }
  // case SYS_CLOSE:
  // {
  //   int fd = *((int *)f->esp + 1);
  //   close(fd);
  //   break;
  // }
  // default:
  //   break;
  // }
}
