#include "userprog/syscall.h"
#include "lib/user/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "lib/stdio.h"
#include "lib/kernel/stdio.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "process.h"
#include "lib/string.h"
#include "devices/input.h"

static void syscall_handler(struct intr_frame *);

// 查找file的辅助函数
struct file *
getFile(int fd)
{
  struct list_elem *l;
  struct file *ret = NULL;
  for (l = list_begin(&thread_current()->files); l != list_end(&thread_current()->files); l = list_next(l))
  {
    struct file *file = list_entry(l, struct file, elem);
    if (file->fd == fd)
    {
      return ret;
    }
  }
  return NULL;
}

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  // printf ("system call!\n");
  // thread_exit ();
  if (!is_user_vaddr(f->esp))
    exit(-1);

  switch (*(int *)f->esp)
  {
  case SYS_HALT:
  {
    // 实现系统调用halt,已经通过
    halt();
    break;
  }
  case SYS_EXIT:
  {
    // 实现系统调用void exit(int status); 貌似可以了
    int status = *((int *)f->esp + 1);
    exit(status);
    break;
  }
  case SYS_EXEC:
  {
    char *file_name = (char *)(*((int *)f->esp + 1));
    f->eax = exec(file_name);
    break;
  }
  case SYS_WAIT:
  {
    // pid_t就是int
    pid_t pid = *((int *)f->esp + 1);
    f->eax = wait(pid);
    break;
  }

  case SYS_CREATE:
  {
    char *file = (char *)(*((int *)f->esp + 1));
    unsigned int initial_size = *((int *)f->esp + 2);
    f->eax = create(file, initial_size);
    break;
  }
  case SYS_REMOVE:
  {
    char *file = (char *)(*((int *)f->esp + 1));
    f->eax = remove(file);
    break;
  }
  case SYS_OPEN:
  {
    char *file = (char *)(*((int *)f->esp + 1));
    f->eax = open(file);
    break;
  }
  case SYS_FILESIZE:
  {
    int fd = *((int *)f->esp + 1);
    f->eax = filesize(fd);
    break;
  }
  case SYS_READ:
  {
    int fd = *((int *)f->esp + 1);
    void *buffer = (void *)(*((int *)f->esp + 2));
    unsigned int length = *((unsigned *)f->esp + 3);
    f->eax = read(fd, buffer, length);
    break;
  }
  case SYS_WRITE:
  {
    int fd = *((int *)f->esp + 1);
    void *buffer = (void *)(*((int *)f->esp + 2));
    unsigned size = *((unsigned *)f->esp + 3);
    // 运行你编写的系统调用函数。
    // 一旦系统调用要返回一个值，将它保存在eax中
    f->eax = write(fd, buffer, size);
    break;
  }
  case SYS_SEEK:
  {
    int fd = *((int *)f->esp + 1);
    unsigned int position = *((int *)f->esp + 2);
    seek(fd, position);
    break;
  }
  case SYS_TELL:
  {
    int fd = *((int *)f->esp + 1);
    f->eax = tell(fd);
    break;
  }
  case SYS_CLOSE:
  {
    int fd = *((int *)f->esp + 1);
    close(fd);
    break;
  }
  default:
    printf("other!\n");
    break;
  }
}

void halt(void)
{
  // 直接断电就好
  shutdown();
}
void exit(int status)
{
  // 设置退出状态，然后退出
  struct thread *cur = thread_current();
  cur->ret = status;
  thread_exit();
}
pid_t exec(const char *file)
{
  // printf("exec:%s\n", file);
  return process_execute(file);
}
int wait(pid_t pid)
{
  // printf("wait:%d\n", pid);
  return process_wait(pid);
}
bool create(const char *file, unsigned initial_size)
{
  // printf("create:%s %d\n", file, initial_size);
  return filesys_create(file, initial_size);
}
bool remove(const char *file)
{
  // printf("remove %s\n",file);
  return filesys_remove(file);
}
int open(const char *file)
{
  // printf("open : %s\n", file);
  static int next_fd = 2;
  struct file *f = filesys_open(file);
  if (f == NULL)
    return -1;
  f->fd = next_fd++;
  list_push_back(&thread_current()->files, &f->elem);
  return f->fd;
}
int filesize(int fd)
{
  // printf("filesize:%d\n", fd);
  struct list_elem *l;
  struct list files = thread_current()->files;
  struct file *dest = NULL;
  for (l = list_begin(&thread_current()->files); l != list_end(&thread_current()->files); l = list_next(l))
  {
    struct file *file = list_entry(l, struct file, elem);
    if (file->fd == fd)
    {
      dest = file;
      break;
    }
  }
  return file_length(dest);
}
int read(int fd, void *buffer, unsigned length)
{
  // printf("read:%d %d\n", fd, length);
  if (fd == STDIN_FILENO)
  {
    for(int i=0;i<length;i++)
    {
      char c = input_getc();
      memcpy(buffer+i,&c,sizeof(char));
      return length;
    }
  }
  else
  {
    struct file *f = getFile(fd);
    return (int)file_read(f, buffer, length);
  }
}
int write(int fd, const void *buffer, unsigned length)
{
  if (fd == STDOUT_FILENO) // 如果输出到终端
  {
    // 直接使用putbuf即可输出
    putbuf(buffer, length);
    return length;
  }
  else
  {
    // printf("write:%d %d\n", fd, length);
    struct file *f = getFile(fd);
    return (int)file_write(f, buffer, length);
  }
}
void seek(int fd, unsigned position)
{
  // printf("seek:%d %d\n", fd, position);
  struct file *f = getFile(fd);
  file_seek(f, position);
}
unsigned tell(int fd)
{
  // printf("tell:%d\n", fd);
  struct file *f = getFile(fd);
  return file_tell(f);
}
void close(int fd)
{
  // printf("close:%d\n", fd);
  struct file * f = getFile(fd);
  file_close(f);
  list_remove(&f->elem);
}