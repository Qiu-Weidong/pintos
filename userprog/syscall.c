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
  // 没找到，直接终止
  exit(-1);
  return NULL;
}

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  if (f == NULL || !is_user_vaddr(f->esp))
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
    // 要检查参数是否在有效地址
    if(!is_user_vaddr((int *)f->esp+1)) exit(-1);
    int status = *((int *)f->esp + 1);
    exit(status);
    break;
  }
  case SYS_EXEC:
  {
    if(!is_user_vaddr((int *)f->esp+1)) exit(-1);
    char *file_name = (char *)(*((int *)f->esp + 1));
    f->eax = exec(file_name);
    break;
  }
  case SYS_WAIT:
  {
    // pid_t就是int
    if(!is_user_vaddr((int *)f->esp+1)) exit(-1);
    pid_t pid = *((int *)f->esp + 1);
    f->eax = wait(pid);
    break;
  }

  case SYS_CREATE:
  {
    if(!is_user_vaddr((int *)f->esp+1) || !is_user_vaddr((int *)f->esp+2)) exit(-1);
    char *file = (char *)(*((int *)f->esp + 1));
    unsigned int initial_size = *((int *)f->esp + 2);
    f->eax = create(file, initial_size);
    break;
  }
  case SYS_REMOVE:
  {
    if(!is_user_vaddr((int *)f->esp+1)) exit(-1);
    char *file = (char *)(*((int *)f->esp + 1));
    f->eax = remove(file);
    break;
  }
  case SYS_OPEN:
  {
    if(!is_user_vaddr((int *)f->esp+1)) exit(-1);
    char *file = (char *)(*((int *)f->esp + 1));
    f->eax = open(file);
    break;
  }
  case SYS_FILESIZE:
  {
    if(!is_user_vaddr((int *)f->esp+1)) exit(-1);
    int fd = *((int *)f->esp + 1);
    f->eax = filesize(fd);
    break;
  }
  case SYS_READ:
  {
    if(!is_user_vaddr((int *)f->esp+1)||!is_user_vaddr((int *)f->esp+2)||!is_user_vaddr((int *)f->esp+3)) exit(-1);
    int fd = *((int *)f->esp + 1);
    void *buffer = (void *)(*((int *)f->esp + 2));
    unsigned int length = *((unsigned *)f->esp + 3);
    f->eax = read(fd, buffer, length);
    break;
  }
  case SYS_WRITE:
  {
    if(!is_user_vaddr((int *)f->esp+1)||!is_user_vaddr((int *)f->esp+2)||!is_user_vaddr((int *)f->esp+3)) exit(-1);
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
    if(!is_user_vaddr((int *)f->esp+1)||!is_user_vaddr((int *)f->esp+2)) exit(-1);
    int fd = *((int *)f->esp + 1);
    unsigned int position = *((int *)f->esp + 2);
    seek(fd, position);
    break;
  }
  case SYS_TELL:
  {
    if(!is_user_vaddr((int *)f->esp+1)) exit(-1);
    int fd = *((int *)f->esp + 1);
    f->eax = tell(fd);
    break;
  }
  case SYS_CLOSE:
  {
    if(!is_user_vaddr((int *)f->esp+1)) exit(-1);
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
  shutdown_power_off();
}
void exit(int status)
{
  // 设置退出状态，然后退出
  // printf("... exit_status:%d\n",status);
  struct thread *cur = thread_current();
  cur->ret = status;
  thread_exit();
}
pid_t exec(const char *file)
{
  if(file == NULL || !is_user_vaddr(file)) return TID_ERROR;
  return process_execute(file);
}
int wait(pid_t pid)
{
  // printf("wait:%d\n", pid);
  return process_wait(pid);
}
bool create(const char *file, unsigned initial_size)
{
  // 直接使用filesys_create函数创建文件
  if(file == NULL||!is_user_vaddr(file)) exit(-1);
  return filesys_create(file, initial_size);
}
bool remove(const char *file)
{
  // 直接使用filesys_remove删除文件，删除文件后，打开的文件不会被关闭
  return filesys_remove(file);
}
int open(const char *file)
{
  static int next_fd = 2;
  struct file *f = filesys_open(file);
  if (f == NULL)
    return -1;
  f->fd = next_fd++; // 为打开的文件分配文件描述符
  list_push_back(&thread_current()->files, &f->elem);// 将打开的文件添加到当前线程的文件列表当中
  return f->fd;
}
int filesize(int fd)
{
  struct file * f = getFile(fd);
  return file_length(f);
}
int read(int fd, void *buffer, unsigned length)
{
  if(buffer == NULL || !is_user_vaddr(buffer)) return 0;
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
  if(buffer == NULL || !is_user_vaddr(buffer)) return 0;
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