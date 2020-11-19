# pintos实验2
pintos的实验2需要完成4个任务
 - 进程终止信息
 - 参数传递
 - 系统调用
 - 不能写入可执行文件

## 进程终止信息
要求：在进程结束时输出退出码(main函数的返回值)
注意：用户进程结束时输出退出码，核心线程返回时不输出
```cpp
    printf("%s:exit()\n",...);
```
在thread中加入变量保存返回值
```cpp
int ret
```
在线程退出时保存其返回值到ret中，这个将在系统调用里的exit函数当中保存。

每个线程结束后都会调用thread_exit()函数，如果是加载了用户进程，则在thread_exit()函数中还会调用process_exit()函数，在process_exit()函数中，如果是用户进程，那么页表一定不为nullptr，而核心进程的页表一定为nullptr，因此可以使用pd!=nullptr来判断是否是用户进程。如果是，就打印退出码
```cpp
if(pd!=nullptr)
{
    thread * cur = thread_current();
    printf("%s:exit(%d)\n",cur->name,cur->ret);
}
```

## 参数传递
要求：分离从命令行传入的文件名和各个参数。
按照C函数的约定，将参数放入栈中。

分离参数：
使用string.h中的strtok_r()方法。详情见string.c
在process_execute()函数当中，因为thread_create()函数需要一个线程名，此时应该传递文件名，如下：
```cpp
char * real_name, * save_ptr;
real_name = strlok_r(file_name," ",&save_ptr);
tid = thread_create(real_name,
    PRI_DEFAULT,start_process,fn_copy);
```
在start_process()函数中，再次分离参数，放入栈中。

