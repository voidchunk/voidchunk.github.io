---
title: ELF文件保护机制
date: 2024-06-07 00:44:52
---

本文提到的编译选项，可以访问官方文档以获取更详细，更准确的介绍
https://gcc.gnu.org/onlinedocs/gcc-14.2.0/gcc/Option-Summary.html

# canary
```sh
gcc a.c -o a	# 默认部分开启canary，即仅在含有char数组的函数中加入canary
gcc a.c -o a -fno-stack-protector # 关闭canary
gcc a.c -o a -fstack-protector # 部分开启canary，这是默认选项
gcc a.c -o a -fstack-protector-all # 在所有函数中插入canary，即使没有char数组
```

# NX
```sh
gcc a.c -o a # 默认栈不可执行
gcc a.c -o a -z execstack # 栈可执行
gcc a.c -o a -z noexecstack # 栈不可执行，这是默认选项
```

# PIE
PIE，全名 position-independent code for executables
```sh
# 以下选项编译程序时使用
-fpic # 如果可能，生成1级的位置无关的代码，适用于共享库
-fPIC # 如果可能，生成2级的位置无关的代码，适用于共享库
-fpie	# 如果可能，生成1级的位置无关的代码，适用于可执行程序
-fPIE # 如果可能，生成2级的位置无关的代码，适用于可执行程序
-fno-pie # 生成位置相关的代码

# 以下选项链接程序时使用
-pie # 创建位置无关的可执行程序
-no-pie # 不创建位置无关的可执行程序

# 注意
# 关于‘如果可能’，请查看官方文档，一般来说指目标机器支持
# -fpie与-fPIE的区别请查看官方文档
# -fpie需要与-pie一起使用，一个用于编译阶段，一个用于链接阶段
# -fno-pie与-pie一起使用会报错

# 用法
gcc a.c -o a # 默认开启 -fpie 与 -pie
gcc a.c -o a -fpie -pie # 生成位置无关的程序
gcc a.c -o a -fno-pie -no-pie # 生成位置相关的程序
```

# ASLR
有以下两种方式查看ASLR状态
```sh
cat /proc/sys/kernel/randomize_va_space
2

sysctl -a --pattern randomize
kernel.randomize_va_space = 2
```

通过以下两种方式修改ASLR状态
```sh
# 全局更改
sudo -s echo 0 > /proc/sys/kernel/randomize_va_space

# 全局更改
sysctl -w kernel.randomize_va_space=0

# 使用setarch控制某个程序关闭ASLR
setarch `uname -m` -R ./your_program

# 使用gdb修改
set disable-randomization on # 开启
set disable-randomization off # 关闭
show disable-randomization # 查看
```

关于ASLR状态
```sh
# 0 = 关闭
# 1 = 半随机。共享库、栈、mmap() 以及 VDSO 将被随机化。
# 2 = 全随机。除了1中所述，还有heap。
```
注意：只有在开启 ASLR 之后，PIE 才会生效。  


# RELRO
```sh
Partial RELRO：.got不可写，.got.plt 可写
Full RELRO：.got和.got.plt 均不可写
gcc a.c -o a # 默认 -z lazy
gcc a.c -o a -z norelro # 关闭，No RELRO
gcc a.c -o a -z lazy # 部分开启，Partial RELRO
gcc a.c -o a -z now # 完全开启，Full RELRO
```

