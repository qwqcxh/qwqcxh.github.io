---
layout:     post
title:      MITJOS
subtitle:   lab1
date:       2019-02-04
author:     qwqcxh
header-img: img/in-post/模板类壁纸/model.jpg
catalog: true
tags:
    - OS
    - course design
---

# Booting a PC
## Part 1: PC Bootstrap
### Getting Started with x86 assembly

**Exercise 1.** Familiarize yourself with the assembly language materials available on the 6.828 reference page. You don't have to read them now, but you'll almost certainly want to refer to some of this material when reading and writing x86 assembly.

We do recommend reading the section "The Syntax" in **Brennan's Guide to Inline Assembly**. It gives a good (and quite brief) description of the AT&T assembly syntax we'll be using with the GNU assembler in JOS. 

该任务的目的是熟悉AT&T汇编语言的使用，其指令与Intel大体相同，需要注意的是源操作数和目的操作数的差别，因为
以前学过Intel格式的X86汇编，所以基本能看懂本实验的汇编代码，对于个别不懂得指令也基本可以从网上找到其用法。

### Simulating the x86
本实验使用QEMU仿真器来仿真操作系统得运行，其使用比较简单，在实验文件目录下使用`make`命令会执行Makefile中
的编译指令自动生成目标文件，运行时使用`make qemu`或`make qemu-nox`即可启动qemu运行JOS。如下是初次启动后
的运行画面：
![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-qemurun.jpg)

仿真器使用ctrl+a x退出。初始状态下能运行kerninfo和help两条命令（对lab1暂不需要）。调试时在一个终端中使用
命令make qemu-nox-gdb在另一个终端中使用make gdb即可实现联调。

### The PC's Physical Address Space
首先我们可以看下PC的物理地址空间布局
```
+------------------+  <- 0xFFFFFFFF (4GB)
|      32-bit      |
|  memory mapped   |
|     devices      |
|                  |
/\/\/\/\/\/\/\/\/\/\

/\/\/\/\/\/\/\/\/\/\
|                  |
|      Unused      |
|                  |
+------------------+  <- depends on amount of RAM
|                  |
|                  |
| Extended Memory  |
|                  |
|                  |
+------------------+  <- 0x00100000 (1MB)
|     BIOS ROM     |
+------------------+  <- 0x000F0000 (960KB)
|  16-bit devices, |
|  expansion ROMs  |
+------------------+  <- 0x000C0000 (768KB)
|   VGA Display    |
+------------------+  <- 0x000A0000 (640KB)
|                  |
|    Low Memory    |
|                  |
+------------------+  <- 0x00000000
```
早期的16位Intel 8088处理器只有1MB的寻址空间，所以物理地址以0x00000000开始并结束于0x000FFFFF。上图中的Low Memory部分是唯一的RAM.其余的空间保留给特殊的硬件使用，在这些地址中最重要的一块是BIOS，
这64KB空间存放着开机后执行的引导系统运行的部分代码，主要是后面会提到的开机自检以及从MBR中加载bootloader。
后来的80386处理器支持4G的寻址空间，为了实现向后兼容仍旧保留了第1M空间的布局。具体可参见上图

### The ROM BIOS
开机后，处理器处于16bit的实模式下，此时CS初始化为0XF000,IP=0XFFF0.
转成物理地址是CS<<4+IP==0XFFFF0。该地址位于BIOS ROM空间的顶部，所以执行一条ljmp命令跳到BIOS ROM的较低地址执行BIOS区域的指令。这可以
通过GDB来跟踪BIOS的代码执行。

**Exercise 2.** Use GDB's si (Step Instruction) command to trace into the ROM BIOS for a few more instructions, and try to guess what it might be doing. You might want to look at Phil Storrs I/O Ports Description, as well as other materials on the 6.828 reference materials page. No need to figure out all the details - just the general idea of what the BIOS is doing first.

BIOS启动后，会设立中断描述符表并初始化各种设备，之后寻找启动磁盘读取
MBR中的 *boot loader* 并转去执行 *boot loader* 中的指令。这里我仅
跟踪了bios前几条指令，后面的指令较复杂难以详细弄清其意图。
![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-bios1.jpg)
首先是一条跳转指令跳到BIOS ROM的低地址空间。之后会继续跳转到0xfd15c的地址，我们在查看从该地址起的若干条指令，其截图如下：
![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-bios2.jpg)
首先关中断(cli)，设置字符串读取方向(cld)，然后将0x8f送到端口0x70
然后读0x71，查询手册得到如下两个端口的信息：
```
0070    w CMOS RAM index register port (ISA, EISA)
        bit 7	= 1  NMI disabled
                = 0  NMI enabled
        bit 6-0      CMOS RAM index (64 bytes, sometimes 128 bytes)
        any write to 0070 should be followed by an action to 0071
        or the RTC wil be left in an unknown state
0071	r/w	CMOS RAM data port (ISA, EISA)
		RTC registers:
        00 ...
        01 ...
        ···
        0F    shutdown status byte
		       00 = normal execution of POST
		       01 = chip set initialization for real mode reentry
		       04 = jump to bootstrap code
		       05 = issue an EOI an JMP to Dword ptr at 40:67
		       06 = JMP to Dword ptrv at 40:67 without EOI
		       07 = return to INT15/87 (block move)
		       08 = return to POST memory test
		       09 = return to INT15/87 (block move)
		       0A = JMP to Dword ptr at 40:67 without EOI
		       0B = return IRETS through 40:67
...
0092	r/w	PS/2 system control port A  (port B is at 0061)
		 bit 7-6   any bit set to 1 turns activity light on
		 bit 5	   reserved
		 bit 4 = 1 watchdog timout occurred 
		 bit 3 = 0 RTC/CMOS security lock (on password area) unlocked
		       = 1 CMOS locked (done by POST)
		 bit 2	   reserved
		 bit 1 = 1 indicates A20 active
		 bit 0 = 0 system reset or write
			 1 pulse alternate reset pin (alternate CPU reset)
```
从上述资料中可以知道BIOS会将NMI disable掉并读取CMOS RAM index为
0F的RTC寄存器，该寄存器存关机状态信息。接着将0x2送到0x92端口，即
开启A20模式（实模式转保护模式需要开启A20），后面的指令就是设置好IDT和GDT的基地址，将cr0控制寄存器的PE位置1，使用ljmp开始进入保护模式...
后续指令与底层硬件相关性较大没有继续跟踪，查询资料大致是与中断程序的安装以及硬件自检相关了。BIOS最后会从MBR加载boot loader到0x7c00处并
jmp到该位置执行。

## Part 2: The Boot Loader
Boot Loader主要做两件事情：
1. *将CPU从实模式再次转到保护模式*，在前面的跟踪中可以发现BIOS也是先进入保护模式来设置中断描述符表等后续动作，然后再执行某些操作时又会返回实模式。虽然不知道为什么，但是可以肯定的是刚执行boot loader时CPU处于实模式下，需要先转成保护模式。
2. *从1号扇区开始读取kernal* 到内存。0号扇区存的是boot loader,所以kernal需要从1号扇区开始读取。

**Exercise 3.** Take a look at the lab tools guide, especially the section on GDB commands. Even if you're familiar with GDB, this includes some esoteric GDB commands that are useful for OS work.

Set a breakpoint at address 0x7c00, which is where the boot sector will be loaded. Continue execution until that breakpoint. Trace through the code in boot/boot.S, using the source code and the disassembly file obj/boot/boot.asm to keep track of where you are. Also use the x/i command in GDB to disassemble sequences of instructions in the boot loader, and compare the original boot loader source code with both the disassembly in obj/boot/boot.asm and GDB.

Trace into bootmain() in boot/main.c, and then into readsect(). Identify the exact assembly instructions that correspond to each of the statements in readsect(). Trace through the rest of readsect() and back out into bootmain(), and identify the begin and end of the for loop that reads the remaining sectors of the kernel from the disk. Find out what code will run when the loop is finished, set a breakpoint there, and continue to that breakpoint. Then step through the remainder of the boot loader. 

GDB的x命令常见的有通过`x /Ni addr`来显示指令地址后的N条指令，`x /Nx addr `来显示指定的N个内存值。要进入0x7c00地址处，可以直接在GDB中
使用`b *0x7c00`设置断点然后用`c`执行到该断点即可。由于实验提供了自动生成的反汇编文件，所以我们主要通过boot.s,main.c以及
obj/boot/boot.asm这三个文件来分析boot loader。

### Loading the kernel
#### boot.s
先分析boot.s汇编文件。
```
.set PROT_MODE_CSEG, 0x8         # kernel code segment selector
.set PROT_MODE_DSEG, 0x10        # kernel data segment selector
.set CR0_PE_ON,      0x1         # protected mode enable flag
```
该文件首先使用.set伪指令定义了几个常量，类似于#define
```
.globl start
start:
  .code16                     # Assemble for 16-bit mode
  cli                         # Disable interrupts
  cld                         # String operations increment

  # Set up the important data segment registers (DS, ES, SS).
  xorw    %ax,%ax             # Segment number zero
  movw    %ax,%ds             # -> Data Segment
  movw    %ax,%es             # -> Extra Segment
  movw    %ax,%ss             # -> Stack Segment
```
接着关中断，设置字符串操作的方向并将几个寄存器的值初始化为0.
```
seta20.1:
  inb     $0x64,%al               # Wait for not busy
  testb   $0x2,%al
  jnz     seta20.1

  movb    $0xd1,%al               # 0xd1 -> port 0x64
  outb    %al,$0x64

seta20.2:
  inb     $0x64,%al               # Wait for not busy
  testb   $0x2,%al
  jnz     seta20.2

  movb    $0xdf,%al               # 0xdf -> port 0x60
  outb    %al,$0x60
```
这段指令是开启A20模式，在实模式下A20默认是关闭的，即第21根地址线是0，这样做是为了兼容实模式，到了保护模式下需开启A20，上述指令就是为了
实现这样的目的，在此不必过于纠结。
接下来就是本文件最关键的部分了：
```
  lgdt    gdtdesc
  movl    %cr0, %eax
  orl     $CR0_PE_ON, %eax
  movl    %eax, %cr0

  ljmp    $PROT_MODE_CSEG, $protcseg
  .code32                     # Assemble for 32-bit mode
protcseg:
  # Set up the protected-mode data segment registers
  movw    $PROT_MODE_DSEG, %ax    # Our data segment selector
  movw    %ax, %ds                # -> DS: Data Segment
  movw    %ax, %es                # -> ES: Extra Segment
  movw    %ax, %fs                # -> FS
  movw    %ax, %gs                # -> GS
  movw    %ax, %ss                # -> SS: Stack Segment
  
  # Set up the stack pointer and call into C.
  movl    $start, %esp
  call bootmain
```
首先使用lgdt命令来设置GDTR，GDTR是一个48位的寄存器，前32位是GDT的
基址，后16位是段界限。可以直接查看该文件末尾的关于GDT的设置：  
	gdt:
	SEG_NULL				# null seg  
	SEG(STA_X|STA_R, 0x0, 0xffffffff)	# code seg  
	SEG(STA_W, 0x0, 0xffffffff)	        # data seg  
该代码设置了3个段描述符，第一个是空的，第二三个设置的分别是代码段和
数据段，且段基址都是0，段界限是整个1M地址空间。这样做的目的是为了进入保护模式后的逻辑地址与实模式下的地址映射到相同的物理地址。我们可以
用GDB来查看GDT的3个描述符。在查看之前有必要了解段描述符的相关知识，
段描述符占8个字节，各个字节的含义可参考老师给的实验1PPT中的图示，截图如下：
![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-gdt1.jpg)
我们主要关注第2，3，4，7四个字节的段基址，和第0，1字节的段界限。现在
可以用GDB来查看gdt了。
![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-gdt2.jpg)
首先找到GDTR的相关信息，查看0x7c64位置可以知道GDT的大小是0x0017(低16位是段界限)。GDT的基址是0x7c4c,查看0x7c4c处24个字节（3个描述符）可以知道第一个描述符全0，第2，3个描述符基址都是0，段大小是0xffff，验证了我们的想法。  
	movl    %cr0, %eax  
	orl     $CR0_PE_ON, %eax  
	movl    %eax, %cr0  
这三条语句是将cr0的PE位置1，只有这样才能开启32位的保护模式，但此时还
并没进入保护模式，需要将寄存器的值修改后才能正式进入保护模式。
`ljmp $PRO_MODE_CSEG,$protcseg` 就是实现这一目的，PRO_MODE_CSEG的值是0x8,也就是将CS的值设为0x8这样就使得GDT索引是8，其转换是将CS的高13位乘以8来找GDT，这样恰好找到第二个段描述符。$protcseg就是下一条语句的偏移，所以就是跳到下一条语句，但此时已进入
32位保护模式。

后面的代码就是初始化一些段寄存器和esp了，之后进入bootmain。至此boot.s分析完毕。
#### main.c
我们先来看bootmain函数的代码，说明可见注释
```c
void
bootmain(void)
{
	struct Proghdr *ph, *eph;
	// 从磁盘读取一页（64KB)到ELFHDR位置（0x10000)
	readseg((uint32_t) ELFHDR, SECTSIZE*8, 0);
	// 检查ELF文件的魔数来判断是否有效
	if (ELFHDR->e_magic != ELF_MAGIC)
		goto bad;
	// ph指向ELF文件的程序头表的头部
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
	eph = ph + ELFHDR->e_phnum;//eph指向程序头表的尾部,注意ph+xxx是加sizeof(struct Proghdr)*xxx
	for (; ph < eph; ph++)//循环读取每一段
		// p_pa is the load address of this segment (as well
		// as the physical address)
		readseg(ph->p_pa, ph->p_memsz, ph->p_offset);
	//开始进入kernel执行
	((void (*)(void)) (ELFHDR->e_entry))();

bad:
	outw(0x8A00, 0x8A00);
	outw(0x8A00, 0x8E00);
	while (1)
		/* do nothing */;
}
```
在分析上述代码之前我们需要先了解ELF文件的基本知识。ELF文件的布局可以参见下图：
![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-elflayout.jpg)
左边是可重定向文件（.o文件）视图，右边是可执行文件视图，我们需要关注的是执行文件视图。
一个ELF文件最开始的是ELF header,然后是program header table,接着是具体各个segment的信息，一个segment是由
多个section组成，如.text,.data等。ELF header是一个定长的结构，可以在inc/elf.h中查看其声明：
```c
struct Elf {
	uint32_t e_magic;	//魔数用于判断文件的有效性
	uint8_t e_elf[12]; //包括数据的大小端、OS类型、ELF文件类型等
	uint16_t e_type; //文件类型
	uint16_t e_machine; //机器架构
	uint32_t e_version; //版本
	uint32_t e_entry;   //.txt代码执行入口
	uint32_t e_phoff;   //program header 的起始点偏移
	uint32_t e_shoff;   //section header 的起始点偏移
	uint32_t e_flags;   
	uint16_t e_ehsize;  
	uint16_t e_phentsize;
	uint16_t e_phnum;  //the number of program headers
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};
```
从上面可以知道ELF header描述了ELF文件的基本信息，比较重要的成员已给出注释说明。为了加深理解，可以用readelf来查看ELF header,
如下是我kernel的ELF header,可以帮助理解上面的结构信息：
![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-elfh.jpg)
我们需要通过读取ELF header中e_phoff,e_phnum来获得program header table的位置以及包含的段数。program header table描述了
每个段的基本信息，其表项的定义在inc/elf.h文件中：
```c
struct Proghdr {
	uint32_t p_type;//类型，如LOAD,STACK等
	uint32_t p_offset; //该段在ELF文件中的偏移
	uint32_t p_va; //段的虚拟地址
	uint32_t p_pa; //段的物理地址
	uint32_t p_filesz; //文件大小
	uint32_t p_memsz; //占用的内存大小
	uint32_t p_flags; //类型标志：R,W,E
	uint32_t p_align; //对齐方式
};
```
每个程序头表的表项描述了该段的基本信息，如其在ELF文件中的偏移，加载到内存的地址以及大小。这样boot loader就可以知道
从磁盘的什么位置（通过p_offset字段）读取多大（p_memsz字段）的数据到内存的什么位置（p_pa)。同样为了加深印象，我们
用readelf来查看program header table的表项。其截图如下：
![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-elfph.jpg)

有了这些知识后理解bootmain就很轻松了。boot loader先从磁盘1号扇区开始读取一页（8个扇区大小）的ELF文件到0x10000位置，
然后就可以获得ELF header了。通过分析ELF header中的e_phoff,e_phnum知道program header table的位置以及表项数，从而
遍历所有表项，将每个段按照表项的说明（Proghdr)读到内存的指定位置。可以通过分析上图知道.text被读到物理地址0x10000处。
最后boot loader 跳到e_entry处开始执行kernel.

现在继续分析main.c中readseg的流程即原理，相关说明参见注释。
```c
void
readseg(uint32_t pa, uint32_t count, uint32_t offset)
{
	uint32_t end_pa;
	end_pa = pa + count;//计算物理地址的尾部
	// 按扇区对齐，如低9位不是0需要清0
	pa &= ~(SECTSIZE - 1);
	// offset是一个segment相对ELF文件的偏移，因为kernel elf放在1号扇区，所以要+1
	offset = (offset / SECTSIZE) + 1;
	while (pa < end_pa) {//按扇区读，直至读完该segment
		//一次读一个扇区，该函数主要是设置磁盘控制器的相关端口，可以参见老师的ppt中参数的含义，不再细述
		readsect((uint8_t*) pa, offset); 
		pa += SECTSIZE;//更新pa
		offset++;//更新offset
	}
}
```
至此boot loader的代码分析完毕，接下来完成相关问题了。
- At what point does the processor start executing 32-bit code?What exactly causes the switch from 16- to 32-bit mode?
  按照个人理解，将cr0的PE位置1后CPU会从16-bit mode转成32-bit mode。但此时还未执行32-bit code。需要使用ljmp $PROT_MODE_CSEG, $protcseg后将相关寄存器设置好后才开始执行32-bit code。(因为保护模式中段寄存器要查GDT后才能算出物理地址，区别于实模式地址计算方式)
- What is the last instruction of the boot loader executed, and what is the first instruction of the kernel it just loaded?
  boot loader执行的最后一条指令是`((void (*)(void)) (ELFHDR->e_entry))();`汇编的形式是`call   *0x10018`。在GDB中用si跟踪
  进入该函数后kernel执行的第一条的指令是`movw   $0x1234,0x472`。截图如下：
  ![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-question2.jpg)
- Where is the first instruction of the kernel?
  上图中显示kernel的第一条指令地址是0x1000c。这与我们在ELF header中看到的e_entry是一致的。
- How does the boot loader decide how many sectors it must read in order to fetch the entire kernel from disk? Where does it find this information?
  首先需要从ELF header获取program header的数目e_phnum(在本实验中是3)以及位置e_phoff，然后循环读取program header table的
  三个表项，每个表项描述了一个段的大小，位置（通过偏移信息可计算出来）。这样就可以通过段大小来计算出要读取多少个扇区。

**Exercise 4.** Read about programming with pointers in C. The best reference for the C language is The C Programming Language by Brian Kernighan and Dennis Ritchie (known as 'K&R'). We recommend that students purchase this book (here is an Amazon Link) or find one of MIT's 7 copies. 
大一就学过C，所以对C语言比较熟悉。

**Exercise 5.** Trace through the first few instructions of the boot loader again and identify the first instruction that would "break" or otherwise do the wrong thing if you were to get the boot loader's link address wrong. Then change the link address in boot/Makefrag to something wrong, run make clean, recompile the lab with make, and trace into the boot loader again to see what happens. Don't forget to change the link address back and make clean again afterward!   

在回答这个问题之前需要了解关于VMA和LMA的基本概念，所谓的LMA是装载地址，也就是将ELF文件中各段从磁盘复制到内存存放时的内存地址。
在此实验中BIOS将存boot loader的0号扇区装到0x7c00，所以0x7c00就是装载地址。而VMA，也即链接地址或运行地址。该是由ld指定的，比如我们普通的用户程序分配的0x8048000，这个地址是可以人为修改的，针对本次实验我们可以在boot/Makefrag中将`-Ttext`后面的参数进行修改。
一般来说，LMA与VMA是相同的，如果不同，那么只能执行位置无关的代码，如相对地址跳转。如果执行位置相关代码，像绝对地址跳转，那么
跳转之后的物理地址就不是LMA地址处的代码，程序就会运行出错。
具体到本实验来说，LMA是0x7c00。手动修改Makefrag中的VMA地址为0x8c00，使用`make clean;make`重新编译链接生成文件。
我们先观察obj/boot.asm 可以看到程序的运行地址是以VMA0x8c00开始的：
![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-VMA.jpg)
这样引起的问题是遇到绝对地址跳转指令时会跳到错误的地址空间，在boot.s中的第一条绝对跳转指令是
`ljmp $PROT_MODE_CSEG, $protcseg`,在GDB中其代码如下：
![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-ljmp.jpg)
而显然0x8c32并不是该指令要跳转的地方，正确的应该是0x7c32。

**Exercise 6.** We can examine memory using GDB's x command. The GDB manual has full details, but for now, it is enough to know that the command x/Nx ADDR prints N words of memory at ADDR. (Note that both 'x's in the command are lowercase.) Warning: The size of a word is not a universal standard. In GNU assembly, a word is two bytes (the 'w' in xorw, which stands for word, means 2 bytes).

Reset the machine (exit QEMU/GDB and start them again). Examine the 8 words of memory at 0x00100000 at the point the BIOS enters the boot loader, and then again at the point the boot loader enters the kernel. Why are they different? What is there at the second breakpoint? (You do not really need to use QEMU to answer this question. Just think.) 

在地址0x0010000c设置一个断点,该地址是kernel的第一条指令，用GDB的x命令在程序刚运行时查看地址0x00100000处的8个words，然后
用continue命令运行到该断点，再次查看，两次查看的截图如下：
![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-change.jpg)
在进入kernel之前，在内存0x00100000处全0。而运行到kernel时，boot loader在之前将kernel的各个段已经load到0x00100000了。因此
我们这时看到的信息时kernel的信息。

## Part 3: The Kernel
### Using virtual memory to work around position dependence
为了实现地址的独立性，需要有分页机制，使得程序能运行在虚拟地址空间的高地址部分（低地址供用户程序使用）。
在本实验中，我们要将[0x00000000,0x00400000)以及[0xf0000000,0xf0400000)这两部分虚拟地址空间映射到物理
地址空间的[0x00000000,0x00400000)。在继续实验之前，我们先得了解分页的机制，给定一个32位的地址，可以把32位
拆分成10+10+12，高10位用于索引页目录表，中间10位用于索引页表，低12位用作页内偏移。其映射过程可参见下图：
![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-pedir.jpg)
现在可以分析kern/entrypgdir.c文件了
```c
pte_t entry_pgtable[NPTENTRIES];//声明一个大小为1k的页目录数组
__attribute__((__aligned__(PGSIZE))) //强制按页对齐
pde_t entry_pgdir[NPDENTRIES] = {
	// Map VA's [0, 4MB) to PA's [0, 4MB)
	[0]
		= ((uintptr_t)entry_pgtable - KERNBASE) + PTE_P,
	// Map VA's [KERNBASE, KERNBASE+4MB) to PA's [0, 4MB)
	// KERNBASE 的值是0xf0000000,PDXSHIFT是22
	[KERNBASE>>PDXSHIFT]
		= ((uintptr_t)entry_pgtable - KERNBASE) + PTE_P + PTE_W
};
```
这段代码是声明一个页目录数组并初始化其中两项，这两项分别对应[0x00000000,0x00400000)以及[0xf0000000,0xf0400000)两
部分虚拟地址空间，[0x00000000,0x003fffff]这段空间的地址高10位全0，分页时索引到页目录表的entry_pgdir[0],[0xf0000000,0xf03fffff]这段地址空间的高10位是0xf0000000>>22，索引到页目录表的entry_pgdir[KERNBASE>>PDXSHIFT]。这两个表项的高20位是相同的，因为页目录描述符的高20位用于索引页表（索引时低12位清0），低12位是标志位，两者的标志不完全相同。
继续看下面的代码：
```c
pte_t entry_pgtable[NPTENTRIES] = {
	0x000000 | PTE_P | PTE_W,
	0x001000 | PTE_P | PTE_W,
	0x002000 | PTE_P | PTE_W,
	...
}
```
这段代码声明并初始化一个1k的页表，该页表的下标索引到相同的页，如第1项索引到第1页，所以该页表是做一个直接映射。
综合前面的分析，通过这样的设置页目录表和页表就实现了将[0,4M),[KERNBASE+0,KERNBASE+4M)两部分虚拟地址空间均
映射到[0,4M)的物理地址空间。

接下来分析entry.s文件
```asm
.globl entry
entry:
	movw	$0x1234,0x472			# warm boot
	# Load the physical address of entry_pgdir into cr3.  entry_pgdir
	# is defined in entrypgdir.c.
	movl	$(RELOC(entry_pgdir)), %eax
	movl	%eax, %cr3
	# Turn on paging.
	movl	%cr0, %eax
	orl	$(CR0_PE|CR0_PG|CR0_WP), %eax
	movl	%eax, %cr0

	# Now paging is enabled, but we're still running at a low EIP
	# (why is this okay?).  Jump up above KERNBASE before entering
	# C code.
	### 因为[0,4M)的低虚拟地址空间也通过分页机制映射到[0,4M),所以ok
	mov	$relocated, %eax
	jmp	*%eax
relocated:
	movl	$0x0,%ebp			# nuke frame pointer
	# Set the stack pointer
	movl	$(bootstacktop),%esp
	# now to C code
	call	i386_init
.data
	# boot stack
	.p2align	PGSHIFT		# force page alignment
	.globl		bootstack
bootstack:
	.space		KSTKSIZE
	.globl		bootstacktop   
bootstacktop:
```
上述代码直接看注释即可弄懂，开启分页然后jmp到高的虚拟地址空间。因为[0,4M),[KERNBASE,KERNBASE+4M)都映射到[0,4M)。所以
上述代码能正常运行。数据段设置了一个stack,由esp指向栈顶。之后调用函数i386_init开始执行C代码。

**Exercise 7.** Use QEMU and GDB to trace into the JOS kernel and stop at the movl %eax, %cr0. Examine memory at 0x00100000 and at 0xf0100000. Now, single step over that instruction using the stepi GDB command. Again, examine memory at 0x00100000 and at 0xf0100000. Make sure you understand what just happened.

What is the first instruction after the new mapping is established that would fail to work properly if the mapping weren't in place? Comment out the movl %eax, %cr0 in kern/entry.S, trace into it, and see if you were right. 

如下是用GDB调试查看的结果：
![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-entry.jpg)
在执行mov %eax,%cr0之前还没开启分页，所以0xf0100000处的内存仍然是0。执行该指令后这两个地址指向相同的物理地址，因而这两
地址处的内存值相同。

### Formatted Printing to the Console
这一部分是实现printf函数，虽然实现复杂，但是分析起来并不困难。由于这部分代码过多，所以不会逐语句分析，仅分析比较重要的
部分。与这部分相关的代码文件是kern/printf.c,kern/console.c,lib/printfmt.c
在printf.c文件中主要实现了cprintf函数和putch函数。两函数的调用链如下：
cprintf-->vcprintf-->vprintfmt  
putch---->cputchar-->cons_putc-->seria_putc、lpt_putc、cga_putc  
由于cprintf函数最后会调用vprintfmt函数来实现，所以我们可以考察该函数。
vprintfmt函数外层是一个while循环，循环内部首先处理常规字符：
```c
while ((ch = *(unsigned char *) fmt++) != '%') {
	if (ch == '\0') //字符串读完，结束循环
		return;
	putch(ch, putdat); //调用putch输出常规字符
}
```
上述循环在遇到`%`时会退出，开始对`%`后的格式描述进行分析，该过程是一个switch语句，结合每个case的注释不难理解，
这里不再赘述。
```c
	reswitch:
		switch (ch = *(unsigned char *) fmt++) {
		case '-':
			padc = '-'; //置右对齐标志
			goto reswitch;
		case '0':
			padc = '0'; //置0填充空格标记
			goto reswitch;
		// 设置精度
		case '1':case '2':case '3':case '4':case '5':
		case '6':case '7':case '8':case '9':
			for (precision = 0; ; ++fmt) {
				precision = precision * 10 + ch - '0';//计算精度
				ch = *fmt;
				if (ch < '0' || ch > '9')
					break;
			}
			goto process_precision;
		.........
		// unsigned decimal
		case 'u':
			num = getuint(&ap, lflag);
			base = 10;
			goto number;
		// (unsigned) octal
		case 'o'://8进制输出，可以参考case 'u'，将base=10改为base=8即可
			// Replace this with your code.
			num = getuint(&ap,lflag);
			base = 8;
			goto number;
		.........
```
从上面的分析可以知道字符串的格式分析由此函数完成，也许我们会比较好奇printf函数的可变参数列表的
实现机制。接下来就对其进行分析。
与可变参数实现相关的有3个宏，分别时va_start,va_end,va_arg。它们在inc/stdarg.h中声明：
```
typedef __builtin_va_list va_list;
#define va_start(ap, last) __builtin_va_start(ap, last)
#define va_arg(ap, type) __builtin_va_arg(ap, type)
#define va_end(ap) __builtin_va_end(ap)
```
也就是它们是由编译器内建宏完成的，为了了解这些宏的具体内容，查阅相关资料后总结如下：  
 _INTSIZEOF(n) ((sizeof(n)+sizeof(int)-1)&~(sizeof(int) - 1) ) 
va_start(ap,last) ( ap = (va_list)&last + _INTSIZEOF(last) ) 
va_arg(ap,t)   ( *(t *)((ap += _INTSIZEOF(t)) - _INTSIZEOF(t)) )
va_end(ap) ( ap = (va_list)0 )
- va_start将ap指针初始化为可变参数字符串的地址
- va_arg(ap,t)返回一个类型为t的参数变量然后指向下一个参数
- va_end将ap指针清0.

现在我们知道了如何获取可变参数了，首先我们分析格式字符串fmt，依次遍历fmt直至遇到%，通过分析%后面
的格式字符确定需要一个什么类型的参数，然后使用va_arg(ap,type)来从va_list中读取一个该类型的参数并
将ap指针移动到下一个参数直至fmt字符串分析完。另外在printfmt.c中用getint,getuint封装了下va_arg，可以
拿来直接用。

**Exercise 8.** We have omitted a small fragment of code - the code necessary to print octal numbers using patterns of the form "%o". Find and fill in this code fragment.   
通过上述分析我们知道需要在vprintfmt的switch中修改case 'o'的相关内容，通过参考case 'd'可以很
容易地写出如下代码：
```
case 'o'://8进制输出，可以参考case 'u'，将base=10改为base=8即可
	// Replace this with your code.
	num = getuint(&ap,lflag);//从可变参数列表读取一个unsigned
	base = 8; //设置基数
	goto number; 
```

接下来分析putch的调用链：
```
static void putch(int ch, int *cnt)
{
	cputchar(ch);
	*cnt++;
}
void cputchar(int c)
{
	cons_putc(c);
}
static void cons_putc(int c)
{
	serial_putc(c);
	lpt_putc(c);
	cga_putc(c);
}
```
可以看到putch最终会调用cons_putc，而该函数又是调用seria_putc,lpt_putc以及cga_putc。
serial_putc与lpt_putc主要是设置好串行端口和并行端口的相关参数。而与显示相关的代码则具体由cga_putc
实现。如下是cga_putc的代码：  
```
static void
cga_putc(int c)
{
	// if no attribute given, then use black on white
	if (!(c & ~0xFF))//c的低字节是具体的ASCILL字符，而高字节则是于颜色设置相关
		c |= 0x0700;

	switch (c & 0xff) {
	case '\b'://回退
		if (crt_pos > 0) {
			crt_pos--;
			crt_buf[crt_pos] = (c & ~0xff) | ' ';
		}
		break;
	case '\n'://换行
		crt_pos += CRT_COLS;
		/* fallthru */
	case '\r'://回车
		crt_pos -= (crt_pos % CRT_COLS);
		break;
	case '\t'://制表
		cons_putc(' ');
		cons_putc(' ');
		cons_putc(' ');
		cons_putc(' ');
		cons_putc(' ');
		break;
	default: //普通字符
		crt_buf[crt_pos++] = c;		/* write the character */
		break;
	}

	// What is the purpose of this?
	if (crt_pos >= CRT_SIZE) { //光标超过屏幕大小
		int i;
		memmove(crt_buf, crt_buf + CRT_COLS, (CRT_SIZE - CRT_COLS) * sizeof(uint16_t));//将屏幕从第2行开始都往上挪动一行
		for (i = CRT_SIZE - CRT_COLS; i < CRT_SIZE; i++)//最后一行填空格
			crt_buf[i] = 0x0700 | ' ';
		crt_pos -= CRT_COLS;//光标置于最后一行开头位置
	}

	/* move that little blinky thing */
	outb(addr_6845, 14);
	outb(addr_6845 + 1, crt_pos >> 8);
	outb(addr_6845, 15);
	outb(addr_6845 + 1, crt_pos);
}
```
上面代码比较简单，就是设置字符的颜色以及实现字符显示和翻屏功能，相关分析可参见注释。

现在可以来回答本部分相关问题了：
1. Explain the interface between printf.c and console.c. Specifically, what function does console.c export? How is this function used by printf.c?  
printf.c通过调用console.c封装的函数cputchar来实现通信。该函数接收一个要打印的字符参数，然后设置好console的相关端口来输出该
字符。
2. Explain the following from console.c  
	1      if (crt_pos >= CRT_SIZE) {  
	2              int i;  
	3              memmove(crt_buf, crt_buf + CRT_COLS, (CRT_SIZE - CRT_COLS) * sizeof(uint16_t));  
	4              for (i = CRT_SIZE - CRT_COLS; i < CRT_SIZE; i++)  
	5              crt_buf[i] = 0x0700 | ' ';  
	6              crt_pos -= CRT_COLS;  
	7      }  
该段代码的功能是实现翻屏，如果光标超出屏幕就将整个屏幕上移一行并将最后一行用空格填充。  
3. For the following questions you might wish to consult the notes for Lecture 2. These notes cover GCC's calling convention on the x86.  
   Trace the execution of the following code step-by-step:
```
    int x = 1, y = 3, z = 4;
    cprintf("x %d, y %x, z %d\n", x, y, z);
```
- In the call to cprintf(), to what does fmt point? To what does ap point?
  fmt指向"x %d, y %x, z %d\n".ap指向第一个可变参数x。
- List (in order of execution) each call to cons_putc, va_arg, and vcprintf. For cons_putc, list its argument as well. For va_arg, list what ap points to before and after the call. For vcprintf list the values of its two arguments.   
 具体调试可以在这几个函数设置断点，然后每次continue运行即可观察执行顺序，如下是部分运行截图：
 ![](https://raw.github.com/qwqcxh/qwqcxh.github.io/master/img/in-post/OS/lab1-qsdb.jpg) 
 因为va_arg是内建宏，不能设置断点，但是可以从源代码中分析其调用位置，在遍历到%d,%x,%d的过程中，ap会先后
 指向1，2，3。整体而言会先指行到vcprintf,然后执行cons_putc,因为输出字符较多，所以会多次执行该函数。在遇到百分号
 后会执行var_arg宏，由于调用次数过多，此处不再细述。
4. Run the following code.
```
unsigned int i = 0x00646c72;
cprintf("H%x Wo%s", 57616, &i);
```
What is the output? Explain how this output is arrived at in the step-by-step manner of the previous exercise. Here's an ASCII table that maps bytes to characters.  
The output depends on that fact that the x86 is little-endian. If the x86 were instead big-endian what would you set i to in order to yield the same output? Would you need to change 57616 to a different value?  
运行结果为"He110 World"，因为57616的16进制表示就是0xe110,而0x72,0x6c,0x64分别是'r','l','d'的Ascill码。所以输出该结果。
如果机器是大端的话，需要将i的值改为0x726c6400。而57616不需要修改，因为无论大小端其值是相同的。
5. In the following code, what is going to be printed after 'y='? (note: the answer is not a specific value.) Why does this happen?
```
cprintf("x=%d y=%d", 3);
```  
y后面会输出一个任意值，因为ap每取出一个参数会往后移动，而因为y对应的参数缺少，所以ap移动后指向的内存中的值不确定。
6. Let's say that GCC changed its calling convention so that it pushed arguments on the stack in declaration order, so that the last argument is pushed last. How would you have to change cprintf or its interface so that it would still be possible to pass it a variable number of arguments?
如果不修改va_start,va_arg,va_end的话，需要将cprintf的接口改为cprintf(...,const char*fmt)这种形式，此外可变参数也得从右至左
匹配fmt字符串，这样才能保证压栈后栈中参数与原来一致。或者通过修改va_start,va_arg这些宏而保留原接口形式,在改变之前栈中由低到高
地址依次是fmt,va1,va2...,改变后变为van...va2,va1,fmt。需要将va_start宏的+变为-,va_arg的+=改为-=
```
va_start(ap,fmt) ( ap = (va_list)&fmt - _INTSIZEOF(fmt) ) //&fmt为fmt的地址，减去其占用的字节才是第一个参数。
va_arg(ap,t)   ( *(t *)((ap -= _INTSIZEOF(t)) - _INTSIZEOF(t)) )//ap指针向低地址方向移动
va_end(ap) ( ap = (va_list)0 )
```