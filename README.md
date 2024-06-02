[OSKernel2024-Single-OS-ALL](https://gitlab.eduxiji.net/T202410359993285/OSKernel2024-Single-OS-ALL/-/tree/main/)

该文档为初赛文档，其中完成了文件管理以及部分的系统调用，其中参考资料为NPUOS以及清华的rCore-v3。

该文档以及整个项目为一人编写，其中完成了部分的系统调用，以及文件管理、进程管理等。

系统调用（System Call）是操作系统提供给用户程序或应用程序的一种服务请求的接口，它允许用户程序请求操作系统内核执行特权指令，从而执行一些底层的、只有内核才能执行的任务。系统调用是用户空间和内核空间之间的重要接口，允许用户程序访问操作系统的核心功能，例如文件操作、进程管理、网络通信等。

1、**系统调用的相关原理：**

1. **用户态和内核态：**

2. - 大多数现代操作系统采用分时多任务的方式运行多个程序。在这种情况下，每个程序都有两种运行状态，即用户态和内核态。
   - 用户态下程序只能执行非特权指令，而要执行一些特权操作（如访问硬件、修改内存映射等），必须切换到内核态。系统调用是用户程序切换到内核态的一种方式。

3. **系统调用的触发：**

4. - 系统调用的触发通常是由用户程序主动发起的，通过特定的指令或函数调用（例如**int 0x80**或**syscall**指令）向操作系统发出请求。
   - 用户程序通过传递参数（通常是寄存器中或堆栈中的参数）来指定系统调用的类型和所需操作的具体细节。

5. **系统调用的处理过程：**

6. - 当用户程序触发系统调用时，处理器将切换到内核态，跳转到操作系统内核的相应系统调用处理函数。
   - 内核根据用户程序提供的参数，执行相应的内核操作。
   - 完成操作后，将结果返回给用户程序，并将处理器切换回用户态，使用户程序可以继续执行。

7. **系统调用的分类：**

8. - 系统调用涉及的功能非常广泛，可以分为文件系统调用、进程管理调用、内存管理调用、网络调用等。
   - 不同的操作系统和架构有不同的系统调用接口，例如在Linux上使用的**int 0x80**或**syscall**指令，而在Windows上使用的是**int 0x2E**。

**系统调用的算法：**

1. **系统调用参数传递：**

2. - 系统调用通常需要传递参数，参数的传递方式有多种，包括寄存器传递、堆栈传递等。
   - 参数的传递方式通常取决于硬件架构和操作系统设计。

3. **系统调用表：**

4. - 操作系统维护一个系统调用表，其中包含了系统调用的编号和对应的处理函数的映射关系。
   - 用户程序发起系统调用时，通过系统调用编号来定位相应的处理函数。

5. **内核态切换开销：**

6. - 切换到内核态和返回用户态涉及到上下文的保存和恢复。系统调用的实现需要考虑这些开销，并尽量减少切换的次数和开销。

7. **安全性和权限检查：**

8. - 在执行系统调用之前，内核通常会进行安全性检查，确保用户程序有执行特定操作的权限。
   - 权限检查是系统调用的一部分，以保护系统的稳定性和安全性。

9. **错误处理：**

10. - 系统调用可能会失败，内核需要提供有效的错误信息给用户程序，以便用户程序能够适当地处理错误情况。

简易的文件系统：

为了实现简易的文件系统，我们采用：扁平化、权限控制的文件系统，不支持软硬链接；

![img](file:///C:/Users/pgl/AppData/Local/Temp/msohtmlclip1/01/clip_image002.png)

 

**4.** **系统结构和主要的算法设计思路**

为内核设计系统调用；其中包括无结构体的系统调用以及有结构体的系统调用；其中的设计思路为：

首先在内核OS文件中的scr文件夹中的syscall文件夹中的mod.rs文件中添加系统调用的调用号；

![img](file:///C:/Users/pgl/AppData/Local/Temp/msohtmlclip1/01/clip_image004.png)

之后再在该文件下编写syscall；

![img](file:///C:/Users/pgl/AppData/Local/Temp/msohtmlclip1/01/clip_image006.png)

之后再在该syscall文件夹中的除了mod文件之外的文件中实现该syscall方法。如下图：

![img](file:///C:/Users/pgl/AppData/Local/Temp/msohtmlclip1/01/clip_image008.png)

该过程为实现系统调用的流程，也就是为外层写一个ABI接口；

在这个项目中我负责完成文件系统的管理；其中完成的系统调用为：sys_dup、sys_dup3、sys_write、sys_read、sys_open_at、sys_close、sys_fstat、sys_mkdirat、sys_getcwd、sys_chdir；

同时完成了文件系统的扩展，实现了两级目录：

![img](file:///C:/Users/pgl/AppData/Local/Temp/msohtmlclip1/01/clip_image010.png)

**5.** **程序实现——主要数据结构**

其中所含有的结构体：

针对于fstat的结构体：

![img](file:///C:/Users/pgl/AppData/Local/Temp/msohtmlclip1/01/clip_image012.png)

针对于文件打开关闭的结构体：

![img](file:///C:/Users/pgl/AppData/Local/Temp/msohtmlclip1/01/clip_image014.png)

**6.** **程序实现——程序实现细节描述**

以一个系统调用为例子来讲解系统调用的编写：

第一步：编写一个系统调用号：

const SYSCALL_DUP: usize = 23;

第二部使用syscall调用：

SYSCALL_DUP => sys_dup(args[0] as usize),

第三步实现系统调用的函数：

pub fn sys_dup(fd: usize) -> isize {

  let task = current_task().unwrap();

  let mut inner = task.inner_exclusive_access();

  let new_fd = inner.alloc_fd(0);

  inner.fd_table[new_fd] = inner.fd_table[fd].clone();

  print!("sys_dup(fd: {}) = {}", fd, new_fd);

  new_fd as isize

}

最后讲一下两级文件系统的编写：

一个 DiskInode 在磁盘上占据128字节的空间。我们考虑加入 indirect3 字段并缩减 INODE_DIRECT_COUNT 为27以保持 DiskInode 的大小不变。此时直接索引可索引13.5KiB的内容，一级间接索引和二级间接索引仍然能索引64KiB和8MiB的内容，而三级间接索引能索引128 * 8MiB = 1GiB的内容。当文件大小大于13.5KiB + 64KiB + 8MiB时，需要用到三级间接索引。

下面的改动都集中在 easy-fs/src/layout.rs 中。首先修改 DiskInode 和相关的常量定义。

 

pub struct DiskInode {

  pub size: u32,

  pub direct: [u32; INODE_DIRECT_COUNT],

  pub indirect1: u32,

  pub indirect2: u32,

  pub indirect3: u32,

  type_: DiskInodeType,

}

在计算给定文件大小对应的块总数时，需要新增对三级间接索引的处理。三级间接索引的存在使得二级间接索引所需的块数不再计入所有的剩余数据块。

在pub fn total_blocks(size: u32) -> u32 {}函数中

DiskInode 的 get_block_id 方法中遇到三级间接索引要额外读取三次块缓存。

pub fn get_block_id(&self, inner_id: u32, block_device: &Arc<dyn BlockDevice>) -> u32 {}

![img](file:///C:/Users/pgl/AppData/Local/Temp/msohtmlclip1/01/clip_image016.png)

然后修改方法 increase_size。不要忘记在填充二级间接索引时维护 current_blocks 的变化，并限制目标索引 (a1, b1) 的范围。

![img](file:///C:/Users/pgl/AppData/Local/Temp/msohtmlclip1/01/clip_image018.png)

对方法 clear_size 的修改与 increase_size 类似。先实现辅助方法 collect_tree_blocks；然后修改方法 clear_size。

![img](file:///C:/Users/pgl/AppData/Local/Temp/msohtmlclip1/01/clip_image020.png)

接下来你可以在 easy-fs-fuse/src/main.rs 中测试easy-fs文件系统的修改，比如读写大小超过10MiB的文件。

**7.****程序运行的主要界面和实验结果截图**

二级文件系统：其中验证了实现的mkdir，以及getcwd以及open_at

![img](file:///C:/Users/pgl/AppData/Local/Temp/msohtmlclip1/01/clip_image022.png)

对于文件的创建以及读写以及查看都有验证：即create、open_at、read、write、

![img](file:///C:/Users/pgl/AppData/Local/Temp/msohtmlclip1/01/clip_image024.png)

对于文件的dup以及dup3的测试，首先先创建一个文件，并且获取其中的fd即文件描述符；之后传入到dup或dup3中进行测试。其中的测试结果为：

![img](file:///C:/Users/pgl/AppData/Local/Temp/msohtmlclip1/01/clip_image026.png)

dup3:

**8.****总结和感想体会**

实验设计涉及系统调用和文件系统两个重要的操作系统概念，以及在RISC-V硬件环境下的开发。下面是学生可能在这个课程设计中获得的一些体验：

**1.** **深入理解操作系统概念：**

- **系统调用理解：** 学生将深入了解系统调用的概念、作用和原理，以及如何设计和实现自定义的系统调用。这有助于巩固操作系统的基本原理。
- **文件系统设计：** 学生通过修改文件系统结构，了解文件系统中的数据结构和设计原理，同时实践考虑文件系统的扩展性和性能。

**2.** **熟悉RISC-V硬件环境：**

- **Rust****和C编程：** 学生将使用Rust和C两种编程语言，分别编写系统调用和进行底层硬件编程。这有助于学生掌握多种编程语言和底层硬件交互的能力。
- **QEMU****模拟器：** 学生需要在QEMU模拟器中测试系统调用和文件系统的功能，深入了解RISC-V架构在模拟环境中的使用。

**3.** **实际的内核开发经验：**

- **系统调用的编写和调试：** 学生亲自编写和调试系统调用，从而获得实际的内核开发经验。这将提高他们的调试技能和代码理解能力。
- **文件系统结构修改：** 学生通过修改文件系统结构，实践对实际项目进行结构调整和优化的能力，了解这些修改如何影响文件系统的性能和扩展性。

**4.** **团队协作与沟通：**

- **版本控制使用：** 如果是团队项目，学生可能需要使用版本控制系统（如Git）进行协同开发，提高团队协作和代码管理的经验。
- **文档撰写：** 学生可能需要编写文档来解释他们的系统调用和文件系统的设计，以确保其他开发者能够理解和使用他们的工作。

**5.** **实验中的挑战与解决问题：**

- **调试挑战：** 学生将面临调试系统调用和文件系统的挑战，可能需要使用调试工具和技术来解决问题。
- **设计决策：** 学生在修改文件系统结构时，需要进行设计决策，考虑性能、空间利用和扩展性等方面的权衡。

**6.** **应用理论知识：**

- **理论与实践结合：** 学生通过将操作系统理论应用于实际项目，加深对理论知识的理解，并培养将理论知识转化为实际项目的能力。

**7.** **反馈与改进：**

- **接受反馈：** 学生在测试和调试阶段可能会收到反馈，从而学会接受和利用反馈来改进他们的代码。
- **项目迭代：** 学生有机会对系统调用和文件系统的功能进行迭代改进，提高代码质量和系统性能。

这个课程设计体验不仅提供了对操作系统和底层硬件的深入理解，还锻炼了学生的问题解决能力、团队协作能力和代码设计能力。