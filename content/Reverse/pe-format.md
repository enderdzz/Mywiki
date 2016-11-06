---
title: "逆向工程核心原理のPE文件格式"
date: 2016-10-04 22:03

---

[TOC]

本文摘录于：《逆向工程核心原理》

PE -> Portable Executable  (**未完待续**)

PE文件是Windows操作系统下使用的可执行文件格式。
它是微软在UNIX平台的COFF(common object file format, 通用对象文件格式)基础上制作而成的。这种文件仅使用于Win系列下。
PE文件是指32位的可执行文件，也称PE32, 64位的可执行文件称为PE+或PE32+, 是PE(PE32)文件的一种扩展形式。

|种类   |主扩展名|
|-------|--------|
|可执行系列|EXE、SCR|
|库系列|DLL、OCX、CPL、DRV|
|驱动程序系列|SYS、VXD|
|对象文件系列|OBJ|

严格来说，OBJ文件之外的所有文件都是可执行的。DLL，SYS文件不能在Shell(Explorer.exe)中运行，但也可以在调试或者服务中运行。

学习PE文件格式就是学习PE头中的结构体。
从DOS头(DOS header)到节区头(Section header)是PE头部分，其他节区合称PE体。文件中使用偏移(offest)，内存中使用VA(virtual address)来表示位置。文件加载到内存时，情况就会发生变化(节区的大小、位置等)。文件的内容可分为代码(.text)、数据(.data)、资源(.rsrc)节，分别保存。

注意：根据不同的开发工具与编译选项，节区名称、大小、个数、存储内容等都是不同的。
各个节区头定义了各节区在文件或内存中的大小、位置、属性等。
PE头与各节区的尾部存在一个区域，称为NULL填充

文件偏移<br>
00000000-----{ DOS头 <br>
00000004-----{ DOS存根<br>
000000E0-----{ NT头<br>
000001D8-----{ 节区头(".text")<br>
00000200-----{ 节区头(".data")<br>
00000228-----{ 节区头(".rsrc")<br>
|-----{ NULL<br>
00000400-----{ 节区(".text") size = 7800<br>
|-----{ NULL<br>
00007C00-----{ 节区(".data") size = 800<br>
|-----{ NULL<br>
00008400-----{ 节区(".rsrc") size = 8400<br>
|-----{ NULL<br>

然后上述文件加载到内存中后只有节区大小和全部位置都发生了变化，比如说内存中起始位置是01000000

## VA & RVA

RVA -> relative virtual address，相对虚拟地址，指的是从某个基准位置(ImageBase)开始的相对地址，RVA + ImageBase = VA

PE头内部信息大多以RVA形式存在，原因：PE文件（主要是DLL）加载到进程虚拟内存的特定位置时，需要重定位(Relocation)

注意：32bit WindowsOS中各进程分配有4GB的虚拟内存，因此**进程中VA值的范围是00000000~FFFFFFFF**

## Header

#### 0x01 DOS头

IMAGE_**DOS_HEADER**结构体是为了让PE文件对DOS文件兼容。它被添加到PE头的最前面，用来扩展已有的DOS EXE头

```c
typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;     // DOS signature : 4D5A("MZ")
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];   // 8bytes
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10]; // 20bytes
    LONG e_lfanew;   // offset to NT header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
// 出处：MicroSoft Platform SDK - winnt.h
// IMAGE_DOS_HEADER结构体的大小为0x40(64)字节。
```

该结构体必须知道2个重要的成员：

e_magic（DOS签名）,e_lfanew（指示NT头的偏移（根据不同文件拥有可变值））

|Offset(h)| 00 | 01 | 02 | 03 | 04 05 06...........0F|<br>
00000000  | 4D | 5A | 90 |

#### 0x02 DOS存根（stub）

该项为可选项，且大小不固定，它是由代码和数据混合而成。

文件偏移在40-4D区域为16位汇编指令，32位WindowsOS不会执行该指令（由于已经识别为PE文件，所以完全忽视该代码）

在DOS环境下运行EXE文件或者使用debug.exe（仅适用于WinXP环境）运行，
`debug xxx.exe`

按下u(unassemble)会出现16位的汇编指令。
可使其执行该代码（不认识PE文件格式所以被识别为DOS EXE）。
灵活使用该特性可以在一个可执行文件内创建出另外一个，它在DOS与Windows中都能运行（DOS是16位代码）。

#### 0x03 NT头（IMAGE_NT_HEADERS）

```c
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;     // PE Signature : 50450000("PE"00)
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
// 出处：MicroSoft Platform SDK - winnt.h
```

NT头大小为*0XF8*,大致由三个成员构成：

第一个成员为签名占四个字节，另外两个成员为文件头(File_header)与可选头(Optional_header)结构体

——————————<br>
|<br>
|<br>
\\.....文件头：<br>
```c
typedef struct _IMAGE_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDataStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
// 出处：MicroSoft Platform SDK - winnt.h
```

该结构体中有如下4种重要成员

+ Machine

每个CPU都有唯一的Machine码，兼容32位Intel x86芯片的Machine码为14C。

以下是定义在winnt.h文件中的Machine码：

```c
#define IMAGE_FILE_MACHINE_UNKNOWN   0
#define IMAGE_FILE_MACHINE_I386      0x014c //Intel 386.
#define IMAGE_FILE_MACHINE_R3000     0x0162 //MIPS little-endian, 0x160big-endian
#define IMAGE_FILE_MACHINE_R4000     0x0166 //MIPS little-endian
#define IMAGE_FILE_MACHINE_R10000    0x0168 //MIPS little-endian
#define IMAGE_FILE_MACHINE_WCEMIPSV2 0x0169 //MIPS little-endian WCE v2
#define IMAGE_FILE_MACHINE_ALPHA     0x0184 //Alpha_AXP
//.....
// 出处：MicroSoft Platform SDK - winnt.h
```

+ NumberOfSections

PE文件把代码、数据、资源等依据属性分类到各节区中存储。

这一项指示文件中存在的节区数量。该值一定要大于0，节区数与实际不符时时会发生运行错误。

+ SizeOfOptionalHeader

这一成员用来指出IMAGE_OPTIONAL_HEADER32结构体的长度，该结构体由C语言编写而成，故其大小已经确定，但是PE装载器需要查看IMAGE_FILE_HEADER的SizeOfOptionalHeader值，从而识别出来IMAGE_OPTIONAL_HEADER32结构体的大小。
PE32+格式的文件中使用的是IMAGE_OPTIONAL_HEADER64结构体，而不是IMAGE_OPTIONAL_HEADER32结构体。两个结构体的尺寸是不同的，所以需要在SizeOfOptionalHeader成员中明确指出结构体的大小。

提示：借助IMAGE_DOS_HEADER的e_lfanew成员与IMAGE_FILE_HEADER的SizeOfOptionalHeader成员，可以创建出一种脱离常规的PE文件(PE Patch)（也有人称之为“麻花”PE文件）

+ Characteristics

该字段用来标识文件的属性，文件是否是可运行状态，是否为DLL文件等信息。以bit OR形式组合起来。
以下是定义在winnt.h文件中的Characteristics值(**请记住0002h与2000h这两个值**)

```c
#define IMAGE_FILE_RELOCS_STRIPPED     0x0001 //Relocation info stripped from file.
#define IMAEG_FILE_EXECUTABLE_IMAGE    0x0002 //File is executable
#define IMAGE_FILE_LINE_NUMS_STRIPPED  0x0004 //Line numbers stripped from file.
//......
#define IMAGE_FILE_DLL                 0x2000 //File is a DLL.
//......
// 出处：MicroSoft Platform SDK - winnt.h
```

另外，PE文件中的Characteristics的值有可能不是0002h吗(不可执行)？是的，确实存在这种情况，比如类似*.obj的object文件及resource DLL文件等。

IMAGE_FILE_HEADER的TimeDataStamp成员。该成员的值不影响文件运行，用来记录编辑器创建此文件的时间。

——————————<br>
|<br>
|<br>
\\.....可选头：<br>
IMAGE_OPTIONAL_HEADER32是PE头结构体中最大的。

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES  16
typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DOWRD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
// 出处：MicroSoft Platform SDK - winnt.h
```

在该结构体中我们需要注意如下成员(这些值是文件运行必需的，设置错误将导致文件无法正常运行):

1、 Magic

为IMAGE_OPTIONAL_HEADER32结构体时，Magic码为10B；为IMAGE_OPTIONAL_HEADER64结构体时，Magic码为20B。

2、 AddressOfEntryPoint

AddressOfEntryPoint持有EP的RVA值。该值指出了程序最先执行的代码起始地址，**Very Important！！**

3、 ImageBase

进程虚拟内存的范围为0~FFFFFFFF(32位系统)。PE文件被加载在如此大的内存中时，ImageBase指出文件的优先装入地址。

EXE，DLL文件被装载到用户内存的0~7FFFFFFF中，SYS文件被载入到内核内存中80000000~FFFFFFFF。

一般而言，使用开发工具(VB/VC++/Delphi)创建好EXE文件后，其ImageBase的值为00400000，DLL文件的ImageBase值为10000000(当然也可以指定为其他值)，执行PE文件时，PE装载器先创建进程，再将文件载入内存，然后把EIP寄存器的值设为ImageBase+AddressOfEntryPoint.

4、 SectionAlignment, FileAlignment

PE文件的Body部分划分为若干节区，这些节存储着不同类别的数据。FileAlignment指定了节区在磁盘文件中的最小单位，而SectionAlignment则指定了节区在内存中的最小单位(一个文件中，FileAlignment与SectionAlignment的值可能相同，也可能不同)。磁盘文件或内存的节区大小必定为FileAlignment或SectionAlig
nment值的整数倍。

5、 SizeOfImage

加载PE文件到内存时，SizeOfImage指定了PE Image在虚拟内存中所占空间的大小。一般而言，文件的大小与加载到内存中的大小是不同的。

6、 SizeOfHeader

这个成员指出了整个PE头的大小，该值也必须是FileAlignment的整数倍。第一节区所在位置与SizeOfHeader距文件开始偏移的量相同。

7、 Subsystem

该Subsystem值用来区分系统驱动文件（\*.sys）与普通的可执行文件（\*.exe,\*.dll）。Subsystem成员可拥有的值如下表所示：

|值|含义|备注|
|----|----|----|
|1|Driver文件|系统驱动（如：ntfs.sys）|
|2|GUI文件|窗口应用程序（如：notepad.exe）|
|3|CUI文件|控制台应用程序（如:cmd.exe）|

8、 NumberOfRvaAndSize

这个成员用来指定DataDirectory（IMAGE_OPTIONAL_HEADER32结构体的最后一个成员）数组的个数。虽然结构体定义中明确指出了数组个数为IMAGE_NUMBEROF_DIRECTORY_ENTRIES(16)，但是PE装载器通过查看NumberOfRvaAndSizes值来识别数组的大小，换言之，数组大小也可能不是16.

9、 DataDirectory

它是由IMAGE_DATA_DIRECTORY结构体组成的数组，数组的每项都有被定义的值。下面列出了各个数组项：

```c
DataDirectory[0] = EXPORT Directory
DataDirectory[1] = IMPORT Directory
DataDirectory[2] = RESOURCE Directory
//......
DataDirectory[9] = TLS Directory
//......
DataDirectory[F] = Reserved Directory
```

将此处所说的Directory想成某个结构体数组即可。重点关注EXPORT/IMPORT/RESOURCE/TLS Directory。EXPORT/IMPORT Directory是PE头中非常重要的部分。

#### 0x04 节区头

这一头部定义了各节区属性。原文作者认为把PE文件创建成多个节区结构的好处是保证程序的安全性。

假如向字符串data写数据时，由于某个原因导致导致溢出（输入超过缓存区大小时），那么其下的code(指令)就会被覆盖，应用程序就会崩溃。因此PE文件格式的设计者们决定把具有相似属性的数据同一保存在一个称之为“节区”的地方，然后需要把各节区属性记录在节区头中（节区属性中有文件/内存的起始位置、大小、访问权限等）。

|类别|访问权限|
|----|----|
|code|执行，读取权限|
|data|非执行，读写权限|
|resource|非执行，读取权限|

IMAGE_SECTION_HEADER
节区头是由IMAGE_SECTION_HEADER结构体组成的数组，每个结构体对应一个节区。

```c
#define IMAGE_SIZEOF_SHORT_NAME
typedef struct _IMAGE_SECTION_HEADER {
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
// 出处：MicroSoft Platform SDK - winnt.h
```

重要成员有：

|项目|含义|
|---|----|
|VirtualSize|内存中节区所占大小|
|VirtualAddress|内存中节区起始地址(RVA)|
|SizeOfRawData|磁盘文件中节区所占大小|
|PointerToRawData|磁盘文件中节区起始地址|
|Characteristics|节区属性(bit OR)|

VirtualAddress与PointerToRawData不带有任何值，分别由（定义在IMAGE_OPTIONAL_HEADER32中的）SectionAlignment与FileAlignment确定。

VirtualSize与SizeOfRawData一般具有不同的值，即磁盘文件中节区的大小与加载到内存中的节区大小是不同的。
Characteristics由下列可能值组合(bit OR)而成：

```c
#define IMAGE_SCN_CNT_CODE      0x00000020 //Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED  0x00000040 //Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED 0x00000080 //Section contains uninitialized data.
#define IMAGE_SCN_MEM_EXECUTE   0x20000000 //Section is executable.
#define IMAGE_SCN_MEM_READ      0x40000000 //Section is readable.
#define IMAGE_SCN_MEM_WRITE     0x80000000 //Section is writable.
// 出处：MicroSoft Platform SDK - winnt.h
```

最后是Name字段，Name成员不像C语言中的字符串一样以NULL结束，并且没有“必须使用ASCII值”的限制。PE规范未明确规定节区的Name，所以可以向其放入任何值，甚至可以填充NULL值。所以节区的Name仅供参考，不能保证其百分之百地被用作某种信息（数据节区的名称也可叫做.code）。

Tips:讲解PE文件时经常出现“映像”（Image）这一术语。磁盘文件中PE与内存中的PE具有不同形态。

## RVA to RAW

PE文件加载到内存时，每个节区都要能准确完成内存地址与文件偏移的映射，这种映射一般称为RVA ot RAW.
方法是：

1）查找RVA所在的节区；

2）使用简单的公式计算文件偏移（RAW）

$$RAW - PointerToRawData = RVA - VirtualAddress$$
$$RAW = RVA - VirtualAdress + PointerToRawData$$

但是由于有时某些节区的VirtualSize值比SizeOfRawData值大，此时若再计算Raw可能超出该节区的范围，处于无法定义的状态。

至于为什么VirtualSize & SizeOfRawData两个值不一定相等后续会讲到...

## IAT(Import Address Table，导入地址表)

IAT的内容与Win OS的核心进程、内存、DLL结构等有关。

简言之，IAT是一种表格，用来记录程序正在使用哪些库中的哪些函数。

#### DLL(Dynamic Linked Library)

它支撑起了整个WinOS大厦。

16位的DOS时代不存在DLL这一概念，只有“库”的说法。

到了32位机后才引入这一概念，描述如下：

1. 不要把库包含在程序中，单独组成DLL文件，需要时调用即可。
2. 内存映射技术使加载后的DLL代码、资源在多个进程中实现共享。
3. 更新库时只要替换相关DLL文件即可，简便易行。

加载DLL的方式有两种：一种是“显式链接”（Explicit Linking），程序使用DLL时加载，使用完毕后释放内存；另一种是“隐式链接”（Implicit Linking），程序开始时即一同加载DLL，程序终止时再释放占用的内存。IAT提供的机制即与隐式链接有关。使用OD可以查看PE文件中的IAT. e.g. kernel32.CreateFileW()便在kernel32.dll中

调用CreateFileW()函数时并非直接调用，而是通过获取01001104（`CALL DWORD PTR DS:[1001104]`）地址处的值来实现（所有API调用均采用这种方式）。

地址01001104是notepad.exe中`.text`节区的内存区域（更确切来说是IAT的内存区域）。01001104地址的值为7C8107F0，而7C8107F0地址即是加载到notepad.exe进程内存中的CreateFileW()函数的地址。。。。

那为何不直接`CALL 7C8107F0`呢？
In fact，notepad.exe程序的制作者编译程序时，并不知道该notepad.exe程序要运行在哪种Win（9X、2K、XP、Vista、7）、哪种语言（ENG、JPN、KOR）、哪种服务包（Service Pack）下。为了确保在所有环境中都能正常的调用CreateFileW()函数，编译器准备了要保存CreateFileW()函数实际地址的位置(01001104)，并仅记下`CALL DWORD PTR DS:[1001104]`形式的指令。执行文件时，PE装载器将CreateFileW()函数的地址写到01001104位置。

编译器不用`CALL 7C8107F0`语句的另一个原因在于DLL重定位。DLL文件的ImageBase值一般为10000000。比如某个程序使用a.dll与b.dll时，PE装载器先把a.dll装载到内存的10000000（ImageBase）处，然后尝试把b.dll也装载到此处，但是由于该地址处已经装载了a.dll所以PE装载器查找其他空白的内存空间(e.g. 3E000000)，进行装载。

这就是所谓的DLL重定位，它使我们无法对实际地址硬编码。另一个原因在于，PE头中表示地址时不使用VA，而是RVA。
实际操作中无法保证DLL一定会被加载到PE头内指定的ImageBase处，但是EXE文件(生成进程的主体)却能准确加载到自身的ImageBase中，因为它拥有自己的虚拟空间。

#### IMAGE_IMPORT_DESCRIPTOR

这一结构体中记录着PE文件要导入哪些库文件。

> Import:导入，向库提供服务（函数）。<br>
Export：导出，从库向其他PE文件提供服务（函数）。

```c
typedef struct _IMAGE_IMPORT_DESCRIPOTR {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk; //INT(Import Name Table) address(RVA)
    };
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name; //library name string address (RVA)
    DWORD FirstThunk; //IAT(Import Address Table) address(RVA)
} IMAGE_IMPORT_DESCRIPOTR;

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD Hint; //ordinal
    BYTE Name[1]; //function name string
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
// 出处：MicroSoft Platform SDK - winnt.h
```

执行一个普通程序时往往需要导入多个库，导入多少个库就存在多少个IMAGE_IMPORT_DESCRIPOTR结构体，这些结构体形成了数组，且结构体数组最后以NULL结构体结束。

该结构体中重要成员如下:

|项目|含义|
|----|----|
|OriginalFirstThunk|INT的地址(RVA)|
|Name|库名称字符串的地址(RVA)|
|FirstThunk|IAT地址(RVA)|

> Tips:PE头中提到的“Table”即指数组。<br>
INT与IAT是长整形（4个字节数据类型）数组，以NULL结束（未另外明确指出大小）<br>
INT中各元素的值为IMAGE_IMPORT_BY_NAME结构体指针（有时IAT也拥有相同的值）<br>
INT与IAT的大小应相同

PE装载器把导入函数输入到IAT的顺序：

1. 读取IID的Name成员，获取库名称字符串（"kernel32.dll"）;
2. 装载相应的库（->LoadLibrary("kernel32.dll")）;
3. 读取IID的OriginalFirstThunk成员，获取INT地址;
4. 逐一读取INT中数组的值，获取相应IMAGE_IMPORT_BY_NAME地址（RVA）;
5. 使用IMAGE_IMPORT_BY_NAME的Hint(Ordinal)或Name项，获取相应函数的起始地址;
6. 读取IID的FirstThunk(IAT)成员，获得IAT地址;
7. 将上面获得的函数地址输入相应IAT数组值;
8. 重复以上步骤4~7，直到INT结束（遇到NULL时）

IMAGE_IMPORT_DESCRIPOTR结构体数组存放于PE体中，但是查询其位置的信息却在PE头中，IMAGE_OPTIONAL_HEADER32.DataDirectory[1].VirtualAddress的值即是该结构体数组的起始地址(RVA值)。IMAGE_IMPORT_DESCRIPOTR结构体数组也被称为IMPORT Directory Table。

这一块内容由于笔者能力较难以文字形式表述出来，上手实践绝对是一个不错的选择，在实践的过程中，注意之前讲到的`RVA->RAW`,尝试一下如何找到以下四个变量存储的内容，分别是

+ `Name`
+ `OriginalFirstThunk - INT`
+ `IMAGE_IMPORT_BY_NAME`
+ `FirstThunk - IAT`

> 微软在制作服务包过程中重建相关系统文件，此时会硬编入准确地址（普通的DLL实际地址不会被硬编码到IAT中，通常带有与INT相同的值）
另外，普通DLL文件的ImageBase为10000000，所以经常会发生DLL重定位。但是Windows系统DLL文件（kernel32/user32/gdi32等）拥有自身固有的ImageBase，不会出现DLL重定位。

## EAT(Export Address Table，导出地址表)

EAT是一种核心的机制，它使不同的应用程序可以调用库文件中提供的函数。也就是说，只有通过EAT才能准确求得从相应库中导出函数的起始地址，而且PE文件中仅有一个用来说明库EAT的IMAGE_EXPORT_DIRECTORY结构体，但是用来说明IAT的IMAGE_IMPORT_DESCRIPTOR结构体以数组形式存在，且拥有多个成员。

`&IMAGE_EXPORT_DIRECTORY <=> IMAGE_OPTIONAL_HEADER32.DataDirectory[0].VA`

#### IMAGE_EXPORT_DIRECTORY

```
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
// 出处：MicroSoft Platform SDK - winnt.h
```
从库中获得函数地址的API为GetProcAddress()函数。该API引用EAT来获取指定API的地址。GetProcAddress() API拥有函数名称，下面讲解它如何获取函数地址。理解了这一过程，就等于征服了EAT。

1. 利用AddressOfNames 成员转到“函数名称数组”。
2. “函数名称数组”中存储着字符串地址，通过比较(strcmp)字符串，查找指定的函数名称(此时数组的索引称为name_index)。
3. 利用AddressOfNameOrdinals成员的，转到ordinal数组。
4. 在ordinal数组中通过name_index查找相应ordinal值。
5. 利用AddressOfFunctions成员转到“函数地址数组”（EAT）。
6. 在“函数地址数组”中将刚刚求得的ordinal用作数组索引，获得指定函数的起始地址。
