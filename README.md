# ELF-tracker

## 项目简介

ELF-tracker 不是一个现成可落地的生产级安全产品，而是一个基于 DynamoRIO 的运行时防护实验项目。它的定位更接近：

- 一个用于课程、毕设或安全实验的原型系统
- 一个用于验证运行时控制流保护思路是否有效的研究性项目
- 一个用于演示 `shadow stack`、`CFI` 和动态学习型 `CSCFI` 的教学样例

它想解决的问题很具体：当一个 ELF 程序存在内存破坏漏洞时，攻击者往往不会满足于“把数据写坏”，而是会进一步劫持程序的控制流，让程序跳到攻击者希望执行的位置。

最典型的例子是缓冲区溢出。比如一个函数在栈上申请了一个固定大小的缓冲区，但读入数据时没有做边界检查，那么攻击者就可能继续覆盖：

- 返回地址
- 保存的栈帧指针
- 栈上函数指针
- 传给共享库的回调函数指针

一旦这些关键控制数据被改写，程序原本应该执行的控制流就会被重定向。轻则程序崩溃，重则攻击者可以借此拼接 gadget、调用危险函数，最终拿到 shell、读文件或执行任意代码。

## 项目定位

这个项目是一个“实验性运行时控制流保护原型”，不是生产工具。

这样定义它更准确，原因有两点：

- 它的目标是验证防护机制本身是否能拦住若干类真实的控制流劫持，而不是提供工业级、全场景、低误报、低开销的完整解决方案。
- 它采用的是基于 DBI 的动态插桩方案，这种方案很适合原型验证、快速试验和防护思路对比，但通常不如编译期方案那样适合直接大规模上线。

所以更准确地说，ELF-tracker 解决的是下面这个研究问题：

“在不重新编译目标程序源码的前提下，能否通过运行时插桩，检测并阻断几类典型的控制流劫持行为？”

当前版本聚焦的就是这三类情况：

- 返回地址覆盖
- 主程序内部的间接 `call` 劫持
- 共享库内部的间接 `call` / `jmp` 目标劫持

## 为什么需要这种方案

传统内存破坏漏洞的防御手段很多，但各有局限。

例如：

- 栈 canary 主要用于发现部分栈溢出，但它主要保护的是“返回前检测栈尾标记是否被改坏”，并不能直接约束所有函数指针或间接跳转目标。
- NX / DEP 可以阻止直接执行注入的 shellcode，但无法阻止攻击者重用程序里原本就存在的合法代码片段。
- ASLR 可以增加定位代码地址的难度，但信息泄露一旦存在，ASLR 的效果就会明显下降。
- 编译期 CFI 很强，但它依赖重新编译目标程序，现实里对闭源程序、已有 ELF 二进制或临时验证场景并不总是方便。

这个项目的出发点就是：如果目标是“对现成 ELF 程序做实验性运行时保护”，那么 DBI 是一个很合适的载体，因为它可以在程序运行时观察并修改控制流，不需要改目标源码，也不需要把整个程序迁移到特定编译链上。

## 这个项目用了哪些技术

### 1. DBI：动态二进制插桩

DBI，Dynamic Binary Instrumentation，动态二进制插桩，可以理解成：

- 不改原始 ELF 文件
- 在程序执行时拦截指令流
- 在关键位置自动插入我们自己的检查逻辑

这个项目使用的是 DynamoRIO。它负责把目标程序放到自己的运行时框架里执行，然后在 `call`、`ret`、间接 `jmp` 等关键控制流指令附近插入额外代码。

对这个项目来说，DynamoRIO 的价值在于：

- 可以观察目标程序的控制流行为
- 可以在运行时为每一次关键跳转做校验
- 可以把“训练”和“防护”做成两个独立 client，便于实验

### 2. Shadow Stack：保护返回地址

影子栈可以理解成“额外维护一份只给防护逻辑使用的返回地址栈”。

正常情况下，函数调用和返回应该满足：

- 执行 `call` 时，真实返回地址被压到应用栈上
- 执行 `ret` 时，程序应该回到刚才那条返回地址

问题在于，应用栈是攻击者可能覆盖到的。  
如果攻击者通过缓冲区溢出改掉了栈上的返回地址，那么 `ret` 就会跳去错误的位置。

这个项目的做法是：

- 每次执行 `call` 时，把预期返回地址同时记录到 shadow stack
- 每次执行 `ret` 时，用真实返回地址和 shadow stack 栈顶做严格比对
- 如果两者不一致，就认为返回流程已经被劫持，直接终止进程

因此，shadow stack 主要解决的是：

- 返回地址覆盖
- ret2libc / ROP 这类依赖篡改返回地址的利用链基础步骤

### 3. CFI：控制流完整性检查

CFI，Control-Flow Integrity，控制流完整性，核心思想是：

“程序不是不能跳转，而是只能跳到合法的位置。”

对这个项目来说，重点不是限制所有直接 `call`，而是关注更危险的几类控制流：

- 间接 `call`
- 间接 `jmp`

因为这两类跳转的目标不是写死在指令里的，而是从寄存器或内存中取出来的，所以一旦相关数据被攻击者改写，就很容易把控制流导向错误的函数或错误的代码片段。

当前实现里的基础 CFI 会检查：

- 目标地址是否存在
- 目标地址是否位于可执行内存
- 目标地址是否属于已加载模块

如果目标连最基本的“可执行代码地址”都不是，那么就直接判定为非法控制流。

### 4. IBT / ENDBR：配合硬件风格的间接分支入口约束

在支持 CET/IBT 风格入口标记的代码里，合法的间接跳转目标通常应该落在 `ENDBR` 指令开头。

这个项目会在运行时检查：

- 某个模块是否表现出启用了 IBT 风格入口的特征
- 如果启用了，那么间接控制流的目标是否真的落在合法入口上

它的作用是进一步减少“跳进函数中间”这种利用方式。

### 5. CSCFI：带上下文的动态学习型控制流约束

单纯的 CFI 只能回答一个较粗的问题：

“这个目标地址像不像一段合法代码？”

但在真实攻击里，这还不够。  
因为攻击者完全可能把控制流跳到“另一段也合法、也可执行、也在模块里”的函数上，只是那个函数原本不应该从当前调用点跳过去。

所以这个项目额外实现了 CSCFI。可以把它理解成：

- 不只检查“目标是不是代码”
- 还检查“这个调用点，是否见过跳到这个目标”

具体做法分成两个阶段。

训练阶段：

- 在目标程序正常运行时，记录合法的间接控制流边
- 每条边由 `(callsite / jump-site, target)` 组成
- 这些边会被写入策略文件

防护阶段：

- 当程序再次运行时，如果出现新的 `(site, target)` 配对
- 且这个配对不在训练得到的策略文件里
- 就认为发生了异常控制流劫持，直接拦截

这也是为什么这个项目里有两个入口：

- `[train]`：先学习合法边
- `[ELF_Tracker]`：再加载策略做防护

### 6. main / strong 两种模式

为了权衡实验成本和检查范围，这个项目提供了两种策略范围：

- `main`
  重点保护主程序模块里的相关间接控制流。它更适合先验证“主程序内的函数指针劫持能不能被发现”。
- `strong`
  把共享库里的相关间接控制流也纳入更严格的 CSCFI 检查。它更适合验证“libc 内部间接调用目标被改写时能不能发现”。

换句话说，`main` 更偏“先把主程序本体管住”，`strong` 更偏“把跨模块与共享库路径也一起纳入控制”。

## 这个项目目前能做到什么

当前版本主要证明三件事：

- 影子栈可以拦截返回地址覆盖
- 基于运行时学习的控制流配对检查，可以拦截主程序内函数指针劫持
- 在更严格的模式下，也可以拦截共享库内部的间接调用目标劫持

但它也明确有边界：

- 它不是一个通用、生产级、全自动部署的 CFI 产品
- 它不是编译器级别的完整类型安全 CFI
- 它更关注“验证若干关键防护机制是否有效”，而不是穷尽所有攻击面

如果用一句话概括它，更准确的表述是：

“一个基于 DBI 的实验性运行时控制流保护原型，用于验证 shadow stack 与动态学习型 CSCFI 对 ELF 控制流劫持的检测效果。”


## 目录结构

- `[train]`：训练入口
- `[ELF_Tracker]`：防护入口
- `[install.sh]`：安装软链接脚本
- `[policy/default.policy]`：默认策略文件
- `[policy/poc.policy]`：`poc` 样例策略
- `[core/train.c]`：训练 client
- `[core/shadow_stack.c]`：防护 client
- `[poc_source/test.c]`：返回地址覆盖样例
- `[poc_source/poc.c]`：主程序函数指针劫持样例
- `[poc_source/poc2.c]`：libc `qsort` 比较器劫持样例
- `[poc_source/third_party/poc.py]`：`poc` 攻击脚本
- `[poc_source/third_party/poc2.py]`：`poc2` 攻击脚本
- `[poc_source/third_party/poc2_validate]`：`poc2` 一键验证脚本

## 环境要求

- Linux x86-64
- `bash`
- `gcc`
- Python 3
- 运行攻击脚本时需要 `pwntools`

默认使用仓库内置的 `[dynamorio-min]`。

如果要切换到你自己的 DynamoRIO 安装，设置：

```bash
export ET_DYNAMORIO_DIR=/path/to/DynamoRIO
```

## 安装方式

如果你希望在任意目录直接调用 `train` 和 `ELF_Tracker`，运行：

```bash
./install.sh
```

默认会创建：

```text
~/.local/bin/train
~/.local/bin/ELF_Tracker
```

如果要自定义安装目录：

```bash
./install.sh /tmp/elf-tracker-bin
```

如果该目录不在 `PATH` 中，加入：

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## 重新编译 PoC

仓库根目录当前保留的可执行样例有：

- `[poc]`
- `[test.out]`

如果你要重编：

```bash
gcc -O0 -g -fno-stack-protector -fno-omit-frame-pointer -fcf-protection=branch \
    poc_source/test.c -o test.out

gcc -O0 -g -fno-stack-protector -no-pie -fcf-protection=branch \
    poc_source/poc.c -o poc

gcc -O0 -g -fno-stack-protector -no-pie -fcf-protection=branch \
    poc_source/poc2.c -o poc2
```

## 使用方法

三个入口脚本都支持 `--help`：

```bash
./train --help
./ELF_Tracker --help
./install.sh --help
```

### 1. 训练策略

`train` 不再默认指定目标程序。必须显式传入目标文件：

```bash
./train <target-binary> [target-args...]
```

例如：

```bash
./train ./poc
./train ./test.out
./train ./poc2
```

默认策略输出位置是：

```text
./policy/default.policy
```

如果你想为某个样例单独生成策略：

```bash
./train --policy ./policy/poc.policy ./poc
./train --policy ./policy/poc2.policy ./poc2
```

如果要固定哈希种子：

```bash
./train --seed 0x1337 --policy ./policy/poc2.policy ./poc2
```

### 2. 启动防护

`ELF_Tracker` 也不再默认指定目标程序。必须显式传入目标文件：

```bash
./ELF_Tracker <target-binary> [target-args...]
```

默认防护模式是 `main`：

```bash
./ELF_Tracker ./poc
./ELF_Tracker ./test.out
./ELF_Tracker ./poc2
```

切换到 `strong`：

```bash
./ELF_Tracker --strong ./poc2
```

如果要显式指定策略文件：

```bash
./ELF_Tracker --policy ./policy/poc.policy ./poc
./ELF_Tracker --strong --policy ./policy/poc2.policy ./poc2
```

如果你更习惯环境变量写法，旧方式仍然兼容：

```bash
ET_CSCFI_POLICY=./policy/poc.policy ./train ./poc
ET_CSCFI_POLICY=./policy/poc2.policy ET_CSCFI_ENFORCE_MODE=strong ./ELF_Tracker ./poc2
```

## 防护模式

- `main`
  只对主程序模块中的相关间接控制流做更严格的 CSCFI 检查。共享库路径主要依赖基础 CFI / IBT 约束。
- `strong`
  主程序和共享库中的相关间接控制流都纳入更严格的 CSCFI 检查。

两种模式下，`shadow stack` 都保持开启。

## 三个 PoC 的效果

### 1. `test.out`：返回地址覆盖

源码：

- `[poc_source/test.c](/home/sally/ELF-tracker/source/poc_source/test.c)`

这个样例验证的是返回地址破坏，因此重点由 `shadow stack` 覆盖。

无保护时：

- 溢出会直接影响返回流程
- 不会有运行时控制流校验阻断

启用防护后：

```bash
./ELF_Tracker ./test.out
```

预期效果：

- 返回地址异常时，`shadow stack` 会在返回点发现不一致并终止程序

### 2. `poc`：主程序内函数指针劫持

源码：

- `[poc_source/poc.c]`

攻击逻辑：

- 栈上有 `char buf[24]`
- 后面紧跟函数指针 `f`
- 溢出后可把 `f` 从 `safe` 改成 `evil`
- 最后执行一次间接 `call`

无保护时：

```bash
./poc
```

攻击者把函数指针改成 `evil` 后，会看到：

```text
input:
evil()
```

训练并启用防护：

```bash
./train --policy ./policy/poc.policy ./poc
./ELF_Tracker --policy ./policy/poc.policy ./poc
```

或者直接用攻击脚本：

```bash
python3 ./poc_source/third_party/poc.py
```

预期效果：

- 训练阶段会学到该间接 `call` 的合法目标是 `safe`
- 攻击改写为 `evil` 后，会报 `[cscfi] mismatch`
- 这个样例在 `main` 模式下就应该被拦住

### 3. `poc2`：libc 内部间接调用目标劫持

源码：

- `[poc_source/poc2.c]`

攻击逻辑：

- 程序把比较器函数指针传给 `qsort`
- 溢出只改写比较器指针
- 返回地址本身不变
- 真正被劫持的是 libc 内部触发的间接调用目标

训练：

```bash
./train --policy ./policy/poc2.policy ./poc2
```

运行效果：

```bash
./ELF_Tracker --policy ./policy/poc2.policy --main ./poc2
./ELF_Tracker --policy ./policy/poc2.policy --strong ./poc2
```

预期差异：

- `main` 模式下，这类 libc 内部路径通常不会被严格拦截
- `strong` 模式下，会因为不合法的 `(callsite, target)` 配对触发 `[cscfi] mismatch`

一键验证脚本：

```bash
./poc_source/third_party/poc2_validate
```

## 开销数据

这里保留的是你最后确认要看的口径：

- 单次平均运行时间
- 测的是 PoC 程序本身
- 不是 200 次总时间
- 不是 benchmark 内部单次调用均摊时间

测试目标：

- `[poc]`

测试模式：

- `empty`
- `drrun`
- `main`
- `full`

每种模式各跑 `10` 次，统计单次墙钟平均值：

| 模式 | 单次平均运行时间 |
|---|---:|
| `empty` | `0.006 s` |
| `drrun` | `0.013 s` |
| `main` | `0.035 s` |
| `full` | `0.034 s` |

相对损耗：

- `drrun` 相对 `empty`：`2.17x`
- `main` 相对 `empty`：`5.83x`
- `full` 相对 `empty`：`5.67x`
- `main` 相对 `drrun`：`2.65x`
- `full` 相对 `drrun`：`2.61x`
