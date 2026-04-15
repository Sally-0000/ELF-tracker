# ELF-tracker

## 项目简介

这是一个基于 DynamoRIO 的 ELF 运行时防护实验项目，目标是验证以下两类控制流保护能力：

- `shadow stack`：记录 `call/ret` 配对，检测返回地址被覆盖后的异常返回。
- `CFI / CSCFI`：对间接控制流目标做运行时校验。
  - 基础层：目标必须落在有效可执行区域内。
  - IBT 兼容层：如果目标模块启用了 ENDBR，目标入口也必须满足 ENDBR。
  - CSCFI 层：对间接 `call` 的 `(call site offset, target offset)` 对进行训练和匹配。

项目里有两个 DynamoRIO client：

- `[train.c](/home/sally/ELF-tracker/source/core/train.c)`：训练阶段收集合法间接调用目标，并写入策略文件。
- `[shadow_stack.c](/home/sally/ELF-tracker/source/core/shadow_stack.c)`：防护阶段执行 shadow stack 校验和 CFI / CSCFI 校验。

当前脚本默认使用项目内自带的最小化 DynamoRIO 运行集：

- `[dynamorio-min](/home/sally/ELF-tracker/source/dynamorio-min)`

如果你想切回别的 DynamoRIO 安装，可以通过环境变量 `ET_DYNAMORIO_DIR` 覆盖。

## 目录说明

- `[train](/home/sally/ELF-tracker/source/train)`：编译并运行训练 client。
- `[protect](/home/sally/ELF-tracker/source/protect)`：编译并运行防护 client。
- `[core/cscfi_offsets.policy](/home/sally/ELF-tracker/source/core/cscfi_offsets.policy)`：默认策略文件。
- `[poc_source/test.c](/home/sally/ELF-tracker/source/poc_source/test.c)`：返回地址覆盖样例。
- `[poc_source/poc.c](/home/sally/ELF-tracker/source/poc_source/poc.c)`：主程序内函数指针劫持样例。
- `[core/poc2.c](/home/sally/ELF-tracker/source/core/poc2.c)`：libc 内部间接调用目标劫持样例。
- `[core/poc.py](/home/sally/ELF-tracker/source/core/poc.py)`：`poc` 的攻击脚本。
- `[core/poc2.py](/home/sally/ELF-tracker/source/core/poc2.py)`：`poc2` 的攻击脚本。
- `[poc2_validate](/home/sally/ELF-tracker/source/poc2_validate)`：`poc2` 的一键训练与验证脚本。

## 防护模式

防护端通过 `ET_CSCFI_ENFORCE_MODE` 控制 CSCFI 范围：

- `main`
  - 只对主程序模块里的间接 `call` 做 CSCFI 配对检查。
  - 共享库里的间接 `call` 只做基础 CFI / IBT 检查，不做 callsite-target 对匹配。
- `strong`
  - 主程序和共享库里的间接 `call` 都做 CSCFI 配对检查。

两种模式下，`shadow stack` 都是开启的。

## 依赖与构建

### 依赖

- Linux x86-64
- `gcc`
- `bash`
- Python 3
- 如果要运行攻击脚本：`pwntools`

### 构建样例程序

当前仓库里已经有编译好的 `[test.out](/home/sally/ELF-tracker/source/test.out)`、`[poc](/home/sally/ELF-tracker/source/poc)`、`[poc2](/home/sally/ELF-tracker/source/poc2)`。

如果需要重新编译，可以参考：

```bash
gcc -O0 -g -fno-stack-protector -fno-omit-frame-pointer -fcf-protection=branch \
    poc_source/test.c -o test.out

gcc -O0 -g -fno-stack-protector -no-pie -fcf-protection=branch \
    poc_source/poc.c -o poc

gcc -O0 -g -fno-stack-protector -no-pie -fcf-protection=branch \
    core/poc2.c -o poc2
```

## 使用方法

### 1. 训练策略

对目标程序先跑一遍训练阶段，生成合法的间接调用目标集合：

```bash
./train ./poc
./train ./poc2
./train ./test.out
```

如果想单独指定策略文件：

```bash
ET_CSCFI_POLICY=./core/poc2.policy ./train ./poc2
```

如果想指定哈希种子：

```bash
ET_CSCFI_SEED=0x1337 ET_CSCFI_POLICY=./core/poc2.policy ./train ./poc2
```

### 2. 运行防护

默认是 `main-only` 模式：

```bash
./protect ./poc
./protect ./poc2
./protect ./test.out
```

切到 `strong` 模式：

```bash
ET_CSCFI_ENFORCE_MODE=strong ./protect ./poc2
```

也可以同时指定策略文件：

```bash
ET_CSCFI_POLICY=./core/poc2.policy ET_CSCFI_ENFORCE_MODE=strong ./protect ./poc2
```

### 3. 切换 DynamoRIO 路径

默认使用项目内最小运行集。如果想改用别的 DynamoRIO 目录：

```bash
ET_DYNAMORIO_DIR=/path/to/DynamoRIO ./train ./poc2
ET_DYNAMORIO_DIR=/path/to/DynamoRIO ./protect ./poc2
```

## 三个样例的效果

### 1. `test`：返回地址覆盖

源码：`[poc_source/test.c](/home/sally/ELF-tracker/source/poc_source/test.c)`

程序逻辑：

- `vuln()` 里有 `char buf[128]`
- 使用 `read(0, buf, 256)` 造成经典栈溢出
- 函数返回后回到 `main()`，再打印 `"Hello, World!"`

这个样例的重点不是间接 `call`，而是返回地址完整性。

#### 不加保护

- 程序不会做返回地址校验。
- 如果输入没有精确覆盖到可利用的返回地址，程序可能仍然正常打印 `Hello, World!`。
- 如果构造了有效的返回地址覆盖，理论上可以劫持控制流。

#### 加保护

- `shadow stack` 会记录每次 `call` 的返回地址。
- 当 `ret` 实际跳转地址与 shadow stack 期望值不一致时，防护端会报：

```text
[shadow-stack] mismatch tid=... expected=... actual=...
```

- 进程随后退出。

#### 结论

- `test` 用来验证 `shadow stack` 对返回地址覆盖的检测能力。
- 这个样例不是 `main-only` 和 `strong` 的差异点，两种模式下它的核心防护都来自 `shadow stack`。

### 2. `poc`：主程序内函数指针劫持

源码：`[poc_source/poc.c](/home/sally/ELF-tracker/source/poc_source/poc.c)`

程序逻辑：

- 栈上结构体包含：
  - `char buf[24]`
  - 函数指针 `f`
- 初始时 `f = safe`
- 溢出后可以把 `f` 改成 `evil`
- 最后执行 `frame.f()`

攻击脚本：`[core/poc.py](/home/sally/ELF-tracker/source/core/poc.py)`

#### 不加保护

- 覆盖函数指针后，程序会从 `safe()` 变成执行 `evil()``
- 典型现象是输出：

```text
input:
evil()
```

#### 加保护前先训练

先用正常输入训练一次：

```bash
ET_CSCFI_POLICY=./core/poc.policy ./train ./poc
```

训练时程序会学习到：

- 主程序内这个间接 `call` 的合法目标是 `safe`

#### `main-only` 模式

- 由于攻击点就在主程序里的间接 `call`
- `main-only` 会对这个 call site 做 CSCFI 匹配
- 将函数指针改到 `evil` 后，会触发：

```text
[cscfi] mismatch tid=... site=... target=...
```

#### `strong` 模式

- 同样会拦截
- 因为它包含了 `main-only` 的全部能力，只是把共享库里的间接 `call` 也纳入了 CSCFI

#### 结论

- `poc` 用来验证主程序内部函数指针劫持会被 CSCFI 检测到。
- 这个样例上，`main-only` 和 `strong` 的效果基本一致，都会拦截。

### 3. `poc2`：libc 内部间接调用目标劫持

源码：`[core/poc2.c](/home/sally/ELF-tracker/source/core/poc2.c)`

程序逻辑：

- 栈上结构体包含：
  - `char buf[32]`
  - 比较函数指针 `cmp`
- 初始时 `cmp = safe_cmp`
- 溢出后把 `cmp` 改成 `evil_cmp`
- 然后把 `cmp` 传给 libc 的 `qsort`

关键点在于：

- 真正执行间接 `call` 的位置不在主程序里
- 而是在 libc 的 `qsort` 内部

攻击脚本：`[core/poc2.py](/home/sally/ELF-tracker/source/core/poc2.py)`

一键验证脚本：`[poc2_validate](/home/sally/ELF-tracker/source/poc2_validate)`

#### 不加保护

- 覆盖比较函数指针后，libc 最终会调用到 `evil_cmp()`
- 典型现象是输出：

```text
poc2: overwrite qsort comparator:
evil_cmp()
evil_cmp()
poc2: done
```

#### 训练

先用正常路径训练：

```bash
ET_CSCFI_POLICY=./core/poc2.policy ./train ./poc2
```

训练后会学习到：

- libc 中相关间接 `call` 对应的合法比较函数目标是 `safe_cmp`

#### `main-only` 模式

- `main-only` 只对主程序中的间接 `call` 做 CSCFI
- libc 内部的 `qsort` 间接 `call` 不在 `main-only` 的 CSCFI 覆盖范围内
- 因此攻击仍然可能成功到达 `evil_cmp()`

也就是说，这个样例在 `main-only` 下的现象是：

- 不会被 CSCFI 挡住
- 仍然能看到 `evil_cmp()`

#### `strong` 模式

- `strong` 会把共享库里的间接 `call` 也纳入 CSCFI
- 因此 libc 内部 `qsort` 的 call site 与 `evil_cmp` 的组合不在训练策略中
- 会触发：

```text
[cscfi] mismatch tid=... site=... target=...
```

#### 结论

- `poc2` 是 `main-only` 和 `strong` 差异最明显的样例。
- 它用来验证：`strong` 能检测到 libc 内部间接调用目标被劫持，而 `main-only` 不能。

## 推荐复现实验顺序

### `test`

```bash
./protect ./test.out
```

观察点：

- 正常输入时程序正常结束
- 恶意覆盖返回地址时会触发 shadow stack mismatch

### `poc`

```bash
ET_CSCFI_POLICY=./core/poc.policy ./train ./poc
ET_CSCFI_POLICY=./core/poc.policy ./protect ./poc
python3 ./core/poc.py
```

观察点：

- 无保护时可跳到 `evil()`
- 有保护后主程序内函数指针劫持会被 CSCFI 拦截

### `poc2`

```bash
./poc2_validate
```

观察点：

- `main-only` 下 `evil_cmp()` 仍可执行
- `strong` 下 libc 内部间接 `call` 被 CSCFI 拦截

## 性能测试

本节记录当前版本的一次“更合理”的开销测试结果。

测试原则：

- 不再使用 `poc` / `poc2` 这种极短命程序反复起进程
- 使用单进程长时间运行的基准，尽量把冷启动噪声压低
- 统一对比 4 种模式：
  - `empty`：原生运行，不经过 DynamoRIO
  - `drrun`：只经过 DynamoRIO，不挂防护 client
  - `main`：挂防护 client，`ET_CSCFI_ENFORCE_MODE=main`
  - `full`：挂防护 client，`ET_CSCFI_ENFORCE_MODE=strong`

使用的测试程序与脚本：

- `[core/bench.c](/home/sally/ELF-tracker/source/core/bench.c)`
- `[bench_measure](/home/sally/ELF-tracker/source/bench_measure)`

### 测试一：主程序内函数指针间接调用

工作负载：

- 单进程执行 `500000` 次主程序内函数指针间接调用

平均总时间如下：

| 模式 | 平均总时间 | 每次间接调用平均时间 | 相对 `empty` | 相对 `drrun` |
|---|---:|---:|---:|---:|
| `empty` | 386237 ns | 0.77 ns/call | 1.00x | 0.48x |
| `drrun` | 810869 ns | 1.62 ns/call | 2.10x | 1.00x |
| `main` | 3827058224 ns | 7654.12 ns/call | 9908.57x | 4719.70x |
| `full` | 3838758790 ns | 7677.52 ns/call | 9938.87x | 4734.13x |

损耗对比：

- `drrun` 相对 `empty`：`+109.94%`
- `main` 相对 `empty`：`+990757.48%`
- `full` 相对 `empty`：`+993786.86%`
- `main` 相对 `drrun`：`+471869.98%`
- `full` 相对 `drrun`：`+473312.94%`

### 测试二：libc `qsort` 内部间接调用

工作负载：

- 单进程执行 `2000` 次 `qsort`
- 间接调用发生在 libc 内部比较函数回调

平均总时间如下：

| 模式 | 平均总时间 | 每次 `qsort` 平均时间 | 相对 `empty` | 相对 `drrun` |
|---|---:|---:|---:|---:|
| `empty` | 128521 ns | 64.26 ns/qsort | 1.00x | 0.13x |
| `drrun` | 961332 ns | 480.67 ns/qsort | 7.48x | 1.00x |
| `main` | 641209785 ns | 320604.89 ns/qsort | 4989.14x | 667.00x |
| `full` | 658778336 ns | 329389.17 ns/qsort | 5125.84x | 685.28x |

损耗对比：

- `drrun` 相对 `empty`：`+648.00%`
- `main` 相对 `empty`：`+498814.41%`
- `full` 相对 `empty`：`+512484.20%`
- `main` 相对 `drrun`：`+66600.14%`
- `full` 相对 `drrun`：`+68427.66%`

### 结果解读

这组结果说明：

- 单看 `drrun` 本身，存在开销，但相比挂上当前防护 client 后的热路径开销，并不是主要矛盾。
- 当前实现里，真正大的成本来自每次间接控制流检查时执行的那套运行时逻辑，而不只是 DynamoRIO 冷启动。
- `main` 和 `full` 的差距很小，说明“共享库也纳入 CSCFI”带来的边际成本相对有限。

当前最值得继续优化的方向是：

- 把 CSCFI policy 查找从链表改成哈希表
- 降低 `at_indirect_call()` 中 `dr_lookup_module()` 的频率
- 对重复出现的目标地址做更积极的缓存
