# ELF-tracker

## 项目简介

这是一个基于 DynamoRIO 的运行时防护实验项目，当前实现的重点是：

- `shadow stack`：检测返回地址篡改
- `CFI / CSCFI`：检测间接 `call` / 间接 `jmp` 的非法目标

当前版本是实验型验证方案，不是生产级通用 CFI。它更适合：

- 学习 DynamoRIO 插桩流程
- 验证主程序与 libc 间接控制流劫持的检测效果
- 对比 `main-only` 和 `strong` 两种策略范围

## 当前能力边界

这版实现目前做的是：

- 保留 `shadow stack`
- 只对间接 `call` 和间接 `jmp` 做 CFI 检查
- CSCFI 重点约束间接 `call` 的 `(callsite, target)` 合法配对
- `main` 模式只严格检查主程序模块
- `strong` 模式把共享库里的相关间接调用也纳入检查

这版没有做的事情：

- 不追求生产级别的全程序通防 CFI
- 不处理编译期全局类型约束
- 不和 LLVM 级别 CFI 做效果或性能竞争

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
| `drrun` | `0.020 s` |
| `main` | `0.035 s` |
| `full` | `0.032 s` |

相对损耗：

- `drrun` 相对 `empty`：`3.33x`
- `main` 相对 `empty`：`5.83x`
- `full` 相对 `empty`：`5.33x`
- `main` 相对 `drrun`：`1.75x`
- `full` 相对 `drrun`：`1.60x`
