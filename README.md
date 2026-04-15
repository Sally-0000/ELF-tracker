# ELF-tracker

## 项目说明

这是一个基于 DynamoRIO 的 ELF 运行时防护实验项目，当前主要验证两类能力：

- `shadow stack`
  - 记录 `call/ret` 配对
  - 检测返回地址覆盖后的异常返回
- `CFI / CSCFI`
  - 对间接控制流目标做运行时校验
  - 对间接 `call` 的 `(call site offset, target offset)` 对进行训练和匹配

项目里有两个核心 client：

- `[core/train.c](/home/sally/ELF-tracker/source/core/train.c)`
  - 训练阶段使用
  - 收集合法间接调用目标并写入策略文件
- `[core/shadow_stack.c](/home/sally/ELF-tracker/source/core/shadow_stack.c)`
  - 防护阶段使用
  - 执行 shadow stack 校验和 CFI / CSCFI 校验

默认运行时依赖是项目内最小化的 DynamoRIO：

- `[dynamorio-min](/home/sally/ELF-tracker/source/dynamorio-min)`

如果你需要改用别的 DynamoRIO 安装，可以设置：

```bash
ET_DYNAMORIO_DIR=/path/to/DynamoRIO
```

## 目录结构

- `[train](/home/sally/ELF-tracker/source/train)`：训练入口
- `[protect](/home/sally/ELF-tracker/source/protect)`：防护入口
- `[poc2_validate](/home/sally/ELF-tracker/source/poc2_validate)`：`poc2` 一键验证入口
- `[core/cscfi_offsets.policy](/home/sally/ELF-tracker/source/core/cscfi_offsets.policy)`：默认策略文件
- `[poc_source/test.c](/home/sally/ELF-tracker/source/poc_source/test.c)`：返回地址覆盖样例
- `[poc_source/poc.c](/home/sally/ELF-tracker/source/poc_source/poc.c)`：主程序内函数指针劫持样例
- `[core/poc2.c](/home/sally/ELF-tracker/source/core/poc2.c)`：libc 内部间接调用目标劫持样例
- `[core/poc.py](/home/sally/ELF-tracker/source/core/poc.py)`：`poc` 攻击脚本
- `[core/poc2.py](/home/sally/ELF-tracker/source/core/poc2.py)`：`poc2` 攻击脚本

## 防护模式

防护端通过 `ET_CSCFI_ENFORCE_MODE` 控制 CSCFI 范围：

- `main`
  - 只对主程序模块里的间接 `call` 做 CSCFI 配对检查
  - 共享库里的间接 `call` 只做基础 CFI / IBT 检查
- `strong`
  - 主程序和共享库里的间接 `call` 都做 CSCFI 配对检查

两种模式下，`shadow stack` 都是开启的。

## 环境要求

- Linux x86-64
- `gcc`
- `bash`
- Python 3
- 如果要跑攻击脚本：`pwntools`

## 构建方式

仓库里已经带了可执行文件：

- `[test.out](/home/sally/ELF-tracker/source/test.out)`
- `[poc](/home/sally/ELF-tracker/source/poc)`
- `[poc2](/home/sally/ELF-tracker/source/poc2)`

如果你要重新编译，可以用：

```bash
gcc -O0 -g -fno-stack-protector -fno-omit-frame-pointer -fcf-protection=branch \
    poc_source/test.c -o test.out

gcc -O0 -g -fno-stack-protector -no-pie -fcf-protection=branch \
    poc_source/poc.c -o poc

gcc -O0 -g -fno-stack-protector -no-pie -fcf-protection=branch \
    core/poc2.c -o poc2
```

## 基本使用

### 1. 训练策略

先对目标程序跑一遍训练阶段：

```bash
./train ./poc
./train ./poc2
./train ./test.out
```

如果想单独指定策略文件：

```bash
ET_CSCFI_POLICY=./core/poc.policy ./train ./poc
ET_CSCFI_POLICY=./core/poc2.policy ./train ./poc2
```

如果想指定哈希种子：

```bash
ET_CSCFI_SEED=0x1337 ET_CSCFI_POLICY=./core/poc2.policy ./train ./poc2
```

### 2. 启动防护

默认是 `main` 模式：

```bash
./protect ./poc
./protect ./poc2
./protect ./test.out
```

切到 `strong` 模式：

```bash
ET_CSCFI_ENFORCE_MODE=strong ./protect ./poc2
```

如果要显式指定策略文件：

```bash
ET_CSCFI_POLICY=./core/poc.policy ./protect ./poc
ET_CSCFI_POLICY=./core/poc2.policy ET_CSCFI_ENFORCE_MODE=strong ./protect ./poc2
```

## 重点案例：`poc` 的防护效果

源码：

- `[poc_source/poc.c](/home/sally/ELF-tracker/source/poc_source/poc.c)`

攻击脚本：

- `[core/poc.py](/home/sally/ELF-tracker/source/core/poc.py)`

### 程序逻辑

`poc` 是一个主程序内函数指针劫持样例。

栈上结构体中有两个成员：

- `char buf[24]`
- 函数指针 `f`

程序初始时：

- `f = safe`

随后：

- 使用 `read(0, frame.buf, 128)` 触发溢出
- 攻击者可以覆盖 `f`
- 最后执行 `frame.f()`

### 无保护时

直接运行：

```bash
./poc
```

如果覆盖函数指针为 `evil`，会看到：

```text
input:
evil()
```

也就是说：

- 控制流已经从 `safe()`` 被劫持到 `evil()`

### 有保护时

先训练：

```bash
ET_CSCFI_POLICY=./core/poc.policy ./train ./poc
```

然后启用防护：

```bash
ET_CSCFI_POLICY=./core/poc.policy ./protect ./poc
```

或者直接跑攻击脚本：

```bash
python3 ./core/poc.py
```

训练后，系统会学到：

- 这个主程序内间接 `call` 的合法目标是 `safe`

当攻击者把函数指针改为 `evil` 时，会触发：

```text
[cscfi] mismatch tid=... site=... target=...
```

### 结论

`poc` 说明：

- 对主程序内的函数指针劫持，`main` 模式就能拦住
- `strong` 当然也能拦住
- 这个案例主要体现的是 CSCFI 对主程序内间接 `call` 的防护效果

## 其他两个样例

### `test`

源码：

- `[poc_source/test.c](/home/sally/ELF-tracker/source/poc_source/test.c)`

特点：

- 用于验证返回地址覆盖
- 防护重点在 `shadow stack`

### `poc2`

源码：

- `[core/poc2.c](/home/sally/ELF-tracker/source/core/poc2.c)`

特点：

- 用于验证 libc 内部间接 `call` 目标劫持
- `main` 模式下通常放过
- `strong` 模式下会被 `[cscfi] mismatch` 拦截

一键验证：

```bash
./poc2_validate
```

## 当前开销数据

这里保留的是你确认要看的口径：

- `poc` 的**单次平均运行时间**
- 不是批量 200 次总时间
- 也不是 benchmark 内部几十万次调用的均摊时间

测试目标：

- `[poc](/home/sally/ELF-tracker/source/poc)`

测试模式：

- `empty`
- `drrun`
- `main`
- `full`

每种模式各跑 `10` 次，统计单次墙钟时间平均值。

结果如下：

| 模式 | 单次平均运行时间 |
|---|---:|
| `empty` | `0.006 s` |
| `drrun` | `0.020 s` |
| `main` | `0.035 s` |
| `full` | `0.032 s` |

相对倍率：

- `drrun` 相对 `empty`：`3.33x`
- `main` 相对 `empty`：`5.83x`
- `full` 相对 `empty`：`5.33x`
- `main` 相对 `drrun`：`1.75x`
- `full` 相对 `drrun`：`1.60x`

这组数据的含义是：

- 你手动执行一次 `./protect ./poc`，体感上确实会明显小于 `1s`
- 当前版本对 `poc` 的单次防护开销，大致就是几十毫秒量级

## 备注

- `train` 和 `protect` 现在不会每次都重编 client
- 只有当 `[core/train.c](/home/sally/ELF-tracker/source/core/train.c)` 或 `[core/shadow_stack.c](/home/sally/ELF-tracker/source/core/shadow_stack.c)` 更新时，才会重新生成 `.so`
