# Fixed Notes

## 这次做了什么优化

本轮主要做了两类优化：

### 1. 避免每次都重新编译 client

修改了：

- `[train](/home/sally/ELF-tracker/source/train)`
- `[protect](/home/sally/ELF-tracker/source/protect)`

优化前：

- 每次执行 `./train` 或 `./protect` 都会重新编译对应的 DynamoRIO client
- 即使源码没有变化，也会重复执行一遍 `gcc`

优化后：

- 只有当源码文件比对应的 `.so` 新时，才重新编译
- 否则直接复用：
  - `[core/libtrain.so](/home/sally/ELF-tracker/source/core/libtrain.so)`
  - `[core/libshadow_stack.so](/home/sally/ELF-tracker/source/core/libshadow_stack.so)`

这样减少的是“使用体验上的重复构建开销”，不是运行时热路径本身的开销。

### 2. 优化 CSCFI 热路径

修改了：

- `[core/shadow_stack.c](/home/sally/ELF-tracker/source/core/shadow_stack.c)`

优化点一：把 CSCFI policy 查找从链表改成哈希桶

优化前：

- `enc_pair_head` 是单链表
- `has_encrypted_pair()` 每次查找都线性扫描
- policy 越大，查找越慢

优化后：

- 使用固定大小桶数组 `enc_pair_buckets[4096]`
- 通过 `enc_site` 和 `enc_target` 计算 bucket
- 查找从“全表线性扫描”变成“桶内扫描”

优化点二：降低 `at_indirect_call()` 中 `dr_lookup_module()` 的频率

优化前：

- 每次间接 `call` 都会：
  - `dr_lookup_module(instr_addr)`
  - `dr_lookup_module(target_addr)`

优化后：

- 在线程状态里加入一个小型模块区间缓存
- 先在缓存中匹配 `pc` 所属模块
- 只有缓存未命中时才调用 `dr_lookup_module()`

## 优化思路

整体思路不是继续纠结 `drrun` 本身，而是先区分三种不同开销：

1. `DynamoRIO` 冷启动开销
2. 我们自己的 client 初始化开销
3. 真正热路径上的每次间接控制流检查开销

在之前的测试里，短命程序反复启动会把第 1 类和第 2 类放大得很明显。  
所以后面改成了单进程长时间运行的 benchmark，目的是尽量压低冷启动噪声，逼近第 3 类成本。

在这个前提下，优先优化最可疑的热点：

- 高频查表：CSCFI pair 匹配
- 高频模块查询：`dr_lookup_module()`

这两个点改完之后，再重新跑 benchmark 看收益。

## 优化结果

使用：

- `[core/bench.c](/home/sally/ELF-tracker/source/core/bench.c)`
- `[bench_measure](/home/sally/ELF-tracker/source/bench_measure)`

重新测试之后，结果如下。

### 主程序内函数指针间接调用

优化前：

- `main`: `7654.116 ns/call`
- `full`: `7677.518 ns/call`

优化后：

- `main`: `7090.562 ns/call`
- `full`: `7142.705 ns/call`

收益：

- `main` 改善约 `7.36%`
- `full` 改善约 `6.97%`

### libc `qsort` 内部间接调用

优化前：

- `main`: `320604.893 ns/qsort`
- `full`: `329389.168 ns/qsort`

优化后：

- `main`: `323239.086 ns/qsort`
- `full`: `325996.412 ns/qsort`

结论：

- `qsort` 这条路径的改善不明显
- 说明这条路径更重的部分不完全在这两个优化点上
- 更可能还压在：
  - `is_valid_cfi_target()`
  - `module_requires_ibt()`
  - `is_endbr_target()`

## 当前结论

这轮优化是有效的，但不是数量级优化。

明确得到的结论是：

- CSCFI 查表和模块查询确实是热路径热点
- 它们优化后，对“主程序内间接调用”这一类 workload 有稳定收益
- 但系统的主要开销还没有被完全打掉
- 目前最大的剩余热点，大概率在 target 合法性校验和 IBT 校验

例如之前对 `poc` 的表格里写的是：

- 每组 `200` 次
- 统计的是这 `200` 次的总时间，再除以 `200`

所以：

- 表格里的 `5.994 s`
- 不是“单次运行 `./protect ./poc` 要 5.994 秒”
- 而是“连续运行 200 次，总共 5.994 秒”W

折算回单次，其实只有：

- `29.970 ms/次`
