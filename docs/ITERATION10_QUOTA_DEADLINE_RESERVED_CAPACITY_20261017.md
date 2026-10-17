# 迭代10：配额截止时间与撤单保留容量组件验收

日期：2026-10-17。仓库：bt_api_gateway，分支：dev，交付父提交：29b09555ae6429c2b40d6bfb69dc923a8a71993d。

本轮接受配额组件的本机 SQLite / 合成时钟行为，不增加 DIM07 或 LOAD01 正式通过数量，不证明百策略吞吐、真实 provider 或账户验收。

## 变更

- BEGIN IMMEDIATE 的 BUSY/LOCKED 仅在取得写事务前有界重试，事务体和 COMMIT 不重放。等待排序基于提交后的不可变快照，醒来后在新写事务中重新判断。
- 提交前按剩余业务截止时间缩短锁等待，且不超过该次原始短等待预算；截止时间耗尽则回滚。授权仅在 COMMIT 成功后确认。成功提交后发现超时，不返回过期 grant，已消耗配额保守保留至正常窗口到期。
- COMMIT 失败时不提前标记 granted，finally 继续清理 waiter。
- 普通请求占满 regular capacity 时，同一 subject 的最早 critical 请求可使用剩余 reserved capacity。普通容量仍可用时保留原 ticket FIFO；critical 类内 FIFO、跨 subject last-served 公平性、总容量、backoff 和 deadline 检查不变。虚拟排序与实际准入共用选择器，被旁路的 OPEN 保留。

## 验收

Root R1 首次执行整个配额测试文件：45 项，43 passed / 2 failed，5.40 秒，exit 1。失败记录保留：backoff 用例以事务内旧时点计算 sleep；virtual-rank 用例仍预期旧队头顺序。
仅修复上述两个测试函数：前者使用已有逻辑时钟并保留原 1 微秒容差；后者明确断言 B-cancel、C-open 后由 A-cancel 获得第 3 个槽，C-cancel 本轮无槽。
Root R2 仅补跑这两项：2 passed / exit 0。生产代码两轮完全相同；Root 精确源段比对与独立只读审查确认其他测试未改。两轮均 118 个输入、3 个仓库 HEAD 前后不变，无跳过、无测试错误，stderr 为空。

45 个唯一用例由上述增量证据覆盖；不是最终测试文件一次完整 45/45 通过。新增回归覆盖慢提交、提交前到期、admit 级提交失败清理、保留容量旁路及普通容量 FIFO。独立只读审查 GO，未另行重复测试。
早期作者导入环境和测试预期错误保留在临时原始记录；本轮接受以 Root R1/R2 为准。未重跑旧 200 线程性能诊断或 100 进程测试。

## 精确来源与留存

- production SHA-256: e40c6243b746b3eeb03897ddbcc3a2e538a18b241fdbddc59cfb130343fd8aa4
- final tests SHA-256: 57404ea71a09c8819436e9243ec95b4478e505155c7cc5425533cfaf6d091dbc
- R1 tests SHA-256: e68a857ebe85f153e7a872e2a295c078df71bec5ed58c9d27643fee0488d4a95
- QA 时父 SDK：06465137fcdbd82296779f6f2abc1efbf52900c0；Base：fb47f3dd733613494aa1d86cfd94b2d6fe70314d。
- [原始 Root 输出及 R1 测试快照](evidence/iteration10-quota-boundary-20261017/root-qa.zip)，SHA-256: 080ed36b95c40936a7c6b832026bec196afd299a13c8a846746193577ce7ba46。
- 两个源码/测试文件使用精确 -text 属性，保留验收时 CRLF 字节。此前 FE9 / 0DBA 工作副本另存于本仓 .codex-tmp/quota_boundary_preexisting_wip_backup_20261017_34a0f7e14154496b880943fac84e80fd/，未覆盖。

DIM07 的真实 100 策略进程与 LOAD01 的 pilot/full 仍需用户内存释放通知及重新满足 10,603,200,512 B 可用内存门槛。既有未执行 R5/R12 来源包不能自动视为本提交的验收，应在下一次实际执行前更新来源。保留旧 SimNow 会话，不进行账户操作。
