# Gateway 独立运营界面

本目录是独立 Vue 3 / TypeScript / Vite 页面；可选 Python HTTP 适配器在 `bt_api_gateway.web.app`。二者不创建 Gateway、provider 或交易 owner。必须由可信部署宿主提供浏览器会话认证、CSRF token、与该主体精确对应的 SDK `ThreadedServiceClientRuntime`；尚未接好这些依赖时不要启动为可访问服务。没有实现万能账号或默认密码。

## 构建与发行

在本目录运行 `npm ci`，然后 `npm run bundle`。脚本先执行类型检查与 Vite 构建，再将输出复制到 `src/bt_api_gateway/web/static/`，并包含第三方依赖许可声明。Gateway wheel 通过可选 `web` extra 安装 FastAPI、Pydantic 2 和 Uvicorn，不启用 Web 时不要求安装它们。若构建后需要发行，重新构建 Gateway wheel；应在干净的隔离源码副本中构建 wheel，并核对 `bt_api_gateway/web/static/` 文件集合和字节与本次产物完全一致；setuptools 复用旧 `build/lib` 时可能把已删除的旧 JS 一起打入 wheel。不要清理用户现有构建目录来掩盖这一问题。`bundled_static_dir()` 在未打包静态页面时抛 `GATEWAY_WEB_STATIC_NOT_BUILT`，不会生成替代页面。

宿主使用自己的受信认证与授权来源创建应用（示意接口，`my_trusted_host` 须由部署者实现）：

```python
from bt_api_gateway.web.app import create_app, bundled_static_dir, run_local
from my_trusted_host import authenticate, resolve_runtime, receipt_signing_key

origin = "http://127.0.0.1:8000"
app = create_app(origin=origin, authenticate=authenticate,
                 resolve_runtime=resolve_runtime,
                 receipt_key=receipt_signing_key, receipt_key_id="host-key-v1",
                 static_dir=bundled_static_dir())
run_local(app, origin=origin)
```

`authenticate(request)` 必须对每次请求校验服务端会话/撤权并返回 `AuthenticatedWebSession`；其中 CSRF token 由宿主安全生成并绑定会话，浏览器认证 cookie 应设 HttpOnly、SameSite 和适合部署的安全属性。`WebScope` 必须来自受信授权映射；`scope_id` 是页面使用的本地安全引用，不是浏览器提供的 principal。`resolve_runtime(session, scope)` 返回该用户和对应账户/策略的独立、已认证 SDK runtime，不能返回拥有更大权限的共用服务账户。接口另核对 runtime 当前身份、active binding、精确scope和操作，再由 Gateway 服务端执行独立鉴权。宿主须确保撤权及时反映在认证和 Gateway grant 中。

宿主配置 Gateway 和对应主体的精确授权时，须单独授予 `direct.control.identity`；若要查询和重试 RESUME，还须授予 `direct.control.resume_status`；处理 DRAIN 目标须授予 `direct.control.target_status` 和 `direct.control.drain_target`。另按需要授予 `direct.control.status`、`direct.control.list`、`direct.control.targets`、`direct.control.apply` 和 `direct.control.resume`。未授予查询权限时保持不可用或待人工核查，不能以写入权限推导读取权限。此清单不包含密钥或默认账号，具体身份和授权由可信宿主配置。

宿主应从受保护密钥源注入至少 32 字节的随机 `receipt_key`，并为每次密钥轮换设置不同 `receipt_key_id`；不应把密钥写入浏览器、日志或公开配置。同一密钥和版本可跨 Web 重启验证旧凭据；换密钥或版本后旧凭据保持 UNKNOWN、须人工核查。未注入密钥时使用临时进程密钥，Web 重启后旧凭据不可验证，界面会显示提示，这种模式不构成完整生产交付。

账户快照（2026-11-11 更新）：账户范围的操作员若另有一条账户读取登记（`application.account`，仅 `account.snapshot.typed`），快照路由通过这条登记读取 Gateway 账户读模型**已经持有**的账户视图，不向柜台发查询。只有在以下各项都成立时才展示：账户读取登记与控制登记属于同一个 Gateway 服务（同一服务 epoch、同一已认证对端和服务端公钥）；读取结果里的来源说明所写的 journal 与 `direct.control.identity` 返回的一致、账户一致；数据属于来源说明所写的 owner 代；读模型已就绪且未过期。否则返回 `UNAVAILABLE` 及原因（`SOURCE_PROVENANCE_UNAVAILABLE`、`SOURCE_PROVENANCE_MISMATCH`、`ACCOUNT_VIEW_NOT_READY`、`ACCOUNT_VIEW_UNAVAILABLE`），Gateway 拒绝时返回 `REQUEST_REJECTED` 及 Gateway 的代码。展示的是账户视图（`view: "account"`），缺失的金额为 `null`，不补 0；不能将账户总额冒充策略资金。策略范围的操作员没有策略视图，返回 `STRATEGY_VIEW_UNAVAILABLE`。`read_snapshot(session, scope)` 回调参数仅为兼容保留，不会被调用。本页面（`Dashboard.vue`）尚未展示这份账户视图，页面归迭代 69。以上只有本机合成数据的测试证据，没有实盘证据，集成和实盘能力需单独验收。完整合同见 `docs/gateway-web-api-v1.md` 第 6.2 节。

HTTP入口默认只接受本机客户端和明确的 Host；写操作要求精确 Origin 和会话 CSRF token。生产运行使用同一 loopback origin 托管静态页面和API；`run_local` 只监听 loopback，不启用代理头。若开发时通过 Vite 代理，须在受信本机宿主中单独配置浏览器 origin 与本地后端监听，不能向公网暴露。未来宿主可经 `window.gatewayHost` 指定 API base URL/认证准备回调；修改 URL 不授予权限。

## 控制与状态

只提供 STOP_NEW、FREEZE、DRAIN、逐原因 RESUME 和 DRAIN 冻结目标的执行，不提供通用下单、改账或清除 UNKNOWN。Gateway 自身的 ACL、操作准入和原因版本仍是权威。控制范围、原因和目标列表都带绑定用户所见服务与 journal 的签名视图凭据；准备控制操作时须验证对应视图，防止同一 scope 映射更换后误操作。浏览器先取得由 Web 签名、绑定原请求内容、当前主体、经 CURVE 认证的 Gateway 服务身份及持久 journal 的凭据，再将凭据与请求 ID 保存在本机并用跨标签锁串行；重复点击先查询，不自动换 ID 重发。若本地持久化或跨标签锁不可用，界面不能安全发送新的控制命令。恢复原因后不表示所有交易条件已满足；`RECOVERY_REQUIRED` 和 `UNKNOWN` 分别显示为未完成核对和结果未知。

本版本不实现跨设备会话接续或把浏览器本地存储视为服务端的审计日志；Gateway 原有 journal/命令状态才是持久权威。认证、真实 Gateway/CTP、浏览器安全和发行包检查须在最终集中验收中单列。

`tests/browser-races.cjs` 使用合成 HTTP 视图检查延迟返回和重复控制行为，不连接账户；先执行 `npm run bundle`，再通过可用的 Playwright 执行该脚本。可用 `PLAYWRIGHT_PATH` 指向已有 Playwright 安装，`CHROME_PATH` 指向本机浏览器；这不是对真实 CURVE 或账户功能的验收。

依赖检查记录：npm 公开审计曾报告 3 个 moderate 条目：构建期 `vue-tsc` 2.2.12 → `@vue/language-core` 2.2.12 → `minimatch` 9.0.9；[GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249) 的受影响范围为 minimatch 7.0.0 至 11.0.0。该链条用于 Vue 类型检查，不进入浏览器运行时代码。项目已将构建工具 `vue-tsc` 升至 3.3.14 并更新 lockfile，当前 `npm audit` 返回 0；这是构建工具的主版本升级，本机 Node 25 构建通过，其他 Node/CI 环境仍须验收，审计结果不代表所有安全风险均已排除。

原因及 RESUME 查询的 `NOT_FOUND` 只代表当前授权账本没有记录，不证明先前请求从未发送。服务端每次重新核实当前授权、CURVE 注册绑定及同 journal 身份；仅相同凭据返回 `NOT_FOUND` 后可经运营确认重试，服务端会再次查询，并把原 journal ID 作为同库写入栅栏。服务身份、密钥或 journal 改变、注册期间变化和 UNKNOWN 均不能重试，须人工核查；同一服务身份与 journal 的正常 Gateway 重启可重新核验。路由指纹仅验证账户、scope 和策略，不单独证明 journal 身份。


## HTTP v1

`scope_id` 只从服务端 `GET /api/v1/session` 返回的已授权清单选择；路径不是授权凭据。所有响应 `Cache-Control: no-store`。只读和管理分别使用 SDK 对应 operation grant；写入均需当前会话、精确 Origin、`X-CSRF-Token` 和该范围的 `X-Gateway-Route` 指纹。

| HTTP | Gateway操作/语义 |
| --- | --- |
| `GET /api/v1/session` | 当前会话可见范围、CSRF token及本机请求命名空间；不返回Gateway密钥。 |
| `GET /api/v1/scopes/{scope_id}/snapshot` | 账户范围：经操作员自己的账户读取登记读 `account.snapshot.typed`，来源与控制视图一致时返回账户视图，否则返回 `UNAVAILABLE` 及原因；策略范围返回 `STRATEGY_VIEW_UNAVAILABLE`。 |
| `GET /api/v1/scopes/{scope_id}/causes?after=&limit=100` | `direct.control.list`，当前精确范围有界分页；范围和每个原因附签名视图凭据。 |
| `POST /api/v1/scopes/{scope_id}/requests/prepare` | 验证认证 peer、journal 和权限并签发原内容凭据，不触发控制写入。 |
| `POST /api/v1/scopes/{scope_id}/targets/prepare` | 验证同一服务和 journal 的 PENDING 撤单目标并签发凭据，不触发撤单。 |
| `POST /api/v1/scopes/{scope_id}/requests/status` | 重新验证签名及同一服务和 journal，再查询凭据指定的原请求。 |
| `POST /api/v1/scopes/{scope_id}/requests/run` | 重新验证凭据并查询；仅当前账本无该请求时按原内容、原 ID 和 journal 栅栏执行。 |
| `POST /api/v1/scopes/{scope_id}/targets/query` | 以签名原因视图分页读取 DRAIN 冻结目标；每个目标附签名视图凭据。 |

Gateway未返回可证结果、网络丢失或调用结果无法验证时为 `UNKNOWN`，不是已成功或确定未执行。读取/身份/权限不成立返回403或不可用；外部依赖的详细异常不回显给浏览器。浏览器不是交易、审计或恢复的权威来源。
