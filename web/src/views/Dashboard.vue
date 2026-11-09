<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessageBox } from 'element-plus'
import { useGateway } from '../stores/gateway'

const g = useGateway()
const tab = ref('session')
const selected = computed(() => g.scopes.find(x => x.scope_id === g.scope))
const snapshot = computed(() => g.snapshot ?? {status: 'UNAVAILABLE'})
const sessionStatus = computed(() => {
  const session = snapshot.value.session
  return typeof session === 'object' && session !== null && 'state' in session && 'freshness' in session && session.freshness === 'FRESH' ? String(session.state) : 'UNKNOWN'
})
const marketStatus = computed(() => snapshot.value.market_status === 'LIVE' && snapshot.value.market_freshness !== 'FRESH' ? 'UNKNOWN' : String(snapshot.value.market_status ?? 'UNKNOWN'))
const resultNotice = computed(() => g.result?.code === 'RECOVERY_REQUIRED' ? '恢复核对尚未完成，原因仍然生效。' : g.result?.status === 'NOT_FOUND' && g.retryReady ? '当前账本未查到原请求，不代表从未发送；可确认后重试原内容。' : g.result?.status === 'UNKNOWN' || (typeof g.result?.code === 'string' && g.result.code.includes('CONFLICT')) ? '结果待人工核查；不能据此认定未发送。请保留原请求 ID 并联系 Gateway 管理员核对。' : '')
const mayStartNew = computed(() => {
  const cause = g.result?.cause
  return g.lastCommandMode !== 'RESUME' && g.result?.status === 'OBSERVED' && typeof cause === 'object' && cause !== null && 'cause_id' in cause && 'active' in cause && cause.cause_id === g.lastCommandId && (cause.active === false || cause.active === 0)
})
async function permitNew() {
  const scope = g.scope, epoch = g.scopeGeneration
  try { await ElMessageBox.confirm('原原因已解除；重新核验后允许下一次新建独立控制请求？', '新的控制请求', {confirmButtonText: '允许', cancelButtonText: '取消', type: 'warning'}); await g.permitNewCommand(scope, epoch) } catch { /* User cancelled. */ }
}
async function retryOriginal() {
  try { await ElMessageBox.confirm('将复用原请求 ID 和内容，并由服务端重新核查服务身份、账本和原记录。', '重试原请求', {confirmButtonText: '重试原请求', cancelButtonText: '取消', type: 'warning'}); await g.retryOriginal() } catch { /* User cancelled. */ }
}
const sections = [
  { id: 'session', title: '会话与行情', key: 'session' },
  { id: 'account', title: '账户与策略', key: 'account' },
  { id: 'orders', title: '订单与成交', key: 'orders' },
  { id: 'transfers', title: '内部转移', key: 'transfers' }
]
const section = computed(() => sections.find(x => x.id === tab.value)!)
const content = computed(() => snapshot.value.status === 'UNAVAILABLE' ? snapshot.value : snapshot.value[section.value.key] ?? {status: 'UNAVAILABLE', reason: 'NO_AUTHORIZED_VIEW'})
function text(value: unknown) { return JSON.stringify(value, null, 2) }
function isActive(value: unknown) { return value === true || value === 1 }
function activeLabel(value: unknown) { return isActive(value) ? '生效' : value === false || value === 0 ? '已解除' : 'UNKNOWN' }
async function apply(mode: string) {
  const scope = g.scope, route = selected.value?.route_fingerprint ?? '', view = g.scopeReceipt, epoch = g.scopeGeneration, seq = g.causeGeneration
  try { await ElMessageBox.confirm(`对当前授权范围执行 ${mode}。此操作的结果以 Gateway 记录为准。`, '确认控制操作', {confirmButtonText: '继续', cancelButtonText: '取消', type: 'warning'}); await g.operate(mode, '', 0, view, scope, route, epoch, seq) } catch { /* User cancelled. */ }
}
async function resume(cause: Record<string, unknown>) {
  if (typeof cause.cause_id !== 'string' || typeof cause.version !== 'number' || typeof cause.view_receipt !== 'string') return
  const scope = g.scope, route = selected.value?.route_fingerprint ?? '', epoch = g.scopeGeneration, seq = g.causeGeneration
  try { await ElMessageBox.confirm('只解除所选原因；其他原因和未知状态会保留。', '解除原因', {confirmButtonText: '继续', cancelButtonText: '取消', type: 'warning'}); await g.operate('RESUME', cause.cause_id, cause.version, cause.view_receipt, scope, route, epoch, seq) } catch { /* User cancelled. */ }
}
async function drainTarget(target: Record<string, unknown>) {
  if (typeof target.reservation_id !== 'string' || typeof target.operation_id !== 'string' || typeof target.view_receipt !== 'string' || !g.targetCause) return
  const scope = g.scope, route = selected.value?.route_fingerprint ?? '', cause = g.targetCause, epoch = g.scopeGeneration, seq = g.targetGeneration
  try { await ElMessageBox.confirm('仅处理冻结清单中的这一目标；未知结果不会自动重复派发。', '执行撤单目标', {confirmButtonText: '继续', cancelButtonText: '取消', type: 'warning'}); await g.drainTarget(cause, target.reservation_id, target.operation_id, target.view_receipt, scope, route, epoch, seq) } catch { /* User cancelled. */ }
}
onMounted(() => g.initialize())
</script>
<template>
  <div class="page"><header><div><div class="eyebrow">ACCOUNT GATEWAY <span>/</span> CONTROL PLANE</div><h1>运行总览</h1><p>查看 Gateway 状态、订单与已授权的控制原因。</p></div><div class="top-actions"><el-select v-model="g.scope" :disabled="g.pending" placeholder="选择授权范围" @change="g.switchScope" aria-label="授权范围"><el-option v-for="scope in g.scopes" :key="scope.scope_id" :label="scope.strategy_ref ? `策略 · ${scope.strategy_ref}` : '账户范围'" :value="scope.scope_id" /></el-select><el-button :disabled="!g.scope || g.pending" @click="g.refresh">刷新</el-button></div></header>
  <div v-if="g.error" class="warning">{{ g.error }}</div><div v-if="g.scopes.length && !g.receiptKeyPersistent" class="warning">当前为临时凭据密钥；Web 重启后旧请求需人工核查。</div>
  <div class="scope-line"><span class="dot" :class="g.scope ? 'green' : 'muted'"></span>{{ selected ? (selected.strategy_ref ? `策略视图 / ${selected.strategy_ref}` : '账户视图') : '无可用授权范围' }} <span class="scope-note">访问范围由服务端授权决定</span></div>
  <div class="summary"><article><span>会话状态</span><strong>{{ sessionStatus }}</strong><small>无新鲜度证明时显示未知</small></article><article><span>行情状态</span><strong>{{ marketStatus }}</strong><small>无新鲜度证明时显示未知</small></article><article><span>控制原因（本页）</span><strong>{{ g.error ? 'UNKNOWN' : g.causes.length }}</strong><small>仅当前授权范围</small></article><article><span>数据版本</span><strong>{{ String(snapshot.version ?? '—') }}</strong><small>更新时间与缺口见详情</small></article></div>
  <div class="columns"><section class="panel main-panel"><div class="panel-head"><div><div class="eyebrow">AUTHORIZED VIEWS</div><h2>账户观察</h2></div><span class="badge">只读视图</span></div><div class="tabs"><button v-for="item in sections" :key="item.id" :class="{active: tab === item.id}" @click="tab = item.id">{{ item.title }}</button></div><div class="data-head"><h3>{{ section.title }}</h3><span>状态 / 来源 / 新鲜度</span></div><pre>{{ text(content) }}</pre><div class="hint">真实成交与内部转移分别展示；不可用字段不会按零值补全。</div></section>
  <section class="panel controls"><div class="panel-head"><div><div class="eyebrow">SAFETY CONTROLS</div><h2>控制原因</h2></div><span class="badge amber">须授权</span></div><p class="description">操作按当前范围执行。解除一个原因不代表账户已具备交易条件。</p><div class="buttons"><el-button :disabled="g.pending || !g.scope || !g.scopeReceipt" @click="apply('STOP_NEW')">停止新单</el-button><el-button :disabled="g.pending || !g.scope || !g.scopeReceipt" @click="apply('FREEZE')">冻结</el-button><el-button :disabled="g.pending || !g.scope || !g.scopeReceipt" type="danger" plain @click="apply('DRAIN')">撤销活动单</el-button></div><div v-if="!g.causes.length" class="empty"><span>◌</span><b>{{ g.error ? '控制状态未知' : '当前没有可显示的原因' }}</b><small>连接失败或缺少权限不等于安全就绪</small></div><div v-for="cause in g.causes" :key="String(cause.cause_id)" class="cause"><div><b>{{ String(cause.mode ?? 'UNKNOWN') }}</b><small>{{ String(cause.cause_id ?? '—') }} · v{{ String(cause.version ?? '—') }}</small><small>状态：{{ activeLabel(cause.active) }}</small><el-button v-if="cause.mode === 'DRAIN' && typeof cause.cause_id === 'string'" text size="small" :disabled="g.pending" @click="g.loadTargets(cause.cause_id)">查看撤单目标</el-button></div><el-button v-if="isActive(cause.active)" size="small" :disabled="g.pending" @click="resume(cause)">解除</el-button></div><div class="page-controls"><el-button v-if="g.causeAfter" size="small" @click="g.refresh">返回首页</el-button><el-button v-if="g.causes.length === 100" size="small" @click="g.nextCauses">下一页</el-button></div><div v-if="g.targetCause" class="target-list"><b>撤单目标 · {{ g.targetCause }}</b><div v-for="target in g.targets" :key="String(target.reservation_id)" class="cause"><div><small>{{ String(target.reservation_id ?? '—') }}</small><small>状态：{{ String(target.state ?? 'UNKNOWN') }}</small></div><el-button v-if="target.state === 'PENDING'" size="small" :disabled="g.pending" @click="drainTarget(target)">执行</el-button></div><small v-if="!g.targets.length">没有可显示目标，或结果尚不可用。</small><div class="page-controls"><el-button v-if="g.targetAfter" size="small" @click="g.loadTargets(g.targetCause)">返回首页</el-button><el-button v-if="g.targets.length === 100" size="small" @click="g.nextTargets">下一页</el-button></div></div><div v-if="g.result" class="result"><b>操作结果</b><p v-if="resultNotice" class="result-notice">{{ resultNotice }}</p><pre>{{ text(g.result) }}</pre><small>UNKNOWN 表示结果未确认；重复点击先查询原请求，不自动发送新命令。</small><el-button v-if="g.retryReady" text size="small" :disabled="g.pending" @click="retryOriginal">重试原请求</el-button><el-button v-if="mayStartNew" text size="small" :disabled="g.pending" @click="permitNew">允许新的独立控制请求</el-button></div></section></div>
  <footer>Gateway 独立界面 <span>·</span> 浏览器关闭不会改变服务状态 <span>·</span> 所有控制由 Gateway 鉴权</footer></div>
</template>
