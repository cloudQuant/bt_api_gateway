import { defineStore } from 'pinia'
import { gateway, type Data, type Scope } from '../api/gateway'

interface SavedCommand { schema: 2; namespace: string; scope: string; route: string; mode: string; request_id: string; cause_id: string; expected_version: number; receipt: string }
function savedCommand(raw: string): SavedCommand | null {
  try {
    const v = JSON.parse(raw) as SavedCommand
    if (v.schema !== 2 || typeof v.namespace !== 'string' || typeof v.scope !== 'string' || !/^[0-9a-f]{64}$/.test(v.route)
        || !['STOP_NEW', 'FREEZE', 'DRAIN', 'RESUME'].includes(v.mode) || !/^[0-9a-f-]{36}$/.test(v.request_id)
        || typeof v.receipt !== 'string' || v.receipt.length > 4096 || typeof v.cause_id !== 'string'
        || !Number.isSafeInteger(v.expected_version) || (v.mode === 'RESUME' ? !v.cause_id || v.expected_version < 1 : v.cause_id !== '' || v.expected_version !== 0)) return null
    return v
  } catch { return null }
}

export const useGateway = defineStore('gateway', {
  state: () => ({ scopes: [] as Scope[], scope: '', viewScope: '', scopeReceipt: '', scopeGeneration: 0, snapshotGeneration: 0, causeGeneration: 0, targetGeneration: 0, csrf: '', namespace: '', receiptKeyPersistent: false, snapshot: null as Data | null, causes: [] as Data[], targets: [] as Data[], targetCause: '', causeAfter: '', targetAfter: '', error: '', pending: false, result: null as Data | null, retryReady: false, lastCommandKey: '', lastCommandId: '', lastCommandMode: '' }),
  actions: {
    async initialize() {
      try { const s = await gateway.session(); this.scopes = s.scopes; this.csrf = s.csrf_token; this.namespace = s.namespace; this.receiptKeyPersistent = s.receipt_key_persistent === true; this.scope = this.scopes[0]?.scope_id ?? ''; this.viewScope = this.scope; if (this.scope) await this.refresh() }
      catch { this.error = '会话不可用或未授权，请联系服务管理员。' }
    },
    async refresh() {
      const scope = this.scope, epoch = this.scopeGeneration
      if (!scope || scope !== this.viewScope) return
      ++this.snapshotGeneration
      const causeSeq = ++this.causeGeneration
      ++this.targetGeneration
      this.error = ''; this.causeAfter = ''; this.causes = []; this.scopeReceipt = ''; this.snapshot = {status: 'UNAVAILABLE', reason: 'SOURCE_PROVENANCE_UNAVAILABLE'}; this.targets = []; this.targetCause = ''; this.targetAfter = ''
      const [causes] = await Promise.allSettled([gateway.causes(scope)])
      if (scope !== this.scope || scope !== this.viewScope || epoch !== this.scopeGeneration) return
      if (causeSeq === this.causeGeneration) {
        if (causes.status === 'fulfilled' && Array.isArray(causes.value.causes) && typeof causes.value.scope_receipt === 'string') { this.causes = causes.value.causes as Data[]; this.scopeReceipt = causes.value.scope_receipt }
        else { this.causes = []; this.error = '控制原因不可读取或未授权；无法推断当前安全状态。' }
      }
    },
    async switchScope() {
      ++this.scopeGeneration; ++this.snapshotGeneration; ++this.causeGeneration; ++this.targetGeneration
      this.viewScope = this.scope; this.snapshot = null; this.causes = []; this.scopeReceipt = ''; this.causeAfter = ''; this.targets = []; this.targetCause = ''; this.targetAfter = ''; this.result = null; this.error = ''; this.retryReady = false; this.lastCommandKey = ''; this.lastCommandId = ''; this.lastCommandMode = ''
      await this.refresh()
    },
    async nextCauses() {
      const scope = this.scope, epoch = this.scopeGeneration, after = this.causes.at(-1)?.cause_id
      if (scope !== this.viewScope || typeof after !== 'string') return
      const seq = ++this.causeGeneration; ++this.targetGeneration; this.causes = []; this.scopeReceipt = ''; this.targets = []; this.targetCause = ''; this.targetAfter = ''
      try { const result = await gateway.causes(scope, after); if (scope !== this.scope || scope !== this.viewScope || epoch !== this.scopeGeneration || seq !== this.causeGeneration) return; if (!Array.isArray(result.causes) || typeof result.scope_receipt !== 'string') throw Error(); this.causes = result.causes as Data[]; this.scopeReceipt = result.scope_receipt; this.causeAfter = after }
      catch { if (scope === this.scope && scope === this.viewScope && epoch === this.scopeGeneration && seq === this.causeGeneration) this.error = '无法读取下一页控制原因。' }
    },
    async loadTargets(cause: string, after = '') {
      const scope = this.scope, epoch = this.scopeGeneration
      const row = this.causes.find(c => c.cause_id === cause && c.mode === 'DRAIN'), route = this.scopes.find(s => s.scope_id === scope)?.route_fingerprint
      if (scope !== this.viewScope || !row || typeof row.view_receipt !== 'string' || !route) return
      const seq = ++this.targetGeneration
      this.targets = []; this.targetCause = cause; this.targetAfter = after
      try { const result = await gateway.targets(scope, row.view_receipt, after, this.csrf, route); if (scope !== this.scope || scope !== this.viewScope || epoch !== this.scopeGeneration || seq !== this.targetGeneration || this.targetCause !== cause || this.targetAfter !== after) return; if (Array.isArray(result.targets)) this.targets = result.targets as Data[]; else this.error = '撤单目标不可用，结果保持未知。' }
      catch { if (scope === this.scope && scope === this.viewScope && epoch === this.scopeGeneration && seq === this.targetGeneration && this.targetCause === cause && this.targetAfter === after) this.error = '无法读取撤单目标或未授权。' }
    },
    async nextTargets() {
      const after = this.targets.at(-1)?.reservation_id
      if (typeof after === 'string') await this.loadTargets(this.targetCause, after)
    },
    async drainTarget(cause: string, target: string, operation: string, expectedView: string, expectedScope: string, expectedRoute: string, expectedEpoch: number, expectedTargetGeneration: number) {
      if (this.pending || !navigator.locks || !expectedScope || !expectedView || this.scope !== expectedScope || this.viewScope !== expectedScope || this.scopeGeneration !== expectedEpoch || this.targetGeneration !== expectedTargetGeneration || this.targetCause !== cause || !this.targets.some(t => t.reservation_id === target && t.operation_id === operation && t.view_receipt === expectedView && t.state === 'PENDING')) { this.error = '当前视图已变化，请重新选择撤单目标。'; return }
      const scope = this.scope, route = this.scopes.find(s => s.scope_id === scope)?.route_fingerprint
      if (!route || route !== expectedRoute || !/^[0-9a-f]{64}$/.test(route)) { this.error = '授权路由不可验证，控制功能不可用。'; return }
      const key = JSON.stringify(['gateway-target', this.namespace, scope, cause, target])
      this.retryReady = false
      this.pending = true
      try {
        await navigator.locks.request(key, async () => {
          const existing = localStorage.getItem(key)
          if (existing) {
            try { const saved = JSON.parse(existing); this.result = saved.schema === 2 && saved.cause_id === cause && saved.reservation_id === target && saved.operation_id === operation && saved.route === route && typeof saved.receipt === 'string' ? await gateway.requestStatus(scope, saved.receipt, this.csrf, route) : {status: 'UNKNOWN', code: 'MANUAL_REVIEW_REQUIRED'} }
            catch { this.result = {status: 'UNKNOWN', code: 'MANUAL_REVIEW_REQUIRED', cause_id: cause, reservation_id: target} }
            return
          }
          const command = {cause_id: cause, reservation_id: target, operation_id: operation, view_receipt: expectedView}
          const prepared = await gateway.prepareTarget(scope, command, this.csrf, route)
          if (prepared.status !== 'PREPARED' || typeof prepared.receipt !== 'string') { this.result = {status: 'UNKNOWN', code: 'IDENTITY_UNAVAILABLE'}; return }
          localStorage.setItem(key, JSON.stringify({schema: 2, route, ...command, receipt: prepared.receipt}))
          try { this.result = await gateway.runRequest(scope, prepared.receipt, this.csrf, route) }
          catch { this.result = {status: 'UNKNOWN', cause_id: cause, reservation_id: target} }
          await this.loadTargets(cause)
        })
      } catch { this.error = '操作未确认，请人工核查原请求；不要新建请求。' }
      finally { this.pending = false }
    },
    async operate(mode: string, cause: string, version: number, expectedView: string, expectedScope: string, expectedRoute: string, expectedEpoch: number, expectedCauseGeneration: number) {
      if (this.pending || !expectedScope || !expectedView || this.scope !== expectedScope || this.viewScope !== expectedScope || this.scopeGeneration !== expectedEpoch || this.causeGeneration !== expectedCauseGeneration || (mode === 'RESUME' ? !this.causes.some(c => c.cause_id === cause && c.version === version && c.view_receipt === expectedView && (c.active === true || c.active === 1)) : this.scopeReceipt !== expectedView)) { this.error = '当前视图已变化，请重新选择操作。'; return }
      if (!navigator.locks) { this.error = '浏览器不支持跨标签操作锁，控制功能不可用。'; return }
      const scope = this.scope, route = this.scopes.find(s => s.scope_id === scope)?.route_fingerprint
      if (!route || route !== expectedRoute || !/^[0-9a-f]{64}$/.test(route)) { this.error = '授权路由不可验证，控制功能不可用。'; return }
      const key = JSON.stringify(['gateway-command', this.namespace, scope, mode, cause, version])
      this.retryReady = false
      this.pending = true
      try {
        await navigator.locks.request(key, async () => {
          const existing = localStorage.getItem(key)
          if (existing) {
            const saved = savedCommand(existing)
            if (!saved || saved.namespace !== this.namespace || saved.scope !== scope || saved.route !== route || saved.mode !== mode || saved.cause_id !== cause || saved.expected_version !== version) {
              this.result = {status: 'UNKNOWN', code: 'MANUAL_REVIEW_REQUIRED'}; return
            }
            this.lastCommandKey = key; this.lastCommandId = saved.request_id; this.lastCommandMode = saved.mode
            try {
              this.result = await gateway.requestStatus(scope, saved.receipt, this.csrf, route)
              this.retryReady = this.result.status === 'NOT_FOUND' && (mode === 'RESUME' ? this.result.operation_id === saved.request_id : this.result.cause_id === saved.request_id)
            } catch { this.result = {status: 'UNKNOWN', request_id: saved.request_id} }
            return
          }
          const id = crypto.randomUUID()
          const command = {request_id: id, mode, cause_id: cause, expected_version: version, view_receipt: expectedView}
          const prepared = await gateway.prepare(scope, command, this.csrf, route)
          if (prepared.status !== 'PREPARED' || typeof prepared.receipt !== 'string') { this.result = {status: 'UNKNOWN', code: 'IDENTITY_UNAVAILABLE'}; return }
          const saved: SavedCommand = {schema: 2, namespace: this.namespace, scope, route, ...command, receipt: prepared.receipt}
          localStorage.setItem(key, JSON.stringify(saved))
          this.lastCommandKey = key; this.lastCommandId = id; this.lastCommandMode = mode
          try { this.result = await gateway.runRequest(scope, saved.receipt, this.csrf, route) }
          catch { this.result = {status: 'UNKNOWN', request_id: id} }
        })
        await this.refresh()
      } catch { this.error = '操作未确认，请人工核查原请求；不要新建请求。' }
      finally { this.pending = false }
    },
    async retryOriginal() {
      if (!this.retryReady || this.pending || !navigator.locks || !this.lastCommandKey) return
      const key = this.lastCommandKey, scope = this.scope, epoch = this.scopeGeneration
      this.retryReady = false; this.pending = true
      try {
        await navigator.locks.request(key, async () => {
          const saved = savedCommand(localStorage.getItem(key) ?? ''), route = this.scopes.find(s => s.scope_id === scope)?.route_fingerprint
          if (!saved || saved.namespace !== this.namespace || saved.scope !== scope || saved.route !== route || this.scope !== scope || this.viewScope !== scope || this.scopeGeneration !== epoch || saved.request_id !== this.lastCommandId || JSON.stringify(['gateway-command', saved.namespace, saved.scope, saved.mode, saved.cause_id, saved.expected_version]) !== key) throw Error('request changed')
          try { this.result = await gateway.runRequest(scope, saved.receipt, this.csrf, saved.route) }
          catch { this.result = {status: 'UNKNOWN', request_id: saved.request_id} }
        })
        await this.refresh()
      } catch { this.result = {status: 'UNKNOWN', request_id: this.lastCommandId}; this.error = '原请求或身份无法核实，请人工核查。' }
      finally { this.pending = false }
    },
    async permitNewCommand(expectedScope: string, expectedEpoch: number) {
      if (this.pending || !navigator.locks || !this.lastCommandKey || this.lastCommandMode === 'RESUME' || this.scope !== expectedScope || this.scopeGeneration !== expectedEpoch) return
      const key = this.lastCommandKey, id = this.lastCommandId
      this.pending = true
      try {
        await navigator.locks.request(key, async () => {
          const saved = savedCommand(localStorage.getItem(key) ?? ''), route = this.scopes.find(s => s.scope_id === expectedScope)?.route_fingerprint
          if (!saved || saved.request_id !== id || saved.namespace !== this.namespace || saved.scope !== expectedScope || saved.route !== route || this.scope !== expectedScope || this.scopeGeneration !== expectedEpoch) return
          const result = await gateway.requestStatus(expectedScope, saved.receipt, this.csrf, saved.route)
          const cause = result.cause
          if (result.status !== 'OBSERVED' || typeof cause !== 'object' || cause === null || !('cause_id' in cause) || !('active' in cause) || cause.cause_id !== id || (cause.active !== false && cause.active !== 0)) { this.result = result; return }
          localStorage.removeItem(key); this.lastCommandKey = ''; this.lastCommandId = ''; this.lastCommandMode = ''; this.result = null
        })
      } catch { this.result = {status: 'UNKNOWN', request_id: id} }
      finally { this.pending = false }
    }
  }
})
