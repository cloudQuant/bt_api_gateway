import axios from 'axios'

export interface Scope { scope_id: string; strategy_ref: string | null; route_fingerprint: string }
export interface Session { csrf_token: string; namespace: string; scopes: Scope[]; receipt_key_persistent: boolean }
export type Data = Record<string, unknown>
export interface HostAdapter { baseURL: string; credentials?: boolean; configure?: () => Promise<void> }

// A host can inject URL/session setup without changing the domain view.
const host: HostAdapter = (window as Window & { gatewayHost?: HostAdapter }).gatewayHost ?? { baseURL: '/api/v1', credentials: true }
const http = axios.create({ baseURL: host.baseURL, withCredentials: host.credentials ?? true, timeout: 6000 })
const sessionKey = 'gateway.local.session.v1'
function isSameOrigin(config: {baseURL?: string; url?: string}): boolean {
  try { return new URL(config.url ?? '', new URL(config.baseURL ?? '/', window.location.href)).origin === window.location.origin }
  catch { return false }
}
http.interceptors.request.use(config => {
  if (isSameOrigin(config)) {
    try {
      const token = sessionStorage.getItem(sessionKey)
      if (token) {
        config.headers.set('X-Gateway-Session', token)
        // XHR follows redirects automatically and can forward nonstandard headers.
        config.adapter = 'fetch'
        config.fetchOptions = {...config.fetchOptions, redirect: 'error'}
      }
    } catch { /* Storage unavailable: host authentication remains authoritative. */ }
  }
  return config
})
http.interceptors.response.use(response => response, error => {
  if (error.response?.status === 401 && error.config && isSameOrigin(error.config)) {
    try { sessionStorage.removeItem(sessionKey) } catch { /* Ignore unavailable storage. */ }
  }
  return Promise.reject(error)
})
export const gateway = {
  async session() { await host.configure?.(); return (await http.get<Session>('/session')).data },
  async snapshot(scope: string) { return (await http.get<Data>(`/scopes/${encodeURIComponent(scope)}/snapshot`)).data },
  async causes(scope: string, after = '') { return (await http.get<Data>(`/scopes/${encodeURIComponent(scope)}/causes`, { params: { after, limit: 100 } })).data },
  async prepare(scope: string, body: Data, csrf: string, route: string) { return (await http.post<Data>(`/scopes/${encodeURIComponent(scope)}/requests/prepare`, body, {headers: {'X-CSRF-Token': csrf, 'X-Gateway-Route': route}})).data },
  async prepareTarget(scope: string, body: Data, csrf: string, route: string) { return (await http.post<Data>(`/scopes/${encodeURIComponent(scope)}/targets/prepare`, body, {headers: {'X-CSRF-Token': csrf, 'X-Gateway-Route': route}})).data },
  async requestStatus(scope: string, receipt: string, csrf: string, route: string) { return (await http.post<Data>(`/scopes/${encodeURIComponent(scope)}/requests/status`, {receipt}, {headers: {'X-CSRF-Token': csrf, 'X-Gateway-Route': route}})).data },
  async runRequest(scope: string, receipt: string, csrf: string, route: string) { return (await http.post<Data>(`/scopes/${encodeURIComponent(scope)}/requests/run`, {receipt}, {headers: {'X-CSRF-Token': csrf, 'X-Gateway-Route': route}})).data },
  async targets(scope: string, view_receipt: string, after: string, csrf: string, route: string) { return (await http.post<Data>(`/scopes/${encodeURIComponent(scope)}/targets/query`, {view_receipt, after, limit: 100}, {headers: {'X-CSRF-Token': csrf, 'X-Gateway-Route': route}})).data }
}
