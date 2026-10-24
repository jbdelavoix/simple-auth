import type { LoginBranding } from './loginBranding'
import type { PasswordPolicy } from './passwordPolicy'

export type SessionUser = {
  id: string
  username: string
  name: string
  email: string
  groups: string[]
  is_admin: boolean
  must_change_password?: boolean
  mfa_enabled?: boolean
  mfa_required?: boolean
}

export type Group = {
  id: string
  name: string
  description: string
}

export type DirectoryUser = {
  id: string
  username: string
  email: string
  name: string
  enabled: boolean
  email_verified?: boolean
  group_ids: string[]
  groups?: string[]
  attributes: Record<string, unknown>
  mfa_enabled?: boolean
}

export type Client = {
  client_id: string
  client_name: string
  redirect_uris: string[]
  post_logout_redirect_uris: string[]
  grant_types: string[]
  response_types: string[]
  token_endpoint_auth_method: string
  scope: string
  allowed_groups: string[]
  origins: string[]
  mode: 'oidc' | 'forward'
  has_secret: boolean
  client_secret?: string
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
    ...init,
  })
  if (!response.ok) {
    let detail = response.statusText
    try {
      const data = await response.json()
      detail = data.detail || JSON.stringify(data)
    } catch {
      /* ignore */
    }
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
  }
  if (response.status === 204) {
    return undefined as T
  }
  return response.json() as Promise<T>
}

export type SessionPolicy = {
  idle_seconds: number
  absolute_seconds: number
  mfa_trust_days: number
}

export type AdminSettings = {
  issuer: string
  frontend_origin: string
  discovery_url: string
  scopes_supported: string[]
  login_theme: string
  enable_demo: boolean
  enable_help: boolean
  password_policy: PasswordPolicy
  login_branding: LoginBranding
  session_policy: SessionPolicy
  connector: {
    name: string
    writable: boolean
    description: string
    url?: string
    user_base?: string
    group_base?: string
    group_filter?: string
    admin_group?: string
    group_allowlist?: string[]
    groups_source?: string
  }
  init: {
    data_dir: string
    directory: string
    identities: string
    clients: string
    runtime: string
    jwks: string
    audit: string
    seed_username: string | null
    seed_password: string | null
    signing_kid: string | null
  }
  proxy: {
    trusted_proxies: string[]
    peer: string | null
    peer_trusted: boolean
    forwarded_headers: boolean
    client_ip: string | null
  }
}

export type AuditEvent = {
  id: string
  ts: number
  at: string
  action: string
  outcome: string
  actor?: string | null
  actor_id?: string | null
  ip?: string | null
  target?: string | null
  target_type?: string | null
  client_id?: string | null
  grant_type?: string | null
}

export type AuditRotation = {
  current_bytes: number
  max_bytes: number
  keep: number
  archives: { name: string; bytes: number; mtime: number }[]
}

export const api = {
  session: () => request<{ authenticated: boolean; user?: SessionUser }>('/api/session'),
  login: (username: string, password: string, next?: string) =>
    request<{ ok: boolean; mfa_required?: boolean; next?: string; user: SessionUser }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, next: next || undefined }),
    }),
  verifyMfa: (code: string, trust = false) =>
    request<{ ok: boolean; next: string; must_change_password?: boolean; redirect_to?: string }>('/api/auth/mfa', {
      method: 'POST',
      body: JSON.stringify({ code, trust }),
    }),
  mfaStatus: () => request<{ enabled: boolean }>('/api/mfa'),
  mfaSetup: () =>
    request<{ secret: string; otpauth_url: string; qr: string }>('/api/mfa/setup', { method: 'POST' }),
  mfaConfirm: (code: string) =>
    request<{ ok: boolean; recovery_codes: string[] }>('/api/mfa/confirm', {
      method: 'POST',
      body: JSON.stringify({ code }),
    }),
  mfaDisable: (code: string) =>
    request<{ ok: boolean }>('/api/mfa/disable', {
      method: 'POST',
      body: JSON.stringify({ code }),
    }),
  logout: () => request<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }),
  changePassword: (current_password: string, new_password: string, next?: string) =>
    request<{ ok: boolean; next?: string }>('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password, new_password, next }),
    }),
  interaction: (id: string) =>
    request<{
      id: string
      status: string
      client: { client_id: string; client_name: string }
      scopes: string[]
      scope: string
      allowed_groups: string[]
      release: { scope: string; claims: { name: string; value: string | number | boolean | string[] }[] }[]
    }>(`/api/interaction/${id}`),
  interactionLogin: (id: string, username: string, password: string) =>
    request<{ ok: boolean; next: string; mfa_required?: boolean; redirect_to?: string }>(`/api/interaction/${id}/login`, {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  interactionConfirm: (id: string, approve = true) =>
    request<{ redirect_to: string }>(`/api/interaction/${id}/confirm`, {
      method: 'POST',
      body: JSON.stringify({ approve }),
    }),
  profile: () =>
    request<SessionUser & { writable: boolean }>('/api/profile'),
  updateProfile: (body: { name?: string; email?: string }) =>
    request<SessionUser & { writable: boolean }>('/api/profile', {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),
  appearance: () =>
    request<{
      login_theme: string
      enable_demo: boolean
      enable_help: boolean
      password_policy: PasswordPolicy
      login_branding: LoginBranding
      session_policy: SessionPolicy
      issuer: string
    }>('/api/appearance'),
  settings: () => request<AdminSettings>('/api/admin/settings'),
  updateSettings: (body: {
    login_theme?: string
    enable_demo?: boolean
    enable_help?: boolean
    password_policy?: Partial<PasswordPolicy>
    login_branding?: Partial<LoginBranding>
    session_policy?: Partial<SessionPolicy>
  }) =>
    request<AdminSettings>('/api/admin/settings', {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),
  resetCrypto: () =>
    request<{ ok: boolean; kid: string | null; revoked: Record<string, number> }>(
      '/api/admin/crypto/reset',
      { method: 'POST' },
    ),
  audit: (params?: {
    limit?: number
    action?: string
    outcome?: string
    q?: string
    actor?: string
    target?: string
    ip?: string
    since?: number
    until?: number
  }) => {
    const query = new URLSearchParams()
    if (params?.limit) query.set('limit', String(params.limit))
    if (params?.action) query.set('action', params.action)
    if (params?.outcome) query.set('outcome', params.outcome)
    if (params?.q) query.set('q', params.q)
    if (params?.actor) query.set('actor', params.actor)
    if (params?.target) query.set('target', params.target)
    if (params?.ip) query.set('ip', params.ip)
    if (params?.since) query.set('since', String(params.since))
    if (params?.until) query.set('until', String(params.until))
    const suffix = query.toString() ? `?${query}` : ''
    return request<{ events: AuditEvent[]; rotation: AuditRotation }>(`/api/admin/audit${suffix}`)
  },
  rotateAudit: () =>
    request<{ ok: boolean; rotated: boolean; rotation: AuditRotation }>('/api/admin/audit/rotate', {
      method: 'POST',
    }),
  users: {
    list: () => request<DirectoryUser[]>('/api/admin/users'),
    create: (body: Record<string, unknown>) =>
      request<DirectoryUser>('/api/admin/users', { method: 'POST', body: JSON.stringify(body) }),
    update: (id: string, body: Record<string, unknown>) =>
      request<DirectoryUser>(`/api/admin/users/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    remove: (id: string) => request<void>(`/api/admin/users/${id}`, { method: 'DELETE' }),
    resetMfa: (id: string) =>
      request<{ ok: boolean }>(`/api/admin/users/${id}/mfa/reset`, { method: 'POST' }),
  },
  groups: {
    list: () => request<Group[]>('/api/admin/groups'),
    create: (body: Record<string, unknown>) =>
      request<Group>('/api/admin/groups', { method: 'POST', body: JSON.stringify(body) }),
    update: (id: string, body: Record<string, unknown>) =>
      request<Group>(`/api/admin/groups/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    remove: (id: string) => request<void>(`/api/admin/groups/${id}`, { method: 'DELETE' }),
  },
  clients: {
    list: () => request<Client[]>('/api/admin/clients'),
    create: (body: Record<string, unknown>) =>
      request<Client>('/api/admin/clients', { method: 'POST', body: JSON.stringify(body) }),
    update: (id: string, body: Record<string, unknown>) =>
      request<Client>(`/api/admin/clients/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    remove: (id: string) => request<void>(`/api/admin/clients/${id}`, { method: 'DELETE' }),
  },
}
