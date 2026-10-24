import type { Messages } from './i18n/types'

export type ReleasedClaim = {
  name: string
  value: string | number | boolean | string[]
}

export type ReleasedScope = {
  scope: string
  claims: ReleasedClaim[]
}

const SCOPE_KEYS: Record<string, { title: keyof Messages; hint: keyof Messages }> = {
  openid: { title: 'consentScopeOpenid', hint: 'consentScopeOpenidHint' },
  profile: { title: 'consentScopeProfile', hint: 'consentScopeProfileHint' },
  email: { title: 'consentScopeEmail', hint: 'consentScopeEmailHint' },
  groups: { title: 'consentScopeGroups', hint: 'consentScopeGroupsHint' },
  offline_access: { title: 'consentScopeOffline', hint: 'consentScopeOfflineHint' },
}

const CLAIM_KEYS: Record<string, keyof Messages> = {
  sub: 'consentClaimSub',
  name: 'consentClaimName',
  preferred_username: 'consentClaimUsername',
  email: 'consentClaimEmail',
  email_verified: 'consentClaimEmailVerified',
  groups: 'consentClaimGroups',
}

export function scopeTitle(scope: string, t: (key: keyof Messages) => string): string {
  const keys = SCOPE_KEYS[scope]
  return keys ? t(keys.title) : scope
}

export function scopeHint(scope: string, t: (key: keyof Messages) => string): string {
  const keys = SCOPE_KEYS[scope]
  return keys ? t(keys.hint) : ''
}

export function claimLabel(name: string, t: (key: keyof Messages) => string): string {
  const key = CLAIM_KEYS[name]
  return key ? t(key) : name
}

export function claimDisplay(value: ReleasedClaim['value'], t: (key: keyof Messages) => string): string {
  if (Array.isArray(value)) return value.length ? value.join(', ') : t('consentEmpty')
  if (typeof value === 'boolean') return value ? t('consentYes') : t('consentNo')
  const text = String(value ?? '').trim()
  return text || t('consentEmpty')
}
