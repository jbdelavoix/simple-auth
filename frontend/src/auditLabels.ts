import type { AuditEvent } from './api'
import type { Messages } from './i18n/types'

export const AUDIT_ACTIONS: { value: string; key: keyof Messages }[] = [
  { value: 'login', key: 'auditActLogin' },
  { value: 'login_failed', key: 'auditActLoginFailed' },
  { value: 'mfa_ok', key: 'auditActMfaOk' },
  { value: 'mfa_trusted', key: 'auditActMfaTrusted' },
  { value: 'mfa_failed', key: 'auditActMfaFailed' },
  { value: 'mfa_enabled', key: 'auditActMfaEnabled' },
  { value: 'mfa_disabled', key: 'auditActMfaDisabled' },
  { value: 'mfa_reset', key: 'auditActMfaReset' },
  { value: 'password_change', key: 'auditActPasswordChange' },
  { value: 'profile_update', key: 'auditActProfileUpdate' },
  { value: 'logout', key: 'auditActLogout' },
  { value: 'consent_allow', key: 'auditActConsentAllow' },
  { value: 'consent_deny', key: 'auditActConsentDeny' },
  { value: 'token_issued', key: 'auditActTokenIssued' },
  { value: 'token_failed', key: 'auditActTokenFailed' },
  { value: 'token_revoked', key: 'auditActTokenRevoked' },
  { value: 'refresh_reuse', key: 'auditActRefreshReuse' },
  { value: 'user_create', key: 'auditActUserCreate' },
  { value: 'user_update', key: 'auditActUserUpdate' },
  { value: 'user_delete', key: 'auditActUserDelete' },
  { value: 'group_create', key: 'auditActGroupCreate' },
  { value: 'group_update', key: 'auditActGroupUpdate' },
  { value: 'group_delete', key: 'auditActGroupDelete' },
  { value: 'client_create', key: 'auditActClientCreate' },
  { value: 'client_update', key: 'auditActClientUpdate' },
  { value: 'client_delete', key: 'auditActClientDelete' },
  { value: 'crypto_reset', key: 'auditActCryptoReset' },
  { value: 'audit_rotate', key: 'auditActAuditRotate' },
  { value: 'client_forbidden', key: 'auditActClientForbidden' },
]

const ACTION_KEYS = Object.fromEntries(AUDIT_ACTIONS.map((item) => [item.value, item.key])) as Record<
  string,
  keyof Messages
>

const OUTCOME_KEYS: Record<string, keyof Messages> = {
  success: 'auditSuccess',
  failure: 'auditFailure',
  denied: 'auditDenied',
}

export function auditActionLabel(action: string, t: (key: keyof Messages) => string): string {
  const key = ACTION_KEYS[action]
  return key ? t(key) : action.replaceAll('_', ' ')
}

export function auditOutcomeLabel(outcome: string, t: (key: keyof Messages) => string): string {
  const key = OUTCOME_KEYS[outcome]
  return key ? t(key) : outcome
}

export function auditOutcomeClass(outcome: string): string {
  if (outcome === 'success') return 'ok'
  if (outcome === 'denied') return 'warn'
  return 'fail'
}

export function auditDetail(event: AuditEvent, t: (key: keyof Messages) => string): string {
  const parts: string[] = []
  if (event.grant_type === 'authorization_code') parts.push(t('auditGrantCode'))
  else if (event.grant_type === 'refresh_token') parts.push(t('auditGrantRefresh'))
  else if (event.grant_type) parts.push(event.grant_type.replaceAll('_', ' '))
  if (event.client_id) parts.push(event.client_id)
  return [...new Set(parts)].join(' · ')
}
