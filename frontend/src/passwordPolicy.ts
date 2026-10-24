import type { Messages } from './i18n/types'

export type PasswordPolicy = {
  min_length: number
  require_letter: boolean
  require_digit: boolean
  require_upper: boolean
  require_special: boolean
  forbid_username: boolean
}

export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = {
  min_length: 12,
  require_letter: true,
  require_digit: true,
  require_upper: false,
  require_special: false,
  forbid_username: true,
}

export function passwordPolicyHint(policy: PasswordPolicy, t: (key: keyof Messages, vars?: Record<string, string>) => string) {
  const parts = [t('passwordRuleMin', { n: String(policy.min_length) })]
  if (policy.require_letter) parts.push(t('passwordRuleLetter'))
  if (policy.require_digit) parts.push(t('passwordRuleDigit'))
  if (policy.require_upper) parts.push(t('passwordRuleUpper'))
  if (policy.require_special) parts.push(t('passwordRuleSpecial'))
  if (policy.forbid_username) parts.push(t('passwordRuleUsername'))
  return t('passwordRuleJoin', { rules: parts.join(', ') })
}
