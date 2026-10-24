import type { Messages } from './i18n/types'

const ERROR_KEYS: Record<string, keyof Messages> = {
  client_forbidden: 'errorClientForbidden',
  'User is not allowed to use this client': 'errorClientForbidden',
  origin_taken: 'errorOriginTaken',
}

export function localizeError(
  err: unknown,
  t: (key: keyof Messages) => string,
  fallback: keyof Messages,
): string {
  const raw = err instanceof Error ? err.message : ''
  const key = raw ? ERROR_KEYS[raw] : undefined
  return key ? t(key) : raw || t(fallback)
}
