import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import de from './locales/de'
import en from './locales/en'
import es from './locales/es'
import fr from './locales/fr'
import it from './locales/it'
import pt from './locales/pt'
import { LOCALES, type Locale, type Messages } from './types'

const CATALOG: Record<Locale, Messages> = { fr, en, de, es, it, pt }

function fromBrowserTag(tag: string): Locale | null {
  const normalized = tag.trim().toLowerCase().replace('_', '-')
  if (LOCALES.includes(normalized as Locale)) return normalized as Locale
  const short = normalized.split('-')[0]
  if (LOCALES.includes(short as Locale)) return short as Locale
  return null
}

export function detectLocale(): Locale {
  const candidates = [...(navigator.languages ?? []), navigator.language]
  for (const tag of candidates) {
    if (!tag) continue
    const match = fromBrowserTag(tag)
    if (match) return match
  }
  return 'en'
}

type I18nContextValue = {
  locale: Locale
  setLocale: (locale: Locale) => void
  t: (key: keyof Messages, vars?: Record<string, string>) => string
  messages: Messages
}

const I18nContext = createContext<I18nContextValue | null>(null)

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(() => detectLocale())

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next)
  }, [])

  useEffect(() => {
    document.documentElement.lang = locale
  }, [locale])

  useEffect(() => {
    const onLanguageChange = () => setLocaleState(detectLocale())
    window.addEventListener('languagechange', onLanguageChange)
    return () => window.removeEventListener('languagechange', onLanguageChange)
  }, [])

  const messages = CATALOG[locale]

  const t = useCallback(
    (key: keyof Messages, vars?: Record<string, string>) => {
      let value = messages[key] || en[key] || String(key)
      if (vars) {
        for (const [k, v] of Object.entries(vars)) {
          value = value.replaceAll(`{${k}}`, v)
        }
      }
      return value
    },
    [messages],
  )

  const value = useMemo(
    () => ({ locale, setLocale, t, messages }),
    [locale, setLocale, t, messages],
  )

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n() {
  const ctx = useContext(I18nContext)
  if (!ctx) throw new Error('useI18n must be used within I18nProvider')
  return ctx
}

export { LOCALES } from './types'
export type { Locale, Messages } from './types'
export { LOCALE_LABELS } from './types'
