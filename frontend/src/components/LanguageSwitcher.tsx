import { Languages } from 'lucide-react'
import { LOCALE_LABELS, LOCALES, useI18n } from '../i18n'
import { Icon } from './Icon'

export function LanguageSwitcher({ compact = false }: { compact?: boolean }) {
  const { locale, setLocale, t } = useI18n()

  return (
    <label className={`lang-switch ${compact ? 'compact' : ''}`}>
      <Icon icon={Languages} size={14} />
      {!compact ? <span>{t('language')}</span> : null}
      <select
        aria-label={t('language')}
        value={locale}
        onChange={(e) => setLocale(e.target.value as typeof locale)}
      >
        {LOCALES.map((code) => (
          <option key={code} value={code}>
            {LOCALE_LABELS[code]}
          </option>
        ))}
      </select>
    </label>
  )
}
