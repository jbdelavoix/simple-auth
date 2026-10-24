import { Check, Copy } from 'lucide-react'
import { useState } from 'react'
import { useI18n } from '../i18n'
import { Icon } from './Icon'

export function CopyField({ value, label }: { value: string; label?: string }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)

  async function copy() {
    await navigator.clipboard.writeText(value)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1400)
  }

  return (
    <div className="copy-field">
      {label ? <span className="copy-label">{label}</span> : null}
      <div className="copy-row">
        <code className="mono">{value}</code>
        <button
          className={`btn ghost with-icon copy-btn ${copied ? 'is-copied' : ''}`}
          type="button"
          aria-label={copied ? t('copied') : t('copy')}
          onClick={() => void copy()}
        >
          <Icon icon={copied ? Check : Copy} size={14} />
          <span className="copy-btn-text">{copied ? t('copied') : t('copy')}</span>
        </button>
      </div>
    </div>
  )
}
