import { Check, Copy } from 'lucide-react'
import { useId, useState } from 'react'
import { useI18n } from '../i18n'
import { Icon } from './Icon'

export type CodeTab = { label: string; code: string }

/** Multi-line snippet with a copy button; several tabs show a switcher. */
export function CodeBlock({ tabs }: { tabs: CodeTab[] }) {
  const { t } = useI18n()
  const [active, setActive] = useState(0)
  const [copied, setCopied] = useState(false)
  const id = useId()
  const current = tabs[active] ?? tabs[0]

  async function copy() {
    await navigator.clipboard.writeText(current.code)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1400)
  }

  return (
    <div className="code-block">
      <div className="code-bar">
        <div className="code-tabs" role="tablist">
          {tabs.map((tab, i) => (
            <button
              key={tab.label}
              id={`${id}-tab-${i}`}
              className={`code-tab ${i === active ? 'active' : ''}`}
              type="button"
              role="tab"
              aria-selected={i === active}
              aria-controls={`${id}-panel`}
              onClick={() => setActive(i)}
            >
              {tab.label}
            </button>
          ))}
        </div>
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
      <pre className="mono" id={`${id}-panel`} role="tabpanel" aria-labelledby={`${id}-tab-${active}`}>
        {current.code}
      </pre>
    </div>
  )
}
