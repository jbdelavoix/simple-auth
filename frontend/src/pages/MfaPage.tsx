import { ShieldCheck } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { api } from '../api'
import { AuthShell } from '../components/AuthShell'
import { AuthBrand } from '../components/AuthBrand'
import { Icon } from '../components/Icon'
import { LanguageSwitcher } from '../components/LanguageSwitcher'
import { useAppearance } from '../appearance'
import { useI18n } from '../i18n'

export function MfaPage() {
  const { t } = useI18n()
  const trustDays = useAppearance().session_policy.mfa_trust_days
  const [code, setCode] = useState('')
  const [trust, setTrust] = useState(false)
  const [error, setError] = useState('')

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    setError('')
    try {
      const result = await api.verifyMfa(code, trustDays > 0 && trust)
      window.location.href = result.redirect_to || result.next || '/admin'
    } catch (err) {
      setError(err instanceof Error ? err.message : t('mfaError'))
    }
  }

  return (
    <AuthShell>
      <div className="auth-card stack">
        <div className="auth-top">
          <AuthBrand />
          <LanguageSwitcher compact />
        </div>
        <div>
          <h1 className="panel-heading">
            <Icon icon={ShieldCheck} />
            {t('mfaTitle')}
          </h1>
          <p>{t('mfaLead')}</p>
        </div>
        <form className="stack" onSubmit={onSubmit}>
          <label>
            {t('mfaCode')}
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
              required
            />
          </label>
          {trustDays > 0 ? (
            <label className="check">
              <input type="checkbox" checked={trust} onChange={(event) => setTrust(event.target.checked)} />
              {t('mfaTrust', { days: String(trustDays) })}
            </label>
          ) : null}
          {trustDays > 0 && trust ? <p className="muted field-hint">{t('mfaTrustHint')}</p> : null}
          {error ? <p className="error">{error}</p> : null}
          <button className="btn block with-icon" type="submit">
            <Icon icon={ShieldCheck} />
            {t('mfaSubmit')}
          </button>
        </form>
      </div>
    </AuthShell>
  )
}
