import { ShieldCheck, ShieldOff } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { api } from '../api'
import { CopyField } from './CopyField'
import { Icon } from './Icon'
import { useI18n } from '../i18n'

export function MfaSettings({ onChanged }: { onChanged?: () => void }) {
  const { t } = useI18n()
  const [enabled, setEnabled] = useState(false)
  const [secret, setSecret] = useState('')
  const [qr, setQr] = useState('')
  const [code, setCode] = useState('')
  const [recovery, setRecovery] = useState<string[]>([])
  const [error, setError] = useState('')

  async function refresh() {
    const status = await api.mfaStatus()
    setEnabled(status.enabled)
  }

  useEffect(() => {
    void refresh().catch((err) => setError(err.message))
  }, [])

  async function startSetup() {
    setError('')
    setRecovery([])
    try {
      const setup = await api.mfaSetup()
      setSecret(setup.secret)
      setQr(setup.qr)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('mfaError'))
    }
  }

  async function confirm(event: FormEvent) {
    event.preventDefault()
    setError('')
    try {
      const result = await api.mfaConfirm(code)
      setRecovery(result.recovery_codes)
      setSecret('')
      setQr('')
      setCode('')
      setEnabled(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('mfaError'))
    }
  }

  async function disable(event: FormEvent) {
    event.preventDefault()
    setError('')
    try {
      await api.mfaDisable(code)
      setEnabled(false)
      setCode('')
      setRecovery([])
    } catch (err) {
      setError(err instanceof Error ? err.message : t('mfaError'))
    }
  }

  return (
    <section className="panel stack">
      <div>
        <h2 className="panel-heading">
          <Icon icon={ShieldCheck} />
          {t('mfaSettingsTitle')}
        </h2>
        <p>{t('mfaSettingsLead')}</p>
      </div>
      <p className="muted" style={{ margin: 0 }}>
        {enabled ? t('mfaEnabled') : t('mfaDisabled')}
      </p>
      {qr ? (
        <div className="stack">
          <img className="qr" src={qr} alt="" width={168} height={168} />
          <CopyField label={t('mfaSecret')} value={secret} />
          <form className="stack" onSubmit={confirm}>
            <label>
              {t('mfaCode')}
              <input value={code} onChange={(e) => setCode(e.target.value)} required />
            </label>
            <button className="btn with-icon" type="submit">
              <Icon icon={ShieldCheck} />
              {t('mfaConfirm')}
            </button>
          </form>
        </div>
      ) : null}
      {recovery.length ? (
        <div className="stack">
          <p>{t('mfaRecoveryOnce')}</p>
          <div>
            {recovery.map((item) => (
              <div className="mono" key={item}>
                {item}
              </div>
            ))}
          </div>
          <button
            className="btn"
            type="button"
            onClick={() => {
              setRecovery([])
              onChanged?.()
            }}
          >
            {t('mfaRecoveryDone')}
          </button>
        </div>
      ) : null}
      {!enabled && !qr ? (
        <button className="btn with-icon" type="button" onClick={() => void startSetup()}>
          <Icon icon={ShieldCheck} />
          {t('mfaEnable')}
        </button>
      ) : null}
      {enabled && !qr && !recovery.length ? (
        <form className="stack" onSubmit={disable}>
          <label>
            {t('mfaCode')}
            <input value={code} onChange={(e) => setCode(e.target.value)} required />
          </label>
          <button className="btn danger with-icon" type="submit">
            <Icon icon={ShieldOff} size={14} />
            {t('mfaDisable')}
          </button>
        </form>
      ) : null}
      {error ? <p className="error">{error}</p> : null}
    </section>
  )
}
