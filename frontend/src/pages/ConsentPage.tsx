import { Check, ShieldCheck, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { AuthShell } from '../components/AuthShell'
import { AuthBrand } from '../components/AuthBrand'
import { Icon } from '../components/Icon'
import { LanguageSwitcher } from '../components/LanguageSwitcher'
import { localizeError } from '../errors'
import { useI18n } from '../i18n'
import { claimDisplay, claimLabel, scopeHint, scopeTitle, type ReleasedScope } from '../scopeLabels'

export function ConsentPage() {
  const { t } = useI18n()
  const [params] = useSearchParams()
  const interaction = params.get('interaction')
  const navigate = useNavigate()
  const [error, setError] = useState('')
  const [info, setInfo] = useState<{
    client: { client_name: string; client_id: string }
    scopes: string[]
    release: ReleasedScope[]
    allowed_groups: string[]
  } | null>(null)

  useEffect(() => {
    if (!interaction) {
      navigate('/login')
      return
    }
    api
      .interaction(interaction)
      .then(setInfo)
      .catch((err) => setError(localizeError(err, t, 'consentError')))
  }, [interaction, navigate])

  async function decide(approve: boolean) {
    if (!interaction) return
    setError('')
    try {
      const result = await api.interactionConfirm(interaction, approve)
      window.location.href = result.redirect_to
    } catch (err) {
      setError(localizeError(err, t, 'consentError'))
    }
  }

  const shares = info?.release?.length
    ? info.release
    : (info?.scopes || []).map((scope) => ({ scope, claims: [] }))

  return (
    <AuthShell>
      <div className="auth-card wide stack">
        <div className="auth-top">
          <AuthBrand />
          <LanguageSwitcher compact />
        </div>
        <div>
          <h1 className="panel-heading">
            <Icon icon={ShieldCheck} />
            {t('consentTitle')}
          </h1>
          <p>{info ? t('consentLead', { app: info.client.client_name }) : t('consentLoading')}</p>
        </div>
        {info ? (
          <div className="consent-share">
            <p className="muted" style={{ marginBottom: 0 }}>
              {t('consentScopes')}
            </p>
            {shares.map((item) => (
              <div className="consent-share-item" key={item.scope}>
                <strong>
                  {scopeTitle(item.scope, t)}
                  <code>{item.scope}</code>
                </strong>
                {scopeHint(item.scope, t) ? <p>{scopeHint(item.scope, t)}</p> : null}
                {item.claims.length ? (
                  <ul>
                    {item.claims.map((claim) => (
                      <li key={claim.name}>
                        <span>{claimLabel(claim.name, t)}</span>
                        <b>{claimDisplay(claim.value, t)}</b>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </div>
            ))}
            {(info.allowed_groups || []).length > 0 ? (
              <p className="muted" style={{ marginBottom: 0 }}>
                {t('consentGroups')}: {info.allowed_groups.join(', ')}
              </p>
            ) : null}
          </div>
        ) : null}
        {error ? <p className="error">{error}</p> : null}
        <div className="row">
          <button className="btn with-icon" type="button" onClick={() => decide(true)} disabled={!info}>
            <Icon icon={Check} />
            {t('consentAllow')}
          </button>
          <button className="btn secondary with-icon" type="button" onClick={() => decide(false)} disabled={!info}>
            <Icon icon={X} />
            {t('consentDeny')}
          </button>
        </div>
      </div>
    </AuthShell>
  )
}
