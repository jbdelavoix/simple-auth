import { KeyRound } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { AuthShell } from '../components/AuthShell'
import { AuthBrand } from '../components/AuthBrand'
import { Icon } from '../components/Icon'
import { LanguageSwitcher } from '../components/LanguageSwitcher'
import { useAppearance } from '../appearance'
import { useI18n } from '../i18n'
import { passwordPolicyHint } from '../passwordPolicy'

export function ChangePasswordPage() {
  const { t } = useI18n()
  const { password_policy: policy } = useAppearance()
  const [params] = useSearchParams()
  const interaction = params.get('interaction')
  const next = params.get('next') || ''
  const navigate = useNavigate()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [error, setError] = useState('')

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    setError('')
    try {
      const result = await api.changePassword(currentPassword, newPassword, next || undefined)
      if (interaction) {
        navigate(`/consent?interaction=${interaction}`)
        return
      }
      window.location.href = result.next || '/profile'
    } catch (err) {
      setError(err instanceof Error ? err.message : t('loginError'))
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
            <Icon icon={KeyRound} />
            {t('loginChangeTitle')}
          </h1>
          <p>{t('loginChangeLead')}</p>
          <p>{passwordPolicyHint(policy, t)}</p>
        </div>
        <form className="stack" onSubmit={onSubmit}>
          <label>
            {t('loginCurrentPassword')}
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          <label>
            {t('loginNewPassword')}
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              autoComplete="new-password"
              minLength={policy.min_length}
              required
            />
          </label>
          {error ? <p className="error">{error}</p> : null}
          <button className="btn block with-icon" type="submit">
            <Icon icon={KeyRound} />
            {t('loginChangeSubmit')}
          </button>
        </form>
      </div>
    </AuthShell>
  )
}
