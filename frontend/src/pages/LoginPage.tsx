import { ArrowLeft, LogIn } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { AuthShell } from '../components/AuthShell'
import { AuthBrand } from '../components/AuthBrand'
import { Icon } from '../components/Icon'
import { LanguageSwitcher } from '../components/LanguageSwitcher'
import { localizeError } from '../errors'
import { useI18n } from '../i18n'

export function LoginPage() {
  const { t } = useI18n()
  const [params] = useSearchParams()
  const interaction = params.get('interaction')
  const next = params.get('next') || ''
  const denied = params.get('error') || ''
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [clientName, setClientName] = useState('')

  useEffect(() => {
    if (!denied) return
    setError(localizeError(new Error(denied), t, 'loginError'))
  }, [denied, t])

  useEffect(() => {
    if (interaction || denied || !/^https?:\/\//i.test(next)) return
    api
      .session()
      .then((info) => {
        if (info.authenticated && !info.user?.must_change_password) {
          window.location.href = `/session/handoff?rd=${encodeURIComponent(next)}`
        }
      })
      .catch(() => {})
  }, [interaction, denied, next])

  useEffect(() => {
    if (!interaction) return
    api
      .interaction(interaction)
      .then((info) => setClientName(info.client.client_name))
      .catch((err) => setError(localizeError(err, t, 'loginError')))
  }, [interaction])

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    setError('')
    try {
      if (interaction) {
        const result = await api.interactionLogin(interaction, username, password)
        if (result.redirect_to) {
          window.location.href = result.redirect_to
          return
        }
        navigate(result.next || `/consent?interaction=${interaction}`)
        return
      }
      const result = await api.login(username, password, next || undefined)
      window.location.href = result.next || (result.user.is_admin ? '/admin' : '/')
    } catch (err) {
      setError(localizeError(err, t, 'loginError'))
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
            <Icon icon={LogIn} />
            {t('loginTitle')}
          </h1>
          {interaction ? <p>{t('loginLeadApp', { app: clientName || '…' })}</p> : null}
        </div>
        <form className="stack" onSubmit={onSubmit}>
          <label>
            {t('loginUsername')}
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
          </label>
          <label>
            {t('loginPassword')}
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          {error ? <p className="error">{error}</p> : null}
          <button className="btn block with-icon" type="submit">
            <Icon icon={LogIn} />
            {t('loginSubmit')}
          </button>
        </form>
        {!interaction ? (
          <p className="muted" style={{ marginBottom: 0 }}>
            <Link className="nav-link" to="/">
              <Icon icon={ArrowLeft} size={14} />
              {t('loginBack').replace(/^←\s*/, '')}
            </Link>
          </p>
        ) : null}
      </div>
    </AuthShell>
  )
}
