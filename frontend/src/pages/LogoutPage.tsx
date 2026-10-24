import { useState, type FormEvent } from 'react'
import { LogOut } from 'lucide-react'
import { Link, useSearchParams } from 'react-router-dom'
import { AuthShell } from '../components/AuthShell'
import { AuthBrand } from '../components/AuthBrand'
import { Icon } from '../components/Icon'
import { LanguageSwitcher } from '../components/LanguageSwitcher'
import { useI18n } from '../i18n'

const FORWARDED = ['client_id', 'post_logout_redirect_uri', 'state', 'ui_locales'] as const

export function LogoutPage() {
  const { t } = useI18n()
  const [params] = useSearchParams()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError('')
    const body = new URLSearchParams()
    for (const name of FORWARDED) {
      const value = params.get(name)
      if (value) body.set(name, value)
    }
    try {
      // fetch + JSON avoids Chrome/Safari form-action blocking the post-logout redirect.
      const res = await fetch('/oauth/logout', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body,
        credentials: 'same-origin',
      })
      if (!res.ok) throw new Error('logout failed')
      const data = (await res.json()) as { redirect_to?: string }
      window.location.assign(data.redirect_to || '/')
    } catch {
      setBusy(false)
      setError(t('logoutError'))
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
            <Icon icon={LogOut} />
            {t('logoutTitle')}
          </h1>
          <p>{t('logoutLead')}</p>
        </div>
        <form className="stack" method="post" action="/oauth/logout" onSubmit={onSubmit}>
          {FORWARDED.map((name) => {
            const value = params.get(name)
            return value ? <input key={name} type="hidden" name={name} value={value} /> : null
          })}
          {error ? <p className="error">{error}</p> : null}
          <button className="btn block with-icon" type="submit" disabled={busy}>
            <Icon icon={LogOut} />
            {t('navLogout')}
          </button>
          <Link className="btn secondary block" to="/">
            {t('logoutCancel')}
          </Link>
        </form>
      </div>
    </AuthShell>
  )
}
