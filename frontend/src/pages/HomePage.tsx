import { CircleUser, LayoutDashboard, LogIn } from 'lucide-react'
import { Link } from 'react-router-dom'
import type { SessionUser } from '../api'
import { CopyField } from '../components/CopyField'
import { Icon } from '../components/Icon'
import { PublicHeader } from '../components/PublicHeader'
import { useI18n } from '../i18n'

export function HomePage({
  user,
  onLogout,
}: {
  user: SessionUser | null
  onLogout: () => Promise<void>
}) {
  const { t } = useI18n()
  const issuer = window.location.origin
  const endpoints = [
    { label: t('settingsIssuer'), value: issuer },
    { label: t('homeDiscovery'), value: `${issuer}/.well-known/openid-configuration` },
    { label: t('homeJwks'), value: `${issuer}/jwks.json` },
    { label: t('homeAuthorize'), value: `${issuer}/oauth/authorize` },
    { label: t('homeToken'), value: `${issuer}/oauth/token` },
    { label: t('homeUserinfo'), value: `${issuer}/oauth/userinfo` },
  ]

  return (
    <div className="app-shell">
      <PublicHeader user={user} onLogout={onLogout} />
      <section className="home">
        <h1>{t('homeTitle')}</h1>
        <p>{t('homeLead')}</p>
        {user ? (
          <>
            <p className="user-chip" style={{ marginBottom: '0.85rem' }}>
              {t('homeHello', { name: user.name || user.username })}
            </p>
            <div className="row">
              <Link className="btn with-icon" to="/profile">
                <Icon icon={CircleUser} />
                {t('navProfile')}
              </Link>
              {user.is_admin ? (
                <Link className="btn secondary with-icon" to="/admin">
                  <Icon icon={LayoutDashboard} />
                  {t('navAdmin')}
                </Link>
              ) : null}
            </div>
          </>
        ) : (
          <Link className="btn with-icon" to="/login">
            <Icon icon={LogIn} />
            {t('navLogin')}
          </Link>
        )}
      </section>
      <section className="panel stack">
        <h2>{t('homeEndpoints')}</h2>
        {endpoints.map((item) => (
          <CopyField key={item.label} label={item.label} value={item.value} />
        ))}
      </section>
    </div>
  )
}
