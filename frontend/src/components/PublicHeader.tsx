import { CircleHelp, CircleUser, LayoutDashboard, LogIn, LogOut, Menu, Play, X } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useAppearance } from '../appearance'
import type { SessionUser } from '../api'
import { useI18n } from '../i18n'
import { portalName } from '../loginBranding'
import { BrandMark } from './BrandMark'
import { Icon } from './Icon'
import { LanguageSwitcher } from './LanguageSwitcher'
import { useMenu } from './useMenu'

export function PublicHeader({
  user,
  onLogout,
}: {
  user?: SessionUser | null
  onLogout?: () => Promise<void>
}) {
  const { t } = useI18n()
  const { enable_demo, enable_help, login_branding, issuer } = useAppearance()
  const name = portalName(login_branding, issuer)
  const menu = useMenu()

  return (
    <header className={`topbar ${menu.open ? 'is-open' : ''}`}>
      <div className="topbar-inner">
        <Link className="brand" to="/">
          <span className="auth-brand-mark">
            <BrandMark size={16} />
          </span>
          <span className="brand-name">{name}</span>
        </Link>
        {!user ? (
          <Link className="btn with-icon topbar-cta" to="/login">
            <Icon icon={LogIn} />
            {t('navLogin')}
          </Link>
        ) : null}
        <button
          className="btn ghost icon-btn menu-toggle"
          type="button"
          aria-label={t('navMenu')}
          aria-expanded={menu.open}
          aria-controls="public-nav"
          onClick={menu.toggle}
        >
          <Icon icon={menu.open ? X : Menu} size={18} />
        </button>
        <nav className="top-nav" id="public-nav">
          {enable_help ? (
            <Link className="nav-link" to="/help">
              <Icon icon={CircleHelp} />
              {t('navHelp')}
            </Link>
          ) : null}
          {enable_demo ? (
            <Link className="nav-link" to="/demo">
              <Icon icon={Play} />
              {t('navDemo')}
            </Link>
          ) : null}
          {user ? (
            <Link className="nav-link" to="/profile">
              <Icon icon={CircleUser} />
              {t('navProfile')}
            </Link>
          ) : null}
          <LanguageSwitcher compact />
          {user?.is_admin ? (
            <Link className="btn secondary with-icon" to="/admin">
              <Icon icon={LayoutDashboard} />
              {t('navAdmin')}
            </Link>
          ) : null}
          {user && onLogout ? (
            <button className="btn ghost with-icon" type="button" onClick={() => void onLogout()}>
              <Icon icon={LogOut} />
              {t('navLogout')}
            </button>
          ) : null}
          {!user ? (
            <Link className="btn with-icon nav-login" to="/login">
              <Icon icon={LogIn} />
              {t('navLogin')}
            </Link>
          ) : null}
        </nav>
      </div>
    </header>
  )
}
