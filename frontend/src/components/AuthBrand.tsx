import { useAppearance } from '../appearance'
import { portalName } from '../loginBranding'
import { BrandMark } from './BrandMark'

export function AuthBrand() {
  const { login_branding, issuer } = useAppearance()
  const logo = login_branding.logo
  const title = portalName(login_branding, issuer)
  const subtitle = login_branding.subtitle.trim()

  return (
    <div className="auth-brand">
      <div className={`auth-brand-mark ${logo ? 'has-logo' : ''}`}>
        {logo ? <img className="auth-logo" src={logo} alt="" /> : <BrandMark />}
      </div>
      <div className="auth-brand-text">
        {title}
        {subtitle ? <small>{subtitle}</small> : null}
      </div>
    </div>
  )
}
