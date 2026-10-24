import type { CSSProperties, ReactNode } from 'react'
import { useAppearance } from '../appearance'
import { brandingStyle, resolvedBranding } from '../loginBranding'

export { LOGIN_THEMES } from '../loginBranding'
export type { LoginTheme } from '../loginBranding'

export function AuthShell({ children }: { children: ReactNode }) {
  const { login_theme: theme, login_branding } = useAppearance()
  const style = brandingStyle(resolvedBranding(theme, login_branding))
  return (
    <div className={`auth-screen theme-${theme}`} style={style as CSSProperties}>
      {children}
    </div>
  )
}
