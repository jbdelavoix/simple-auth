import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { api, type SessionPolicy } from './api'
import { EMPTY_BRANDING, portalName, type LoginBranding } from './loginBranding'
import { DEFAULT_PASSWORD_POLICY, type PasswordPolicy } from './passwordPolicy'

export type Appearance = {
  login_theme: string
  enable_demo: boolean
  enable_help: boolean
  password_policy: PasswordPolicy
  login_branding: LoginBranding
  session_policy: SessionPolicy
  issuer: string
}

const DEFAULT_SESSION_POLICY: SessionPolicy = {
  idle_seconds: 1800,
  absolute_seconds: 43200,
  mfa_trust_days: 30,
}

const DEFAULT_APPEARANCE: Appearance = {
  login_theme: 'classic',
  enable_demo: true,
  enable_help: true,
  password_policy: DEFAULT_PASSWORD_POLICY,
  login_branding: EMPTY_BRANDING,
  session_policy: DEFAULT_SESSION_POLICY,
  issuer: '',
}

const AppearanceContext = createContext<Appearance & { ready: boolean; refresh: () => Promise<void> }>({
  ...DEFAULT_APPEARANCE,
  ready: false,
  refresh: async () => undefined,
})

export function AppearanceProvider({ children }: { children: ReactNode }) {
  const [data, setData] = useState<Appearance>(DEFAULT_APPEARANCE)
  const [ready, setReady] = useState(false)

  async function refresh() {
    try {
      const next = await api.appearance()
      setData({
        login_theme: next.login_theme || 'classic',
        enable_demo: next.enable_demo !== false,
        enable_help: next.enable_help !== false,
        password_policy: { ...DEFAULT_PASSWORD_POLICY, ...(next.password_policy || {}) },
        login_branding: { ...EMPTY_BRANDING, ...(next.login_branding || {}) },
        session_policy: { ...DEFAULT_SESSION_POLICY, ...(next.session_policy || {}) },
        issuer: next.issuer || '',
      })
      const name = portalName(
        { ...EMPTY_BRANDING, ...(next.login_branding || {}) },
        next.issuer || '',
      )
      if (name) document.title = name
    } catch {
      /* keep last known */
    } finally {
      setReady(true)
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  return <AppearanceContext.Provider value={{ ...data, ready, refresh }}>{children}</AppearanceContext.Provider>
}

export function useAppearance() {
  return useContext(AppearanceContext)
}
