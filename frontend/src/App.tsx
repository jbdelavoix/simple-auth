import { useEffect, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AppearanceProvider, useAppearance } from './appearance'
import { api, type SessionUser } from './api'
import { I18nProvider, useI18n } from './i18n'
import { AdminPage } from './pages/AdminPage'
import { ChangePasswordPage } from './pages/ChangePasswordPage'
import { ConsentPage } from './pages/ConsentPage'
import { DemoPage } from './pages/DemoPage'
import { HelpPage } from './pages/HelpPage'
import { HomePage } from './pages/HomePage'
import { LoginPage } from './pages/LoginPage'
import { LogoutPage } from './pages/LogoutPage'
import { MfaPage } from './pages/MfaPage'
import { ProfilePage } from './pages/ProfilePage'

function AppRoutes() {
  const { t } = useI18n()
  const appearance = useAppearance()
  const [user, setUser] = useState<SessionUser | null>(null)
  const [ready, setReady] = useState(false)

  async function refreshSession() {
    const session = await api.session()
    setUser(session.authenticated && session.user ? session.user : null)
  }

  useEffect(() => {
    void refreshSession()
      .catch(() => setUser(null))
      .finally(() => setReady(true))
  }, [])

  async function logout() {
    await api.logout()
    setUser(null)
  }

  if (!ready || !appearance.ready) {
    return (
      <div className="app-shell">
        <p className="muted" style={{ paddingTop: '2.5rem' }}>
          {t('loading')}
        </p>
      </div>
    )
  }

  return (
    <Routes>
      <Route path="/" element={<HomePage user={user} onLogout={logout} />} />
      <Route
        path="/help"
        element={appearance.enable_help ? <HelpPage user={user} onLogout={logout} /> : <Navigate to="/" replace />}
      />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/mfa" element={<MfaPage />} />
      <Route path="/logout" element={<LogoutPage />} />
      <Route path="/change-password" element={<ChangePasswordPage />} />
      <Route
        path="/profile"
        element={<ProfilePage user={user} onLogout={logout} onRefresh={refreshSession} />}
      />
      <Route path="/consent" element={<ConsentPage />} />
      <Route path="/admin" element={<Navigate to="/admin/users" replace />} />
      <Route path="/admin/:tab" element={<AdminPage user={user} onLogout={logout} />} />
      <Route path="/demo" element={appearance.enable_demo ? <DemoPage /> : <Navigate to="/" replace />} />
      <Route path="/demo/callback" element={appearance.enable_demo ? <DemoPage /> : <Navigate to="/" replace />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <I18nProvider>
      <AppearanceProvider>
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
      </AppearanceProvider>
    </I18nProvider>
  )
}
