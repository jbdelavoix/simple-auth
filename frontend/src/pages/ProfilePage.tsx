import { CircleUser, KeyRound, Save } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { Navigate } from 'react-router-dom'
import { api, type SessionUser } from '../api'
import { Icon } from '../components/Icon'
import { MfaSettings } from '../components/MfaSettings'
import { PublicHeader } from '../components/PublicHeader'
import { useAppearance } from '../appearance'
import { useI18n } from '../i18n'
import { passwordPolicyHint } from '../passwordPolicy'

export function ProfilePage({
  user,
  onLogout,
  onRefresh,
}: {
  user: SessionUser | null
  onLogout: () => Promise<void>
  onRefresh: () => Promise<void>
}) {
  const { t } = useI18n()
  const { password_policy: policy } = useAppearance()
  const [name, setName] = useState(user?.name || '')
  const [email, setEmail] = useState(user?.email || '')
  const [writable, setWritable] = useState(true)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    if (!user) return
    void api
      .profile()
      .then((profile) => {
        setName(profile.name)
        setEmail(profile.email)
        setWritable(profile.writable)
      })
      .catch((err) => setError(err instanceof Error ? err.message : t('loginError')))
  }, [user, t])

  if (!user) return <Navigate to="/login" replace />
  if (user.must_change_password) return <Navigate to="/change-password" replace />

  async function saveProfile(event: FormEvent) {
    event.preventDefault()
    setError('')
    setMessage('')
    try {
      await api.updateProfile({ name, email })
      await onRefresh()
      setMessage(t('profileSaved'))
    } catch (err) {
      setError(err instanceof Error ? err.message : t('loginError'))
    }
  }

  async function savePassword(event: FormEvent) {
    event.preventDefault()
    setError('')
    setMessage('')
    try {
      await api.changePassword(currentPassword, newPassword)
      setCurrentPassword('')
      setNewPassword('')
      setMessage(t('profilePasswordSaved'))
    } catch (err) {
      setError(err instanceof Error ? err.message : t('loginError'))
    }
  }

  return (
    <div className="app-shell">
      <PublicHeader user={user} onLogout={onLogout} />
      <div>
        <h1 className="panel-heading">
          <Icon icon={CircleUser} />
          {t('profileTitle')}
        </h1>
        <p>{t('profileLead')}</p>
      </div>
      {error ? <p className="error">{error}</p> : null}
      {message ? <p className="hint">{message}</p> : null}

      <div className="settings-grid">
        <section className="panel stack">
          <h2 className="panel-heading">
            <Icon icon={CircleUser} />
            {t('profileTitle')}
          </h2>
          <form className="stack" onSubmit={saveProfile}>
            <label>
              {t('profileUsername')}
              <input value={user.username} disabled />
            </label>
            <label>
              {t('usersName')}
              <input value={name} onChange={(e) => setName(e.target.value)} disabled={!writable} />
            </label>
            <label>
              {t('usersEmail')}
              <input value={email} onChange={(e) => setEmail(e.target.value)} disabled={!writable} type="email" />
            </label>
            <label>
              {t('usersGroups')}
              <input value={user.groups.join(', ') || '—'} disabled />
            </label>
            {!writable ? <p className="muted">{t('profileReadonly')}</p> : null}
            {writable ? (
              <button className="btn with-icon" type="submit">
                <Icon icon={Save} />
                {t('profileSave')}
              </button>
            ) : null}
          </form>
        </section>

        <section className="panel stack">
          <h2 className="panel-heading">
            <Icon icon={KeyRound} />
            {t('profilePasswordTitle')}
          </h2>
          <p>{writable ? t('profilePasswordLead') : t('profileReadonly')}</p>
          {writable ? <p>{passwordPolicyHint(policy, t)}</p> : null}
          {writable ? (
            <form className="stack" onSubmit={savePassword}>
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
              <button className="btn with-icon" type="submit">
                <Icon icon={KeyRound} />
                {t('loginChangeSubmit')}
              </button>
            </form>
          ) : null}
        </section>
      </div>

      <div style={{ marginTop: '0.9rem' }}>
        <MfaSettings onChanged={() => void onRefresh()} />
      </div>
    </div>
  )
}
