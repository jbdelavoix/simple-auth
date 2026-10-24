import {
  AppWindow,
  Archive,
  Check,
  CircleHelp,
  Clock,
  Inbox,
  KeyRound,
  Lock,
  LogOut,
  Menu,
  Network,
  Palette,
  Pencil,
  Plus,
  RefreshCw,
  Save,
  ScrollText,
  Server,
  Settings,
  ShieldOff,
  Tags,
  Trash2,
  Users,
  X,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { Link, Navigate, useParams } from 'react-router-dom'
import {
  api,
  type AdminSettings,
  type AuditEvent,
  type AuditRotation,
  type Client,
  type DirectoryUser,
  type Group,
  type SessionPolicy,
  type SessionUser,
} from '../api'
import { LOGIN_THEMES, type LoginTheme } from '../components/AuthShell'
import { useAppearance } from '../appearance'
import {
  EMPTY_BRANDING,
  THEME_COLORS,
  brandingStyle,
  portalName,
  resolvedBranding,
  type LoginBranding,
} from '../loginBranding'
import { passwordPolicyHint, type PasswordPolicy } from '../passwordPolicy'
import { CheckList } from '../components/CheckList'
import { BrandMark } from '../components/BrandMark'
import { CopyField } from '../components/CopyField'
import { Icon } from '../components/Icon'
import { MfaSettings } from '../components/MfaSettings'
import { Sheet } from '../components/Sheet'
import { LanguageSwitcher } from '../components/LanguageSwitcher'
import { useMenu } from '../components/useMenu'
import {
  AUDIT_ACTIONS,
  auditActionLabel,
  auditDetail,
  auditOutcomeClass,
  auditOutcomeLabel,
} from '../auditLabels'
import { localizeError } from '../errors'
import { useI18n, type Messages } from '../i18n'

type Tab = 'users' | 'groups' | 'clients' | 'audit' | 'settings'

const TABS: Tab[] = ['users', 'groups', 'clients', 'audit', 'settings']

const TAB_KEYS: Record<Tab, keyof Messages> = {
  users: 'adminUsers',
  groups: 'adminGroups',
  clients: 'adminClients',
  audit: 'adminAudit',
  settings: 'adminSettings',
}

const TAB_ICONS: Record<Tab, LucideIcon> = {
  users: Users,
  groups: Tags,
  audit: ScrollText,
  clients: AppWindow,
  settings: Settings,
}

export function AdminPage({
  user,
  onLogout,
}: {
  user: SessionUser | null
  onLogout: () => Promise<void>
}) {
  const { t } = useI18n()
  const appearance = useAppearance()
  const { tab: tabParam } = useParams()
  const tab: Tab = TABS.includes(tabParam as Tab) ? (tabParam as Tab) : 'users'
  const [error, setError] = useState('')
  const [users, setUsers] = useState<DirectoryUser[]>([])
  const [groups, setGroups] = useState<Group[]>([])
  const [clients, setClients] = useState<Client[]>([])
  const [settings, setSettings] = useState<AdminSettings | null>(null)
  const menu = useMenu()

  async function refresh() {
    setError('')
    try {
      const [u, g, c, s] = await Promise.all([
        api.users.list(),
        api.groups.list(),
        api.clients.list(),
        api.settings(),
      ])
      setUsers(u)
      setGroups(g)
      setClients(c)
      setSettings(s)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('loading'))
    }
  }

  const mfaGate = Boolean(user?.mfa_required && !user.mfa_enabled)

  useEffect(() => {
    if (user?.is_admin && !mfaGate) {
      void refresh()
    }
  }, [user, mfaGate])

  useEffect(() => {
    document.querySelector('.sidebar-nav a.active')?.scrollIntoView({ block: 'nearest', inline: 'nearest' })
  }, [tab])

  if (!user) return <Navigate to="/login" replace />
  if (user.must_change_password) return <Navigate to="/change-password" replace />
  if (!user.is_admin) return <Navigate to="/" replace />
  if (!TABS.includes(tabParam as Tab)) return <Navigate to="/admin/users" replace />
  if (mfaGate && tab !== 'settings') return <Navigate to="/admin/settings" replace />

  return (
    <div className="admin-layout">
      <aside className={`sidebar ${menu.open ? 'is-open' : ''}`}>
        <div className="sidebar-top">
          <Link className="sidebar-brand" to="/">
            <span className="auth-brand-mark">
              <BrandMark size={18} />
            </span>
            <span>
              <strong>{portalName(appearance.login_branding, appearance.issuer)}</strong>
              <span>{t('adminConsole')}</span>
            </span>
          </Link>
          <button
            className="btn ghost icon-btn menu-toggle"
            type="button"
            aria-label={t('navMenu')}
            aria-expanded={menu.open}
            aria-controls="admin-account"
            onClick={menu.toggle}
          >
            <Icon icon={menu.open ? X : Menu} size={18} />
          </button>
        </div>
        <nav className="sidebar-nav">
          {TABS.map((id) => (
            <Link
              key={id}
              to={`/admin/${id}`}
              className={tab === id ? 'active' : ''}
              aria-disabled={mfaGate && id !== 'settings'}
              onClick={(event) => {
                if (mfaGate && id !== 'settings') event.preventDefault()
              }}
            >
              <Icon icon={TAB_ICONS[id]} />
              {t(TAB_KEYS[id])}
            </Link>
          ))}
          {appearance.enable_help ? (
            <Link to="/help">
              <Icon icon={CircleHelp} />
              {t('navHelp')}
            </Link>
          ) : null}
        </nav>
        <div className="sidebar-footer stack" id="admin-account">
          <LanguageSwitcher />
          <span className="user-chip">{user.username}</span>
          <button className="btn secondary with-icon" type="button" onClick={() => void onLogout()}>
            <Icon icon={LogOut} />
            {t('navLogout')}
          </button>
        </div>
      </aside>

      <main className="admin-main">
        <header className="admin-header">
          <div>
            <h1>{t(TAB_KEYS[tab])}</h1>
            <p className="muted" style={{ margin: 0 }}>
              {t('adminConnector', { name: settings?.connector.name ?? '…' })}
            </p>
          </div>
          {settings ? (
            <span className={`badge ${settings.connector.writable ? 'ok' : ''}`}>
              <Icon icon={settings.connector.writable ? Pencil : Lock} size={12} />
              {settings.connector.writable ? t('settingsWritable') : t('settingsReadonly')}
            </span>
          ) : null}
        </header>

        {error ? <p className="error">{error}</p> : null}
        {mfaGate ? <p className="error">{t('mfaAdminRequired')}</p> : null}

        {mfaGate ? (
          <MfaSettings onChanged={() => window.location.reload()} />
        ) : tab === 'users' ? (
          <UsersPanel
            users={users}
            groups={groups}
            writable={settings?.connector.writable ?? true}
            onChanged={refresh}
            onError={setError}
          />
        ) : null}
        {tab === 'groups' ? (
          <GroupsPanel
            groups={groups}
            writable={settings?.connector.writable ?? true}
            onChanged={refresh}
            onError={setError}
          />
        ) : null}
        {tab === 'clients' ? (
          <ClientsPanel clients={clients} groups={groups} onChanged={refresh} onError={setError} />
        ) : null}
        {tab === 'audit' ? <AuditPanel onError={setError} /> : null}
        {tab === 'settings' && settings ? (
          <SettingsPanel settings={settings} onChanged={refresh} onError={setError} />
        ) : null}
      </main>
    </div>
  )
}

function EmptyRow({ cols }: { cols: number }) {
  const { t } = useI18n()
  return (
    <tr>
      <td colSpan={cols} className="empty">
        <span className="with-icon">
          <Icon icon={Inbox} />
          {t('emptyList')}
        </span>
      </td>
    </tr>
  )
}

function UsersPanel({
  users,
  groups,
  writable,
  onChanged,
  onError,
}: {
  users: DirectoryUser[]
  groups: Group[]
  writable: boolean
  onChanged: () => Promise<void>
  onError: (message: string) => void
}) {
  const { t } = useI18n()
  const { password_policy: policy } = useAppearance()
  const [editing, setEditing] = useState<DirectoryUser | null>(null)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [emailVerified, setEmailVerified] = useState(false)
  const [groupIds, setGroupIds] = useState<string[]>([])
  const [formOpen, setFormOpen] = useState(false)
  const [formError, setFormError] = useState('')

  function resetForm() {
    setEditing(null)
    setUsername('')
    setPassword('')
    setEmail('')
    setName('')
    setEnabled(true)
    setEmailVerified(false)
    setGroupIds([])
    setFormError('')
    setFormOpen(false)
  }

  function startCreate() {
    resetForm()
    setFormOpen(true)
  }

  function startEdit(user: DirectoryUser) {
    setFormError('')
    setFormOpen(true)
    setEditing(user)
    setUsername(user.username)
    setPassword('')
    setEmail(user.email || '')
    setName(user.name || '')
    setEnabled(user.enabled !== false)
    setEmailVerified(user.email_verified === true)
    setGroupIds([...(user.group_ids || [])])
  }

  async function submitUser(event: FormEvent) {
    event.preventDefault()
    try {
      if (editing) {
        const payload: Record<string, unknown> = {
          username,
          email,
          name,
          enabled,
          email_verified: emailVerified,
          group_ids: groupIds,
        }
        if (password) payload.password = password
        await api.users.update(editing.id, payload)
      } else {
        await api.users.create({
          username,
          password,
          email,
          name,
          group_ids: groupIds,
          enabled,
          email_verified: emailVerified,
        })
      }
      resetForm()
      await onChanged()
    } catch (err) {
      setFormError(err instanceof Error ? err.message : t('demoError'))
    }
  }

  return (
    <>
      <section className="panel">
        <div className="panel-title has-actions">
          <h2 className="panel-heading">
            <Icon icon={Users} />
            {t('usersTitle')}
            <span className="count">{users.length}</span>
          </h2>
          {writable ? (
            <button className="btn with-icon" type="button" onClick={startCreate}>
              <Icon icon={Plus} />
              {t('usersNew')}
            </button>
          ) : null}
        </div>
        {!writable ? <p className="muted">{t('usersReadonly')}</p> : null}
        <div className="table-wrap">
          <table className="table responsive">
            <thead>
              <tr>
                <th>{t('usersUsername')}</th>
                <th>{t('usersName')}</th>
                <th>{t('usersGroups')}</th>
                <th>{t('mfaTitle')}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {users.length === 0 ? <EmptyRow cols={5} /> : null}
              {users.map((u) => (
                <tr key={u.id} className={editing?.id === u.id ? 'is-selected' : undefined}>
                  <td className="mono cell-primary" data-label={t('usersUsername')}>
                    {u.username}
                    {u.enabled === false ? (
                      <div>
                        <span className="badge fail">{t('usersDisabled')}</span>
                      </div>
                    ) : null}
                  </td>
                  <td data-label={t('usersName')}>
                    <div>
                      {u.name}
                      <div className="muted">{u.email}</div>
                    </div>
                  </td>
                  <td data-label={t('usersGroups')}>
                    {(u.groups || []).map((g) => (
                      <span className="pill" key={g}>
                        {g}
                      </span>
                    ))}
                  </td>
                  <td data-label={t('mfaTitle')}>
                    {u.mfa_enabled ? (
                      <span className="badge ok">{t('mfaEnabled')}</span>
                    ) : (
                      <span className="badge">{t('mfaDisabled')}</span>
                    )}
                  </td>
                  <td className="cell-actions">
                    <div className="row">
                    {writable ? (
                      <button className="btn secondary with-icon" type="button" onClick={() => startEdit(u)}>
                        <Icon icon={Pencil} size={14} />
                        {t('usersEdit')}
                      </button>
                    ) : null}
                    {u.mfa_enabled ? (
                      <button
                        className="btn ghost with-icon"
                        type="button"
                        onClick={() =>
                          void api.users
                            .resetMfa(u.id)
                            .then(onChanged)
                            .catch((err) => onError(err.message))
                        }
                      >
                        <Icon icon={ShieldOff} size={14} />
                        {t('mfaReset')}
                      </button>
                    ) : null}
                    {writable ? (
                      <button
                        className="btn danger with-icon"
                        type="button"
                        onClick={() =>
                          void api.users
                            .remove(u.id)
                            .then(() => {
                              if (editing?.id === u.id) resetForm()
                              return onChanged()
                            })
                            .catch((err) => onError(err.message))
                        }
                      >
                        <Icon icon={Trash2} size={14} />
                        {t('usersDelete')}
                      </button>
                    ) : null}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <Sheet
        open={formOpen}
        icon={editing ? Pencil : Plus}
        title={editing ? `${t('usersEdit')} · ${editing.username}` : t('usersNew')}
        onClose={resetForm}
      >
        <form className="stack" onSubmit={submitUser}>
          <label>
            {t('usersUsername')}
            <input value={username} onChange={(e) => setUsername(e.target.value)} required disabled={!writable} />
          </label>
          <label>
            {editing ? t('usersPasswordOptional') : t('usersPassword')}
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required={!editing}
              minLength={editing && !password ? undefined : policy.min_length}
              disabled={!writable}
            />
          </label>
          <p className="muted">{passwordPolicyHint(policy, t)}</p>
          <label>
            {t('usersName')}
            <input value={name} onChange={(e) => setName(e.target.value)} disabled={!writable} />
          </label>
          <label>
            {t('usersEmail')}
            <input value={email} onChange={(e) => setEmail(e.target.value)} disabled={!writable} />
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={enabled}
              disabled={!writable}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <span>{t('usersEnabled')}</span>
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={emailVerified}
              disabled={!writable}
              onChange={(e) => setEmailVerified(e.target.checked)}
            />
            <span>{t('usersEmailVerified')}</span>
          </label>
          <div>
            <div className="copy-label">{t('usersGroups')}</div>
            <CheckList
              items={groups.map((group) => ({ value: group.id, label: group.name }))}
              value={groupIds}
              onChange={setGroupIds}
              disabled={!writable}
            />
          </div>
          {formError ? <p className="error">{formError}</p> : null}
          <div className="sheet-actions">
            <button className="btn secondary" type="button" onClick={resetForm}>
              {t('usersCancel')}
            </button>
            <button className="btn with-icon" type="submit" disabled={!writable}>
              <Icon icon={editing ? Save : Plus} />
              {editing ? t('usersSave') : t('usersCreate')}
            </button>
          </div>
        </form>
      </Sheet>
    </>
  )
}

function GroupsPanel({
  groups,
  writable,
  onChanged,
  onError,
}: {
  groups: Group[]
  writable: boolean
  onChanged: () => Promise<void>
  onError: (message: string) => void
}) {
  const { t } = useI18n()
  const [editing, setEditing] = useState<Group | null>(null)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [formOpen, setFormOpen] = useState(false)
  const [formError, setFormError] = useState('')

  function resetForm() {
    setEditing(null)
    setName('')
    setDescription('')
    setFormError('')
    setFormOpen(false)
  }

  function startCreate() {
    resetForm()
    setFormOpen(true)
  }

  function startEdit(group: Group) {
    setFormError('')
    setFormOpen(true)
    setEditing(group)
    setName(group.name)
    setDescription(group.description || '')
  }

  async function submitGroup(event: FormEvent) {
    event.preventDefault()
    try {
      if (editing) {
        await api.groups.update(editing.id, { name, description })
      } else {
        await api.groups.create({ name, description })
      }
      resetForm()
      await onChanged()
    } catch (err) {
      setFormError(err instanceof Error ? err.message : t('demoError'))
    }
  }

  return (
    <>
      <section className="panel">
        <div className="panel-title has-actions">
          <h2 className="panel-heading">
            <Icon icon={Tags} />
            {t('groupsTitle')}
            <span className="count">{groups.length}</span>
          </h2>
          {writable ? (
            <button className="btn with-icon" type="button" onClick={startCreate}>
              <Icon icon={Plus} />
              {t('groupsNew')}
            </button>
          ) : null}
        </div>
        {!writable ? <p className="muted">{t('groupsReadonly')}</p> : null}
        <div className="table-wrap">
          <table className="table responsive">
            <thead>
              <tr>
                <th>{t('groupsName')}</th>
                <th>{t('groupsDescription')}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {groups.length === 0 ? <EmptyRow cols={3} /> : null}
              {groups.map((group) => (
                <tr key={group.id} className={editing?.id === group.id ? 'is-selected' : undefined}>
                  <td className="cell-primary" data-label={t('groupsName')}>{group.name}</td>
                  <td className="muted" data-label={t('groupsDescription')}>{group.description}</td>
                  <td className="cell-actions">
                    <div className="row">
                      {writable ? (
                        <button className="btn secondary with-icon" type="button" onClick={() => startEdit(group)}>
                          <Icon icon={Pencil} size={14} />
                          {t('groupsEdit')}
                        </button>
                      ) : null}
                      {writable ? (
                        <button
                          className="btn danger with-icon"
                          type="button"
                          onClick={() =>
                            void api.groups
                              .remove(group.id)
                              .then(() => {
                                if (editing?.id === group.id) resetForm()
                                return onChanged()
                              })
                              .catch((err) => onError(err.message))
                          }
                        >
                          <Icon icon={Trash2} size={14} />
                          {t('groupsDelete')}
                        </button>
                      ) : null}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <Sheet
        open={formOpen}
        icon={editing ? Pencil : Plus}
        title={editing ? `${t('groupsEdit')} · ${editing.name}` : t('groupsNew')}
        onClose={resetForm}
      >
        <form className="stack" onSubmit={submitGroup}>
          <label>
            {t('groupsName')}
            <input value={name} onChange={(e) => setName(e.target.value)} required disabled={!writable} />
          </label>
          <label>
            {t('groupsDescription')}
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              disabled={!writable}
            />
          </label>
          {formError ? <p className="error">{formError}</p> : null}
          <div className="sheet-actions">
            <button className="btn secondary" type="button" onClick={resetForm}>
              {t('groupsCancel')}
            </button>
            <button className="btn with-icon" type="submit" disabled={!writable}>
              <Icon icon={editing ? Save : Plus} />
              {editing ? t('groupsSave') : t('groupsCreate')}
            </button>
          </div>
        </form>
      </Sheet>
    </>
  )
}

function linesToList(value: string): string[] {
  return value
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
}

function ClientsPanel({
  clients,
  groups,
  onChanged,
  onError,
}: {
  clients: Client[]
  groups: Group[]
  onChanged: () => Promise<void>
  onError: (message: string) => void
}) {
  const { t } = useI18n()
  const [editing, setEditing] = useState<Client | null>(null)
  const [clientId, setClientId] = useState('')
  const [clientName, setClientName] = useState('')
  const [redirectUris, setRedirectUris] = useState('http://localhost:5173/demo/callback')
  const [logoutUris, setLogoutUris] = useState('')
  const [allowedGroups, setAllowedGroups] = useState<string[]>([])
  const [forwardUrls, setForwardUrls] = useState('')
  const [mode, setMode] = useState<'oidc' | 'forward'>('oidc')
  const [auth, setAuth] = useState<'secret' | 'pkce'>('secret')
  const [secretOnce, setSecretOnce] = useState('')
  const [secretFor, setSecretFor] = useState('')
  const [formOpen, setFormOpen] = useState(false)
  const [formError, setFormError] = useState('')

  function resetForm() {
    setEditing(null)
    setClientId('')
    setClientName('')
    setRedirectUris('http://localhost:5173/demo/callback')
    setLogoutUris('')
    setAllowedGroups([])
    setForwardUrls('')
    setMode('oidc')
    setAuth('secret')
    setSecretOnce('')
    setSecretFor('')
    setFormError('')
    setFormOpen(false)
  }

  function showSecret(id: string, secret: string | undefined) {
    if (!secret) return
    setSecretFor(id)
    setSecretOnce(secret)
    setFormOpen(true)
  }

  function startCreate() {
    resetForm()
    setFormOpen(true)
  }

  function startEdit(client: Client) {
    setFormError('')
    setFormOpen(true)
    setEditing(client)
    setClientId(client.client_id)
    setClientName(client.client_name)
    setRedirectUris((client.redirect_uris || []).join('\n'))
    setLogoutUris((client.post_logout_redirect_uris || []).join('\n'))
    setAllowedGroups([...(client.allowed_groups || [])])
    setForwardUrls((client.origins || []).join('\n'))
    setMode(client.mode === 'forward' ? 'forward' : 'oidc')
    setAuth(client.token_endpoint_auth_method === 'none' ? 'pkce' : 'secret')
    setSecretOnce('')
  }

  async function submitClient(event: FormEvent) {
    event.preventDefault()
    const payload = {
      client_name: clientName || clientId,
      mode,
      redirect_uris: mode === 'oidc' ? linesToList(redirectUris) : [],
      post_logout_redirect_uris: mode === 'oidc' ? linesToList(logoutUris) : [],
      allowed_groups: allowedGroups,
      origins: mode === 'forward' ? linesToList(forwardUrls) : [],
    }
    const withSecret = mode === 'oidc' && auth === 'secret'
    try {
      if (editing) {
        const updated = await api.clients.update(editing.client_id, {
          ...payload,
          ...(mode === 'oidc'
            ? {
                token_endpoint_auth_method: withSecret
                  ? editing.token_endpoint_auth_method === 'none'
                    ? 'client_secret_post'
                    : editing.token_endpoint_auth_method
                  : 'none',
                rotate_secret: withSecret && !editing.has_secret,
              }
            : {}),
        })
        resetForm()
        showSecret(updated.client_id, updated.client_secret)
      } else {
        const created = await api.clients.create({
          client_id: clientId,
          ...payload,
          token_endpoint_auth_method: withSecret ? 'client_secret_post' : 'none',
          generate_secret: withSecret,
        })
        resetForm()
        showSecret(created.client_id, created.client_secret)
      }
      await onChanged()
    } catch (err) {
      setFormError(localizeError(err, t, 'demoError'))
    }
  }

  const secretLabel = t('clientsSecretOnce', { secret: '' }).replace(/\s*:\s*$/, '')

  return (
    <>
      <section className="panel">
        <div className="panel-title has-actions">
          <h2 className="panel-heading">
            <Icon icon={AppWindow} />
            {t('clientsTitle')}
            <span className="count">{clients.length}</span>
          </h2>
          <button className="btn with-icon" type="button" onClick={startCreate}>
            <Icon icon={Plus} />
            {t('clientsNew')}
          </button>
        </div>
        <div className="table-wrap">
          <table className="table responsive">
            <thead>
              <tr>
                <th>{t('clientsId')}</th>
                <th>{t('clientsMode')}</th>
                <th>{t('clientsGroups')}</th>
                <th>{t('clientsUrls')}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {clients.length === 0 ? <EmptyRow cols={5} /> : null}
              {clients.map((client) => (
                <tr key={client.client_id} className={editing?.client_id === client.client_id ? 'is-selected' : undefined}>
                  <td className="cell-primary" data-label={t('clientsId')}>
                    <div>
                      <div className="mono">{client.client_id}</div>
                      <div className="muted">{client.client_name}</div>
                    </div>
                  </td>
                  <td data-label={t('clientsMode')}>
                    <span className="pill">
                      {client.mode === 'forward' ? t('clientsModeForward') : t('clientsModeOidc')}
                    </span>
                    {client.mode === 'oidc' ? (
                      <span className="pill">
                        {client.token_endpoint_auth_method === 'none' ? t('clientsAuthPkce') : t('clientsAuthSecret')}
                      </span>
                    ) : null}
                  </td>
                  <td data-label={t('clientsGroups')}>
                    {(client.allowed_groups || []).length === 0 ? (
                      <span className="muted">{t('auditAll')}</span>
                    ) : (
                      (client.allowed_groups || []).map((name) => (
                        <span className="pill" key={name}>
                          {name}
                        </span>
                      ))
                    )}
                  </td>
                  <td className="cell-urls" data-label={t('clientsUrls')}>
                    <div>
                      {(client.mode === 'forward' ? client.origins : client.redirect_uris || []).map((uri) => (
                        <div className="mono" key={uri}>
                          {uri}
                        </div>
                      ))}
                    </div>
                  </td>
                  <td className="cell-actions">
                    <div className="row">
                      <button className="btn secondary with-icon" type="button" onClick={() => startEdit(client)}>
                        <Icon icon={Pencil} size={14} />
                        {t('clientsEdit')}
                      </button>
                      <button
                        className="btn danger with-icon"
                        type="button"
                        onClick={() =>
                          void api.clients
                            .remove(client.client_id)
                            .then(() => {
                              if (editing?.client_id === client.client_id) resetForm()
                              return onChanged()
                            })
                            .catch((err) => onError(err.message))
                        }
                      >
                        <Icon icon={Trash2} size={14} />
                        {t('clientsDelete')}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <Sheet
        open={formOpen}
        icon={secretOnce ? KeyRound : editing ? Pencil : Plus}
        title={
          secretOnce
            ? `${secretLabel} · ${secretFor}`
            : editing
              ? `${t('clientsEdit')} · ${editing.client_id}`
              : t('clientsNew')
        }
        onClose={resetForm}
      >
        {secretOnce ? (
          <div className="stack">
            <CopyField value={secretOnce} />
            <p className="muted" style={{ margin: 0 }}>
              {t('clientsSecretHint')}
            </p>
            <div className="sheet-actions">
              <button className="btn" type="button" onClick={resetForm}>
                {t('done')}
              </button>
            </div>
          </div>
        ) : (
          <form className="stack" onSubmit={submitClient}>
            <label>
              {t('clientsId')}
              <input value={clientId} onChange={(e) => setClientId(e.target.value)} required disabled={Boolean(editing)} />
            </label>
            <label>
              {t('clientsName')}
              <input value={clientName} onChange={(e) => setClientName(e.target.value)} />
            </label>
            <div>
              <div className="copy-label">{t('clientsMode')}</div>
              <div className="theme-picker">
                <button
                  className={`theme-swatch ${mode === 'oidc' ? 'active' : ''}`}
                  type="button"
                  onClick={() => setMode('oidc')}
                >
                  {t('clientsModeOidc')}
                </button>
                <button
                  className={`theme-swatch ${mode === 'forward' ? 'active' : ''}`}
                  type="button"
                  onClick={() => setMode('forward')}
                >
                  {t('clientsModeForward')}
                </button>
              </div>
              <p className="muted" style={{ margin: '0.4rem 0 0' }}>
                {mode === 'forward' ? t('clientsModeForwardHint') : t('clientsModeOidcHint')}
              </p>
            </div>
            {mode === 'oidc' ? (
              <>
                <div>
                  <div className="copy-label">{t('clientsAuth')}</div>
                  <div className="theme-picker">
                    <button
                      className={`theme-swatch ${auth === 'secret' ? 'active' : ''}`}
                      type="button"
                      onClick={() => setAuth('secret')}
                    >
                      {t('clientsAuthSecret')}
                    </button>
                    <button
                      className={`theme-swatch ${auth === 'pkce' ? 'active' : ''}`}
                      type="button"
                      onClick={() => setAuth('pkce')}
                    >
                      {t('clientsAuthPkce')}
                    </button>
                  </div>
                  <p className="muted" style={{ margin: '0.4rem 0 0' }}>
                    {auth === 'pkce' ? t('clientsAuthPkceHint') : t('clientsAuthSecretHint')}
                  </p>
                </div>
                <label>
                  {t('clientsRedirects')}
                  <textarea value={redirectUris} onChange={(e) => setRedirectUris(e.target.value)} required />
                </label>
                <label>
                  {t('clientsLogoutRedirects')}
                  <textarea value={logoutUris} onChange={(e) => setLogoutUris(e.target.value)} />
                </label>
              </>
            ) : (
              <label>
                {t('clientsForward')}
                <textarea
                  value={forwardUrls}
                  onChange={(e) => setForwardUrls(e.target.value)}
                  placeholder="https://app.example.com"
                  required
                />
              </label>
            )}
            <div>
              <div className="copy-label">{t('clientsGroups')}</div>
              <CheckList
                items={groups.map((group) => ({ value: group.name, label: group.name }))}
                value={allowedGroups}
                onChange={setAllowedGroups}
              />
              <p className="muted" style={{ margin: '0.4rem 0 0' }}>
                {t('clientsGroupsHint')}
              </p>
            </div>
            {formError ? <p className="error">{formError}</p> : null}
            <div className="sheet-actions">
              {editing?.has_secret && mode === 'oidc' && auth === 'secret' ? (
                <button
                  className="btn ghost with-icon sheet-aside"
                  type="button"
                  onClick={() =>
                    void api.clients
                      .update(editing.client_id, { rotate_secret: true })
                      .then((updated) => {
                        showSecret(editing.client_id, updated.client_secret)
                        return onChanged()
                      })
                      .catch((err) => setFormError(localizeError(err, t, 'demoError')))
                  }
                >
                  <Icon icon={KeyRound} />
                  {t('clientsRotateSecret')}
                </button>
              ) : null}
              <button className="btn secondary" type="button" onClick={resetForm}>
                {t('clientsCancel')}
              </button>
              <button className="btn with-icon" type="submit">
                <Icon icon={editing ? Save : Plus} />
                {editing ? t('clientsSave') : mode === 'forward' ? t('clientsCreateForward') : t('clientsCreate')}
              </button>
            </div>
          </form>
        )}
      </Sheet>
    </>
  )
}

function toUnix(value: string, end = false): number | undefined {
  if (!value) return undefined
  const ts = Date.parse(value)
  if (Number.isNaN(ts)) return undefined
  let seconds = Math.floor(ts / 1000)
  if (end && !/:\d{2}:\d{2}/.test(value)) seconds += 59
  return seconds
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} o`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} Ko`
  return `${(value / (1024 * 1024)).toFixed(1)} Mo`
}

function AuditPanel({ onError }: { onError: (message: string) => void }) {
  const { t, locale } = useI18n()
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [rotation, setRotation] = useState<AuditRotation | null>(null)
  const [action, setAction] = useState('')
  const [outcome, setOutcome] = useState('')
  const [query, setQuery] = useState('')
  const [actor, setActor] = useState('')
  const [target, setTarget] = useState('')
  const [ip, setIp] = useState('')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [busy, setBusy] = useState(false)

  async function load() {
    try {
      const data = await api.audit({
        limit: 200,
        action: action || undefined,
        outcome: outcome || undefined,
        q: query.trim() || undefined,
        actor: actor.trim() || undefined,
        target: target.trim() || undefined,
        ip: ip.trim() || undefined,
        since: toUnix(from),
        until: toUnix(to, true),
      })
      setEvents(data.events)
      setRotation(data.rotation)
    } catch (err) {
      onError(err instanceof Error ? err.message : t('demoError'))
    }
  }

  useEffect(() => {
    const delay = query || actor || target || ip || from || to ? 250 : 0
    const timer = window.setTimeout(() => void load(), delay)
    return () => window.clearTimeout(timer)
  }, [action, outcome, query, actor, target, ip, from, to])

  async function rotate() {
    if (!window.confirm(t('auditRotateConfirm'))) return
    setBusy(true)
    try {
      await api.rotateAudit()
      await load()
    } catch (err) {
      onError(err instanceof Error ? err.message : t('demoError'))
    } finally {
      setBusy(false)
    }
  }

  const dateFmt = new Intl.DateTimeFormat(locale, {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })

  return (
    <section className="panel">
      <div className="panel-title has-actions">
        <h2 className="panel-heading">
          <Icon icon={ScrollText} />
          {t('auditTitle')}
        </h2>
        <div className="row">
          <button className="btn secondary with-icon" type="button" onClick={() => void load()}>
            <Icon icon={RefreshCw} />
            {t('auditRefresh')}
          </button>
          <button className="btn secondary with-icon" type="button" disabled={busy} onClick={() => void rotate()}>
            <Icon icon={Archive} />
            {t('auditRotate')}
          </button>
        </div>
      </div>
      <p>{t('auditLead')}</p>
      {rotation ? (
        <p className="muted">
          {t('auditRotation', {
            current: formatBytes(rotation.current_bytes),
            max: formatBytes(rotation.max_bytes),
            count: String(rotation.archives.length),
          })}
        </p>
      ) : null}
      <div className="audit-filters">
        <label>
          {t('auditQuery')}
          <input value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>
        <label>
          {t('auditActor')}
          <input value={actor} onChange={(e) => setActor(e.target.value)} />
        </label>
        <label>
          {t('auditTarget')}
          <input value={target} onChange={(e) => setTarget(e.target.value)} />
        </label>
        <label>
          {t('auditIp')}
          <input value={ip} onChange={(e) => setIp(e.target.value)} />
        </label>
        <label>
          {t('auditFrom')}
          <input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} />
        </label>
        <label>
          {t('auditTo')}
          <input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} />
        </label>
        <label>
          {t('auditAction')}
          <select value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">{t('auditAll')}</option>
            {AUDIT_ACTIONS.map((item) => (
              <option key={item.value} value={item.value}>
                {t(item.key)}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t('auditOutcome')}
          <select value={outcome} onChange={(e) => setOutcome(e.target.value)}>
            <option value="">{t('auditAll')}</option>
            <option value="success">{t('auditSuccess')}</option>
            <option value="failure">{t('auditFailure')}</option>
            <option value="denied">{t('auditDenied')}</option>
          </select>
        </label>
      </div>
      <div className="table-wrap">
        <table className="table responsive">
          <thead>
            <tr>
              <th>{t('auditTime')}</th>
              <th>{t('auditAction')}</th>
              <th>{t('auditOutcome')}</th>
              <th>{t('auditActor')}</th>
              <th>{t('auditTarget')}</th>
              <th>{t('auditIp')}</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <EmptyRow cols={6} />
            ) : (
              events.map((event) => {
                const extra = auditDetail(event, t)
                return (
                  <tr key={event.id}>
                    <td className="cell-head cell-time">{dateFmt.format(new Date(event.ts * 1000))}</td>
                    <td className="cell-head cell-primary">
                      <div className="audit-action">
                        <strong>{auditActionLabel(event.action, t)}</strong>
                        {extra ? <small>{extra}</small> : null}
                      </div>
                    </td>
                    <td data-label={t('auditOutcome')}>
                      <span className={`badge ${auditOutcomeClass(event.outcome)}`}>
                        {auditOutcomeLabel(event.outcome, t)}
                      </span>
                    </td>
                    <td data-label={t('auditActor')}>{event.actor || '—'}</td>
                    <td data-label={t('auditTarget')}>{event.target || event.client_id || '—'}</td>
                    <td className="mono" data-label={t('auditIp')}>{event.ip || '—'}</td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}

const THEME_KEYS: Record<LoginTheme, keyof Messages> = {
  classic: 'settingsThemeClassic',
  slate: 'settingsThemeSlate',
  light: 'settingsThemeLight',
  contrast: 'settingsThemeContrast',
}

const COLOR_KEYS: { key: 'background' | 'panel' | 'ink' | 'accent'; label: keyof Messages }[] = [
  { key: 'background', label: 'settingsColorBackground' },
  { key: 'panel', label: 'settingsColorPanel' },
  { key: 'ink', label: 'settingsColorInk' },
  { key: 'accent', label: 'settingsColorAccent' },
]

const POLICY_RULES: { key: Exclude<keyof PasswordPolicy, 'min_length'>; label: keyof Messages }[] = [
  { key: 'require_letter', label: 'settingsPasswordLetter' },
  { key: 'require_digit', label: 'settingsPasswordDigit' },
  { key: 'require_upper', label: 'settingsPasswordUpper' },
  { key: 'require_special', label: 'settingsPasswordSpecial' },
  { key: 'forbid_username', label: 'settingsPasswordUsername' },
]

function colorInputValue(hex: string): string {
  const raw = hex.replace('#', '')
  const full = raw.length === 3 ? raw.split('').map((ch) => ch + ch).join('') : raw
  return full.length === 6 ? `#${full}` : '#000000'
}

function ProxyInfo({ proxy }: { proxy: AdminSettings['proxy'] }) {
  const { t } = useI18n()
  const status = proxy.peer_trusted
    ? { className: 'hint', text: t('settingsProxyOk') }
    : proxy.forwarded_headers
      ? { className: 'error', text: t('settingsProxyUntrusted', { peer: proxy.peer || '?' }) }
      : { className: 'hint', text: t('settingsProxyDirect') }

  return (
    <div className="settings-sub stack">
      <div>
        <h3 className="with-icon">
          <Icon icon={Network} size={15} />
          {t('settingsProxyTitle')}
        </h3>
        <p>{t('settingsProxyBody')}</p>
      </div>
      <dl className="kv">
        <dt>{t('settingsProxyTrusted')}</dt>
        <dd>
          {proxy.trusted_proxies.length ? (
            proxy.trusted_proxies.map((item) => (
              <span className="pill mono" key={item}>
                {item}
              </span>
            ))
          ) : (
            <span className="muted">{t('settingsProxyNone')}</span>
          )}
        </dd>
        <dt>{t('settingsProxyPeer')}</dt>
        <dd className="mono">{proxy.peer || '—'}</dd>
        <dt>{t('settingsProxyClient')}</dt>
        <dd className="mono">{proxy.client_ip || '—'}</dd>
      </dl>
      <p className={status.className} style={{ margin: 0 }}>
        {status.text}
      </p>
    </div>
  )
}

function SettingsPanel({
  settings,
  onChanged,
  onError,
}: {
  settings: AdminSettings
  onChanged: () => Promise<void>
  onError: (message: string) => void
}) {
  const { t } = useI18n()
  const appearance = useAppearance()
  const [busy, setBusy] = useState(false)
  const [themeBusy, setThemeBusy] = useState(false)
  const [pagesBusy, setPagesBusy] = useState(false)
  const [policyBusy, setPolicyBusy] = useState(false)
  const [sessionBusy, setSessionBusy] = useState(false)
  const [policy, setPolicy] = useState<PasswordPolicy>(settings.password_policy)
  const [session, setSession] = useState<SessionPolicy>(settings.session_policy)
  const [branding, setBranding] = useState<LoginBranding>(
    resolvedBranding(settings.login_theme, settings.login_branding || EMPTY_BRANDING),
  )
  const [brandingBusy, setBrandingBusy] = useState(false)
  const [done, setDone] = useState<'' | 'branding' | 'policy' | 'session' | 'crypto'>('')

  useEffect(() => {
    setPolicy(settings.password_policy)
  }, [settings.password_policy])

  useEffect(() => {
    setSession(settings.session_policy)
  }, [settings.session_policy])

  useEffect(() => {
    setBranding(resolvedBranding(settings.login_theme, settings.login_branding || EMPTY_BRANDING))
  }, [settings.login_theme, settings.login_branding])
  const files = [
    settings.init.directory,
    settings.init.identities,
    settings.init.clients,
    settings.init.runtime,
    settings.init.jwks,
    settings.init.audit,
  ].filter(Boolean)

  async function savePages(key: 'enable_demo' | 'enable_help', value: boolean) {
    setPagesBusy(true)
    try {
      await api.updateSettings({ [key]: value })
      await appearance.refresh()
      await onChanged()
    } catch (err) {
      onError(err instanceof Error ? err.message : t('demoError'))
    } finally {
      setPagesBusy(false)
    }
  }

  async function savePolicy() {
    setPolicyBusy(true)
    setDone('')
    try {
      await api.updateSettings({ password_policy: policy })
      await appearance.refresh()
      await onChanged()
      setDone('policy')
    } catch (err) {
      onError(err instanceof Error ? err.message : t('demoError'))
    } finally {
      setPolicyBusy(false)
    }
  }

  async function saveSession() {
    setSessionBusy(true)
    setDone('')
    try {
      await api.updateSettings({ session_policy: session })
      await onChanged()
      setDone('session')
    } catch (err) {
      onError(err instanceof Error ? err.message : t('demoError'))
    } finally {
      setSessionBusy(false)
    }
  }

  function setSessionMinutes(key: 'idle_seconds' | 'absolute_seconds', minutes: number) {
    setSession({ ...session, [key]: Math.round(minutes * 60) })
  }

  async function saveTheme(theme: LoginTheme) {
    setThemeBusy(true)
    try {
      const next = { ...branding, ...THEME_COLORS[theme] }
      await api.updateSettings({ login_theme: theme, login_branding: next })
      setBranding(next)
      await appearance.refresh()
      await onChanged()
    } catch (err) {
      onError(err instanceof Error ? err.message : t('demoError'))
    } finally {
      setThemeBusy(false)
    }
  }

  async function saveBranding() {
    setBrandingBusy(true)
    setDone('')
    try {
      await api.updateSettings({ login_branding: branding })
      await appearance.refresh()
      await onChanged()
      setDone('branding')
    } catch (err) {
      onError(err instanceof Error ? err.message : t('demoError'))
    } finally {
      setBrandingBusy(false)
    }
  }

  function onLogo(file: File | undefined) {
    if (!file) return
    if (!/^image\/(png|jpeg|webp|gif)$/.test(file.type) || file.size > 160_000) {
      onError(t('settingsLogoInvalid'))
      return
    }
    const reader = new FileReader()
    reader.onload = () => {
      const data = String(reader.result || '')
      if (data.length > 220_000) {
        onError(t('settingsLogoInvalid'))
        return
      }
      setBranding((current) => ({ ...current, logo: data }))
    }
    reader.readAsDataURL(file)
  }

  async function resetCrypto() {
    if (!window.confirm(t('settingsCryptoConfirm'))) return
    setBusy(true)
    setDone('')
    try {
      await api.resetCrypto()
      await onChanged()
      setDone('crypto')
    } catch (err) {
      onError(err instanceof Error ? err.message : t('demoError'))
    } finally {
      setBusy(false)
    }
  }

  const saved = (
    <span className="saved-note with-icon">
      <Icon icon={Check} size={14} />
      {t('saved')}
    </span>
  )

  return (
    <div className="settings-stack">
      <section className="panel stack">
        <div>
          <h2 className="panel-heading">
            <Icon icon={Palette} />
            {t('settingsThemeTitle')}
          </h2>
          <p>{t('settingsThemeBody')}</p>
        </div>
        <div className="theme-picker">
          {LOGIN_THEMES.map((theme) => (
            <button
              key={theme}
              className={`theme-swatch ${settings.login_theme === theme ? 'active' : ''}`}
              type="button"
              disabled={themeBusy || brandingBusy}
              onClick={() => void saveTheme(theme)}
            >
              <span className={`theme-swatch-preview ${theme}`} />
              {t(THEME_KEYS[theme])}
            </button>
          ))}
        </div>
        <div className="login-preview" style={brandingStyle(branding)}>
          <div className="login-preview-card">
            {branding.logo ? (
              <img className="auth-logo" src={branding.logo} alt="" />
            ) : (
              <BrandMark />
            )}
            <span className="login-preview-text">
              <strong>{portalName(branding, settings.issuer)}</strong>
              {branding.subtitle ? <small>{branding.subtitle}</small> : null}
            </span>
          </div>
        </div>
        <div className="field-row">
          <label>
            {t('settingsBrandTitle')}
            <input
              value={branding.title}
              maxLength={80}
              placeholder={portalName({ title: '' }, settings.issuer)}
              onChange={(event) => setBranding({ ...branding, title: event.target.value })}
            />
          </label>
          <label>
            {t('settingsBrandSubtitle')}
            <input
              value={branding.subtitle}
              maxLength={80}
              placeholder={t('settingsBrandSubtitleHint')}
              onChange={(event) => setBranding({ ...branding, subtitle: event.target.value })}
            />
          </label>
        </div>
        <p className="muted field-hint">{t('settingsBrandTitleHint')}</p>
        <div className="color-fields">
          {COLOR_KEYS.map(({ key, label }) => (
            <label key={key} className="color-field">
              {t(label)}
              <input
                type="color"
                value={colorInputValue(branding[key])}
                onChange={(event) => setBranding({ ...branding, [key]: event.target.value })}
              />
            </label>
          ))}
        </div>
        <div>
          <div className="copy-label">{t('settingsLogo')}</div>
          <div className="logo-preview">
            <input
              type="file"
              accept="image/png,image/jpeg,image/webp,image/gif"
              onChange={(event) => {
                onLogo(event.target.files?.[0])
                event.target.value = ''
              }}
            />
            {branding.logo ? (
              <button
                className="btn secondary"
                type="button"
                onClick={() => setBranding({ ...branding, logo: '' })}
              >
                {t('settingsLogoClear')}
              </button>
            ) : null}
          </div>
          <p className="muted field-hint">{t('settingsLogoHint')}</p>
        </div>
        <div className="panel-actions">
          {done === 'branding' ? saved : null}
          <button className="btn with-icon" type="button" disabled={brandingBusy} onClick={() => void saveBranding()}>
            <Icon icon={Save} />
            {t('settingsBrandingSave')}
          </button>
        </div>
      </section>

      <section className="panel stack">
        <div>
          <h2 className="panel-heading">
            <Icon icon={AppWindow} />
            {t('settingsPagesTitle')}
          </h2>
          <p>{t('settingsPagesBody')}</p>
        </div>
        <div className="check-grid">
          <label className="check">
            <input
              type="checkbox"
              checked={settings.enable_help}
              disabled={pagesBusy}
              onChange={(event) => void savePages('enable_help', event.target.checked)}
            />
            {t('settingsEnableHelp')}
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={settings.enable_demo}
              disabled={pagesBusy}
              onChange={(event) => void savePages('enable_demo', event.target.checked)}
            />
            {t('settingsEnableDemo')}
          </label>
        </div>
      </section>

      <section className="panel stack">
        <div>
          <h2 className="panel-heading">
            <Icon icon={Lock} />
            {t('settingsPasswordTitle')}
          </h2>
          <p>{t('settingsPasswordBody')}</p>
        </div>
        <label className="field-narrow">
          {t('settingsPasswordMin')}
          <input
            type="number"
            min={6}
            max={128}
            value={policy.min_length}
            onChange={(event) => setPolicy({ ...policy, min_length: Number(event.target.value) || 6 })}
          />
        </label>
        <div className="check-grid">
          {POLICY_RULES.map(({ key, label }) => (
            <label className="check" key={key}>
              <input
                type="checkbox"
                checked={policy[key]}
                onChange={(event) => setPolicy({ ...policy, [key]: event.target.checked })}
              />
              {t(label)}
            </label>
          ))}
        </div>
        <p className="muted field-hint">{passwordPolicyHint(policy, t)}</p>
        <div className="panel-actions">
          {done === 'policy' ? saved : null}
          <button className="btn with-icon" type="button" disabled={policyBusy} onClick={() => void savePolicy()}>
            <Icon icon={Save} />
            {t('settingsPasswordSave')}
          </button>
        </div>
      </section>

      <section className="panel stack">
        <div>
          <h2 className="panel-heading">
            <Icon icon={Clock} />
            {t('settingsSessionTitle')}
          </h2>
          <p>{t('settingsSessionBody')}</p>
        </div>
        <div className="field-row">
          <label>
            {t('settingsSessionIdle')}
            <input
              type="number"
              min={1}
              max={43200}
              value={Math.round(session.idle_seconds / 60)}
              onChange={(event) => setSessionMinutes('idle_seconds', Number(event.target.value))}
            />
          </label>
          <label>
            {t('settingsSessionAbsolute')}
            <input
              type="number"
              min={1}
              max={43200}
              value={Math.round(session.absolute_seconds / 60)}
              onChange={(event) => setSessionMinutes('absolute_seconds', Number(event.target.value))}
            />
          </label>
        </div>
        <p className="muted field-hint">{t('settingsSessionLimitHint')}</p>
        <label className="field-narrow">
          {t('settingsSessionTrust')}
          <input
            type="number"
            min={0}
            max={365}
            value={session.mfa_trust_days}
            onChange={(event) => setSession({ ...session, mfa_trust_days: Number(event.target.value) })}
          />
        </label>
        <p className="muted field-hint">{t('settingsSessionTrustHint')}</p>
        <div className="panel-actions">
          {done === 'session' ? saved : null}
          <button className="btn with-icon" type="button" disabled={sessionBusy} onClick={() => void saveSession()}>
            <Icon icon={Save} />
            {t('settingsSessionSave')}
          </button>
        </div>
      </section>

      <MfaSettings />

      <section className="panel stack">
        <div>
          <h2 className="panel-heading">
            <Icon icon={KeyRound} />
            {t('settingsCryptoTitle')}
          </h2>
          <p>{t('settingsCryptoBody')}</p>
        </div>
        {settings.init.signing_kid ? (
          <CopyField label={t('settingsCryptoKid')} value={settings.init.signing_kid} />
        ) : null}
        {done === 'crypto' ? <p className="hint">{t('settingsCryptoDone')}</p> : null}
        <div className="panel-actions">
          <button className="btn danger with-icon" type="button" disabled={busy} onClick={() => void resetCrypto()}>
            <Icon icon={RefreshCw} />
            {t('settingsCryptoReset')}
          </button>
        </div>
      </section>

      <section className="panel stack">
        <div>
          <h2 className="panel-heading">
            <Icon icon={Server} />
            {t('settingsServerTitle')}
          </h2>
          <p>{t('settingsStorage')}</p>
          {settings.connector.name === 'ldap' ? <p>{t('settingsLdapGroups')}</p> : null}
        </div>
        <CopyField label={t('settingsIssuer')} value={settings.issuer} />
        <CopyField label={t('settingsDiscovery')} value={settings.discovery_url} />
        <dl className="kv">
          <dt>{t('settingsConnector')}</dt>
          <dd>
            <span className="mono">{settings.connector.name}</span>
            {' · '}
            {settings.connector.writable ? t('settingsWritable') : t('settingsReadonly')}
          </dd>
          <dt>{t('settingsDataDir')}</dt>
          <dd className="mono">{settings.init.data_dir}</dd>
          <dt>{t('settingsFiles')}</dt>
          <dd>
            {files.map((name) => (
              <span className="pill mono" key={name}>
                {name}
              </span>
            ))}
          </dd>
          {settings.init.seed_username ? (
            <>
              <dt>{t('settingsSeed')}</dt>
              <dd className="mono">
                {settings.init.seed_username}
                {settings.init.seed_password ? ` / ${settings.init.seed_password}` : ''}
              </dd>
            </>
          ) : null}
        </dl>
        <ProxyInfo proxy={settings.proxy} />
      </section>
    </div>
  )
}
