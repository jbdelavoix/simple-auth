import { ArrowLeftRight, ArrowUpRight, Building2, IdCard, KeyRound, LogIn, LogOut } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Icon } from '../components/Icon'
import { useI18n } from '../i18n'
import { scopeHint, scopeTitle } from '../scopeLabels'

const DEMO_SCOPES = ['openid', 'profile', 'email', 'groups', 'offline_access'] as const

function b64url(bytes: Uint8Array) {
  let str = ''
  bytes.forEach((b) => {
    str += String.fromCharCode(b)
  })
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function decodeJwt(token: string): { header: unknown; payload: unknown } | null {
  const parts = token.split('.')
  if (parts.length < 2) return null
  try {
    const decode = (part: string) => {
      const padded = part.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (part.length % 4)) % 4)
      return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(padded), (c) => c.charCodeAt(0))))
    }
    return { header: decode(parts[0]), payload: decode(parts[1]) }
  } catch {
    return null
  }
}

// A second exchange of the same code makes the server revoke the tokens from
// the first one (StrictMode runs effects twice in dev).
const exchangedCodes = new Set<string>()

async function pkce() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)))
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return { verifier, challenge: b64url(new Uint8Array(digest)) }
}

export function DemoPage() {
  const { t } = useI18n()
  const [params] = useSearchParams()
  const code = params.get('code')
  const [tokens, setTokens] = useState<Record<string, unknown> | null>(null)
  const [userinfo, setUserinfo] = useState('')
  const [error, setError] = useState('')
  const [exchanging, setExchanging] = useState(false)
  const [scopes, setScopes] = useState<string[]>(() => {
    const stored = sessionStorage.getItem('demo_scopes')
    const picked = stored ? stored.split(' ').filter(Boolean) : [...DEMO_SCOPES]
    return picked.includes('openid') ? picked : ['openid', ...picked]
  })
  const loggedOut = params.get('state') === 'logged_out'

  function toggleScope(scope: string) {
    if (scope === 'openid') return
    setScopes((current) => {
      const next = current.includes(scope) ? current.filter((item) => item !== scope) : [...current, scope]
      const ordered = DEMO_SCOPES.filter((item) => next.includes(item))
      sessionStorage.setItem('demo_scopes', ordered.join(' '))
      return ordered
    })
  }

  async function startLogin() {
    setError('')
    const { verifier, challenge } = await pkce()
    const requested = DEMO_SCOPES.filter((item) => scopes.includes(item))
    sessionStorage.setItem('demo_verifier', verifier)
    sessionStorage.setItem('demo_scopes', requested.join(' '))
    const url = new URL('/oauth/authorize', window.location.origin)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('client_id', 'demo-app')
    url.searchParams.set('redirect_uri', `${window.location.origin}/demo/callback`)
    url.searchParams.set('scope', requested.join(' '))
    const state = crypto.randomUUID()
    sessionStorage.setItem('demo_state', state)
    url.searchParams.set('state', state)
    url.searchParams.set('code_challenge', challenge)
    url.searchParams.set('code_challenge_method', 'S256')
    window.location.href = url.toString()
  }

  async function startLogout() {
    const access = String(tokens?.access_token || '')
    const refresh = String(tokens?.refresh_token || '')
    const idToken = String(tokens?.id_token || '')
    const revoke = async (token: string) => {
      if (!token) return
      await fetch('/oauth/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token, client_id: 'demo-app' }),
      }).catch(() => undefined)
    }
    await revoke(access)
    await revoke(refresh)
    sessionStorage.removeItem('demo_verifier')
    const url = new URL('/oauth/logout', window.location.origin)
    url.searchParams.set('client_id', 'demo-app')
    url.searchParams.set('post_logout_redirect_uri', `${window.location.origin}/demo`)
    url.searchParams.set('state', 'logged_out')
    if (idToken) url.searchParams.set('id_token_hint', idToken)
    window.location.href = url.toString()
  }

  async function exchangeCode() {
    if (!code || exchangedCodes.has(code)) return
    exchangedCodes.add(code)
    setError('')
    setExchanging(true)
    try {
      const expectedState = sessionStorage.getItem('demo_state')
      if (!expectedState || params.get('state') !== expectedState) throw new Error('state mismatch')
      const verifier = sessionStorage.getItem('demo_verifier') || ''
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${window.location.origin}/demo/callback`,
        client_id: 'demo-app',
        code_verifier: verifier,
      })
      const tokenRes = await fetch('/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const tokenJson = await tokenRes.json()
      if (!tokenRes.ok) throw new Error(JSON.stringify(tokenJson))
      setTokens(tokenJson)
      const infoRes = await fetch('/oauth/userinfo', {
        headers: { Authorization: `Bearer ${tokenJson.access_token}` },
      })
      const infoJson = await infoRes.json()
      if (!infoRes.ok) throw new Error(JSON.stringify(infoJson))
      setUserinfo(JSON.stringify(infoJson, null, 2))
    } catch (err) {
      setError(err instanceof Error ? err.message : t('demoError'))
    } finally {
      setExchanging(false)
    }
  }

  useEffect(() => {
    if (code && !tokens) void exchangeCode()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [code])

  const decodedIdToken = tokens?.id_token ? decodeJwt(String(tokens.id_token)) : null
  const step = tokens ? 4 : code ? 3 : 1
  const steps = [
    { n: 1, label: t('demoStepApp') },
    { n: 2, label: t('demoStepRedirect') },
    { n: 3, label: t('demoStepCode') },
    { n: 4, label: t('demoStepTokens') },
  ]

  return (
    <div className="demo-app">
      <header className="demo-bar">
        <div className="demo-brand">
          <span className="demo-mark">
            <Icon icon={Building2} size={16} />
          </span>
          <div>
            {t('demoBrand')}
            <small>{t('demoBrandSub')}</small>
          </div>
        </div>
        <div className="demo-bar-actions">
          {tokens ? (
            <button className="demo-idp-link" type="button" onClick={() => void startLogout()}>
              <Icon icon={LogOut} size={14} />
              {t('demoLogout')}
            </button>
          ) : null}
          <Link className="demo-idp-link" to="/">
            {t('demoBackIdp')}
            <Icon icon={ArrowUpRight} size={14} />
          </Link>
        </div>
      </header>
      <main className="demo-main">
        <p className="demo-ribbon">{t('demoSiteHint')}</p>
        {loggedOut && !tokens ? <p className="demo-ribbon is-ok">{t('demoLoggedOut')}</p> : null}
        <section className="demo-card">
          <h1>{t('demoTitle')}</h1>
          <p>{t('demoLead')}</p>
          <fieldset className="demo-scopes">
            <legend>{t('demoScopes')}</legend>
            {DEMO_SCOPES.map((scope) => (
              <label key={scope} className={scope === 'openid' ? 'is-locked' : ''}>
                <input
                  type="checkbox"
                  checked={scopes.includes(scope)}
                  disabled={scope === 'openid'}
                  onChange={() => toggleScope(scope)}
                />
                <span>
                  <strong>
                    {scopeTitle(scope, t)}
                    <code>{scope}</code>
                    {scope === 'openid' ? <em>{t('demoScopeRequired')}</em> : null}
                  </strong>
                  <small>{scopeHint(scope, t)}</small>
                </span>
              </label>
            ))}
          </fieldset>
          <ol className="demo-steps">
            {steps.map((item) => (
              <li key={item.n} className={step === item.n ? 'is-current' : step > item.n ? 'is-done' : ''}>
                <span>{item.n}</span>
                {item.label}
              </li>
            ))}
          </ol>
          <div className="row">
            <button className="demo-btn" type="button" onClick={() => void startLogin()}>
              <Icon icon={LogIn} />
              {t('demoStart')}
            </button>
            {code ? (
              <button className="demo-btn ghost" type="button" disabled={exchanging} onClick={() => void exchangeCode()}>
                <Icon icon={ArrowLeftRight} />
                {t('demoExchange')}
              </button>
            ) : null}
            {tokens ? (
              <button className="demo-btn ghost" type="button" onClick={() => void startLogout()}>
                <Icon icon={LogOut} />
                {t('demoLogout')}
              </button>
            ) : null}
          </div>
        </section>
        {code ? (
          <section className="demo-card">
            <h2>{t('demoStepCode')}</h2>
            <p>{t('demoCodeExplain')}</p>
            <p className="demo-code mono">code = {code}</p>
            <p className="muted">{t('demoExchangeHint')}</p>
          </section>
        ) : null}
        {error ? <p className="error">{error}</p> : null}
        {tokens ? (
          <section className="demo-card">
            <h2>
              <Icon icon={KeyRound} />
              {t('demoTokens')}
            </h2>
            <p>{t('demoTokensLead')}</p>
            <pre className="mono">{JSON.stringify(tokens, null, 2)}</pre>
          </section>
        ) : null}
        {decodedIdToken ? (
          <section className="demo-card">
            <h2>
              <Icon icon={KeyRound} />
              {t('demoIdToken')}
            </h2>
            <p>{t('demoIdTokenLead')}</p>
            <pre className="mono">{JSON.stringify(decodedIdToken.payload, null, 2)}</pre>
            <p className="muted" style={{ marginTop: '0.7rem', marginBottom: '0.35rem' }}>
              header
            </p>
            <pre className="mono">{JSON.stringify(decodedIdToken.header, null, 2)}</pre>
          </section>
        ) : null}
        {userinfo ? (
          <section className="demo-card">
            <h2>
              <Icon icon={IdCard} />
              {t('demoUserinfo')}
            </h2>
            <p>{t('demoUserinfoLead')}</p>
            <pre className="mono">{userinfo}</pre>
          </section>
        ) : null}
      </main>
    </div>
  )
}
