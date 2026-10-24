import {
  BookOpen,
  CircleHelp,
  FolderOpen,
  Globe,
  IdCard,
  KeyRound,
  LayoutDashboard,
  Network,
  Play,
  Route,
  Shield,
  Tags,
  User,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useAppearance } from '../appearance'
import type { SessionUser } from '../api'
import { CodeBlock } from '../components/CodeBlock'
import { Icon } from '../components/Icon'
import { PublicHeader } from '../components/PublicHeader'
import { useI18n } from '../i18n'
import {
  CADDY_FORWARD,
  CADDY_OIDC,
  FORWARD_HEADERS,
  NGINX_FORWARD,
  NGINX_OIDC,
  OIDC_APP_CONFIG,
  SERVER_ENV,
} from './helpSnippets'

function termParts(text: string) {
  const [title, ...rest] = text.split('—')
  return { title: title.trim(), body: rest.join('—').trim() }
}

function Steps({ items }: { items: string[] }) {
  return (
    <ol className="steps">
      {items.map((text, i) => (
        <li key={text}>
          <span className="step-n">{i + 1}</span>
          <span>{text}</span>
        </li>
      ))}
    </ol>
  )
}

export function HelpPage({
  user,
  onLogout,
}: {
  user?: SessionUser | null
  onLogout?: () => Promise<void>
}) {
  const { t } = useI18n()
  const { enable_demo } = useAppearance()
  const terms: { title: string; body: string; icon: LucideIcon }[] = [
    { ...termParts(t('helpTermUser')), icon: User },
    { ...termParts(t('helpTermGroup')), icon: Tags },
    { ...termParts(t('helpTermClient')), icon: IdCard },
    { ...termParts(t('helpTermIssuer')), icon: Globe },
    { ...termParts(t('helpTermScope')), icon: KeyRound },
  ]
  const modes = [
    {
      id: 'oidc',
      title: 'OIDC',
      icon: IdCard,
      body: t('helpModeOidcBody'),
      checks: t('helpModeOidcChecks'),
      receives: t('helpModeOidcReceives'),
      console: t('helpModeOidcConsole'),
    },
    {
      id: 'forward',
      title: 'Forward',
      icon: Shield,
      body: t('helpModeForwardBody'),
      checks: t('helpModeForwardChecks'),
      receives: t('helpModeForwardReceives'),
      console: t('helpModeForwardConsole'),
    },
  ]

  return (
    <div className="app-shell">
      <PublicHeader user={user} onLogout={onLogout} />
      <section className="hero">
        <div className="kicker">{t('navHelp')}</div>
        <h1 className="panel-heading">
          <Icon icon={CircleHelp} size={28} />
          {t('helpTitle')}
        </h1>
        <p>{t('helpLead')}</p>
      </section>

      <div className="help-flow">
        <article className="panel">
          <h2 className="panel-heading">
            <Icon icon={BookOpen} />
            {t('helpWhatTitle')}
          </h2>
          <p>{t('helpWhatBody')}</p>
        </article>

        <article className="panel stack">
          <h2 className="panel-heading">
            <Icon icon={Route} />
            {t('helpModesTitle')}
          </h2>
          <div className="mode-grid">
            {modes.map((mode) => (
              <a className="mode-card" href={`#${mode.id}`} key={mode.id}>
                <strong className="with-icon">
                  <Icon icon={mode.icon} size={16} />
                  {mode.title}
                </strong>
                <span>{mode.body}</span>
                <dl className="kv">
                  <dt>{t('helpModeChecks')}</dt>
                  <dd>{mode.checks}</dd>
                  <dt>{t('helpModeReceives')}</dt>
                  <dd>{mode.receives}</dd>
                  <dt>{t('helpModeConsole')}</dt>
                  <dd>{mode.console}</dd>
                </dl>
              </a>
            ))}
          </div>
        </article>

        <article className="panel stack" id="oidc">
          <h2 className="panel-heading">
            <Icon icon={IdCard} />
            {t('helpOidcTitle')}
          </h2>
          <Steps items={[t('helpOidc1'), t('helpOidc2'), t('helpOidc3'), t('helpOidc4'), t('helpOidc5')]} />
          <h3 className="help-sub">{t('helpOidcAuthTitle')}</h3>
          <div className="dl">
            {[termParts(t('helpOidcSecret')), termParts(t('helpOidcPkce'))].map((term) => (
              <div key={term.title}>
                <strong>{term.title}</strong>
                <span>{term.body}</span>
              </div>
            ))}
          </div>
          <h3 className="help-sub">{t('helpOidcConfig')}</h3>
          <CodeBlock tabs={[{ label: 'OIDC', code: OIDC_APP_CONFIG }]} />
        </article>

        <article className="panel stack" id="forward">
          <h2 className="panel-heading">
            <Icon icon={Shield} />
            {t('helpForwardTitle')}
          </h2>
          <Steps
            items={[t('helpForward1'), t('helpForward2'), t('helpForward3'), t('helpForward4'), t('helpForward5')]}
          />
          <h3 className="help-sub">{t('helpForwardHeaders')}</h3>
          <CodeBlock tabs={[{ label: 'HTTP', code: FORWARD_HEADERS }]} />
          <p className="error">{t('helpForwardWarn')}</p>
        </article>

        <article className="panel stack" id="proxy">
          <div>
            <h2 className="panel-heading">
              <Icon icon={Network} />
              {t('helpProxyTitle')}
            </h2>
            <p>{t('helpProxyLead')}</p>
          </div>
          <h3 className="help-sub">{t('helpProxyAuth')}</h3>
          <CodeBlock
            tabs={[
              { label: 'Caddy', code: CADDY_OIDC },
              { label: 'nginx', code: NGINX_OIDC },
            ]}
          />
          <h3 className="help-sub">{t('helpProxyApp')}</h3>
          <CodeBlock
            tabs={[
              { label: 'Caddy', code: CADDY_FORWARD },
              { label: 'nginx', code: NGINX_FORWARD },
            ]}
          />
          <p className="hint" style={{ margin: 0 }}>
            {t('helpProxySession')}
          </p>
          <h3 className="help-sub">{t('helpProxyEnv')}</h3>
          <CodeBlock tabs={[{ label: '.env', code: SERVER_ENV }]} />
          <p className="hint" style={{ margin: 0 }}>
            {t('helpProxyNote')}
          </p>
        </article>
      </div>

      <article className="panel stack" style={{ marginTop: '0.85rem' }}>
        <div>
          <h2 className="panel-heading">
            <Icon icon={FolderOpen} />
            {t('helpInitTitle')}
          </h2>
          <p>{t('helpInitLead')}</p>
        </div>
        <ol className="steps">
          {[t('helpInit1'), t('helpInit2'), t('helpInit3'), t('helpInit4'), t('helpInit5')].map(
            (text, i) => (
              <li key={text}>
                <span className="step-n">{i + 1}</span>
                <span>{text}</span>
              </li>
            ),
          )}
        </ol>
      </article>

      <article className="panel" style={{ marginTop: '0.85rem' }}>
        <h2 className="panel-heading">
          <Icon icon={BookOpen} />
          {t('helpTermsTitle')}
        </h2>
        <div className="dl">
          {terms.map((term) => (
            <div key={term.title}>
              <strong className="with-icon">
                <Icon icon={term.icon} size={14} />
                {term.title}
              </strong>
              <span>{term.body}</span>
            </div>
          ))}
        </div>
      </article>

      <div className="help-grid" style={{ marginTop: '0.85rem' }}>
        {enable_demo ? (
          <article className="panel stack">
            <div>
              <h2 className="panel-heading">
                <Icon icon={Play} />
                {t('helpDemoTitle')}
              </h2>
              <p>{t('helpDemoBody')}</p>
            </div>
            <div>
              <Link className="btn secondary with-icon" to="/demo">
                <Icon icon={Play} />
                {t('navDemo')}
              </Link>
            </div>
          </article>
        ) : null}
        <article className="panel stack">
          <div>
            <h2 className="panel-heading">
              <Icon icon={LayoutDashboard} />
              {t('helpAdminTitle')}
            </h2>
            <p>{t('helpAdminBody')}</p>
          </div>
          <div>
            <Link className="btn secondary with-icon" to="/admin">
              <Icon icon={LayoutDashboard} />
              {t('navAdmin')}
            </Link>
          </div>
        </article>
      </div>
    </div>
  )
}
