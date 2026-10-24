export const LOGIN_THEMES = ['classic', 'slate', 'light', 'contrast'] as const
export type LoginTheme = (typeof LOGIN_THEMES)[number]

export type LoginBranding = {
  background: string
  panel: string
  ink: string
  accent: string
  logo: string
  title: string
  subtitle: string
}

export const EMPTY_BRANDING: LoginBranding = {
  background: '',
  panel: '',
  ink: '',
  accent: '',
  logo: '',
  title: '',
  subtitle: '',
}

export const THEME_COLORS: Record<LoginTheme, Pick<LoginBranding, 'background' | 'panel' | 'ink' | 'accent'>> = {
  classic: { background: '#0c0e13', panel: '#161a22', ink: '#eceef3', accent: '#6e7cf6' },
  slate: { background: '#101214', panel: '#1b1f24', ink: '#e8eaed', accent: '#4f8cff' },
  light: { background: '#dfe5ee', panel: '#ffffff', ink: '#1b2128', accent: '#1e4d8c' },
  contrast: { background: '#000000', panel: '#111111', ink: '#ffffff', accent: '#ffe500' },
}

export function resolvedBranding(theme: string, branding: LoginBranding): LoginBranding {
  const preset = THEME_COLORS[(theme as LoginTheme) in THEME_COLORS ? (theme as LoginTheme) : 'classic']
  return {
    background: branding.background || preset.background,
    panel: branding.panel || preset.panel,
    ink: branding.ink || preset.ink,
    accent: branding.accent || preset.accent,
    logo: branding.logo || '',
    title: branding.title || '',
    subtitle: branding.subtitle || '',
  }
}

export function portalName(branding: Pick<LoginBranding, 'title'>, issuer: string): string {
  const custom = branding.title.trim()
  if (custom) return custom
  try {
    const host = new URL(issuer).host
    if (host) return host
  } catch {
    /* issuer is not a URL yet */
  }
  if (typeof window !== 'undefined' && window.location.host) return window.location.host
  return ''
}

export function isLightColor(hex: string): boolean {
  const raw = hex.replace('#', '')
  const full = raw.length === 3 ? raw.split('').map((ch) => ch + ch).join('') : raw
  if (full.length !== 6) return false
  const value = Number.parseInt(full, 16)
  if (Number.isNaN(value)) return false
  const r = (value >> 16) & 255
  const g = (value >> 8) & 255
  const b = value & 255
  return (0.299 * r + 0.587 * g + 0.114 * b) / 255 > 0.62
}

export function brandingStyle(branding: LoginBranding): Record<string, string> {
  const style: Record<string, string> = {}
  if (branding.background) {
    style['--bg'] = branding.background
    style['--bg-2'] = branding.background
  }
  if (branding.panel) style['--panel'] = branding.panel
  if (branding.ink) style['--ink'] = branding.ink
  if (branding.accent) {
    style['--accent'] = branding.accent
    style['--accent-2'] = branding.accent
    style['--btn-hover'] = branding.accent
    style['--btn-ink'] = isLightColor(branding.accent) ? '#111111' : '#ffffff'
  }
  return style
}
