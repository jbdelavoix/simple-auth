import { X } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useEffect, useId, useRef, type ReactNode } from 'react'
import { useI18n } from '../i18n'
import { Icon } from './Icon'

/** Modal editor: a centered dialog on desktop, a bottom sheet on phones. */
export function Sheet({
  open,
  title,
  icon,
  onClose,
  children,
}: {
  open: boolean
  title: string
  icon?: LucideIcon
  onClose: () => void
  children: ReactNode
}) {
  const { t } = useI18n()
  const ref = useRef<HTMLDialogElement>(null)
  const titleId = useId()

  useEffect(() => {
    const dialog = ref.current
    if (!dialog) return
    if (open && !dialog.open) {
      dialog.showModal()
      dialog.focus()
    }
    if (!open && dialog.open) dialog.close()
  }, [open])

  return (
    <dialog
      ref={ref}
      className="sheet"
      tabIndex={-1}
      aria-labelledby={titleId}
      onClose={onClose}
      onClick={(event) => {
        if (event.target === ref.current) onClose()
      }}
    >
      <header className="sheet-header">
        <h2 className="panel-heading" id={titleId}>
          {icon ? <Icon icon={icon} /> : null}
          {title}
        </h2>
        <button className="btn ghost icon-btn" type="button" aria-label={t('close')} onClick={onClose}>
          <Icon icon={X} size={18} />
        </button>
      </header>
      <div className="sheet-content">{open ? children : null}</div>
    </dialog>
  )
}
