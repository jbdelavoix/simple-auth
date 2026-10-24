import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'

/** Mobile menu state. It closes on navigation because it is tied to the path it was opened on. */
export function useMenu() {
  const { pathname } = useLocation()
  const [openOn, setOpenOn] = useState<string | null>(null)
  const open = openOn === pathname

  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpenOn(null)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open])

  return { open, toggle: () => setOpenOn(open ? null : pathname), close: () => setOpenOn(null) }
}
