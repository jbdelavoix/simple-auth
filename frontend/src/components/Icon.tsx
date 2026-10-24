import type { LucideIcon } from 'lucide-react'

export function Icon({
  icon: Cmp,
  size = 16,
}: {
  icon: LucideIcon
  size?: number
}) {
  return <Cmp size={size} strokeWidth={1.75} aria-hidden="true" />
}
