import { useMemo, useState } from 'react'
import { useI18n } from '../i18n'

export type CheckListItem = {
  value: string
  label: string
}

export function CheckList({
  items,
  value,
  onChange,
  disabled = false,
  placeholder,
}: {
  items: CheckListItem[]
  value: string[]
  onChange: (next: string[]) => void
  disabled?: boolean
  placeholder?: string
}) {
  const { t } = useI18n()
  const [query, setQuery] = useState('')
  const selected = useMemo(() => new Set(value), [value])
  const needle = query.trim().toLowerCase()

  const ordered = useMemo(() => {
    const visible = items.filter(
      (item) =>
        !needle ||
        item.label.toLowerCase().includes(needle) ||
        item.value.toLowerCase().includes(needle),
    )
    return [
      ...visible.filter((item) => selected.has(item.value)),
      ...visible.filter((item) => !selected.has(item.value)),
    ]
  }, [items, needle, selected])

  function toggle(itemValue: string) {
    if (disabled) return
    onChange(selected.has(itemValue) ? value.filter((entry) => entry !== itemValue) : [...value, itemValue])
  }

  return (
    <div className={`check-list${disabled ? ' is-disabled' : ''}`}>
      <input
        className="check-list-search"
        type="search"
        value={query}
        placeholder={placeholder || t('listSearch')}
        disabled={disabled}
        onChange={(e) => setQuery(e.target.value)}
      />
      <div className="check-list-items" role="group">
        {ordered.length === 0 ? (
          <div className="check-list-empty">{t('emptyList')}</div>
        ) : (
          ordered.map((item) => (
            <label
              key={item.value}
              className={`check-list-item${selected.has(item.value) ? ' is-selected' : ''}`}
            >
              <input
                type="checkbox"
                checked={selected.has(item.value)}
                disabled={disabled}
                onChange={() => toggle(item.value)}
              />
              <span>{item.label}</span>
            </label>
          ))
        )}
      </div>
    </div>
  )
}
