export function BrandMark({ size = 22 }: { size?: number }) {
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} aria-hidden="true">
      <path
        fill="currentColor"
        d="M12 2 3 7v5c0 5.25 3.75 10.13 9 11.25C17.25 22.13 21 17.25 21 12V7l-9-5Zm0 3.15L18.2 8.4v3.55c0 3.9-2.55 7.5-6.2 8.55-3.65-1.05-6.2-4.65-6.2-8.55V8.4L12 5.15Zm-1.1 3.1v4.2l3.55 2.1.9-1.5-2.55-1.5V8.25h-1.9Z"
      />
    </svg>
  )
}
