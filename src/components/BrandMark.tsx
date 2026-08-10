interface BrandMarkProps {
  size?: number
}

export function BrandMark({ size = 30 }: BrandMarkProps) {
  return (
    <svg
      aria-hidden="true"
      className="brand-mark"
      height={size}
      viewBox="0 0 32 32"
      width={size}
    >
      <path d="M7.5 5.5h14a3 3 0 0 1 3 3v14a3 3 0 0 1-3 3h-14a3 3 0 0 1-3-3v-14a3 3 0 0 1 3-3Z" />
      <path d="m8.5 20 4.1-4.2 3.2 3.1 2.2-2.2 3.5 3.3" />
      <circle cx="19.8" cy="10.7" r="1.8" />
      <path className="brand-mark__proof" d="m21.7 24.5 2.1 2 4.2-4.6" />
    </svg>
  )
}
