import type { ReactNode, SVGProps } from 'react'

// Small line icons for the app sidebar (no icon library needed). They inherit
// the current text colour and take any SVG props, e.g. className.
export type IconProps = SVGProps<SVGSVGElement>

function Icon({ children, ...props }: IconProps & { children: ReactNode }) {
  return (
    <svg width={18} height={18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden {...props}>
      {children}
    </svg>
  )
}

export const IconDashboard = (p: IconProps) => (
  <Icon {...p}><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></Icon>
)
export const IconConsole = (p: IconProps) => (
  <Icon {...p}><polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" /></Icon>
)
export const IconImport = (p: IconProps) => (
  <Icon {...p}><path d="M12 3v12" /><polyline points="7 10 12 15 17 10" /><path d="M5 21h14" /></Icon>
)
export const IconPipelines = (p: IconProps) => (
  <Icon {...p}><circle cx="6" cy="6" r="2.5" /><circle cx="18" cy="18" r="2.5" /><path d="M8.5 6H14a4 4 0 0 1 4 4v5.5" /></Icon>
)
export const IconPersonalData = (p: IconProps) => (
  <Icon {...p}><circle cx="11" cy="8" r="3.5" /><path d="M4 20a7 7 0 0 1 10.5-6" /><circle cx="17.5" cy="17.5" r="3" /><path d="M19.7 19.7 22 22" /></Icon>
)
export const IconBlackbox = (p: IconProps) => (
  <Icon {...p}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M3 9h18" /><path d="M8 13h8" /><path d="M8 16.5h5" /></Icon>
)
export const IconIntegrity = (p: IconProps) => (
  <Icon {...p}><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" /><polyline points="8.5 12 11 14.5 15.5 10" /></Icon>
)
// Change requests: two branches, and one merging back into the other.
export const IconRequests = (p: IconProps) => (
  <Icon {...p}><circle cx="6.5" cy="5" r="2.5" /><circle cx="6.5" cy="19" r="2.5" /><circle cx="17.5" cy="12" r="2.5" /><path d="M6.5 7.5v9" /><path d="M9 5h3.5a2.5 2.5 0 0 1 2.5 2.5V9.5" /><polyline points="13 12.5 15 10.5 17 12.5" /></Icon>
)
export const IconPolicies = (p: IconProps) => (
  <Icon {...p}><rect x="5" y="4" width="14" height="17" rx="2" /><path d="M9 4V3h6v1" /><polyline points="9 13 11 15 15 11" /></Icon>
)
export const IconKey = (p: IconProps) => (
  <Icon {...p}><circle cx="7.5" cy="15.5" r="3.5" /><path d="M10 13l9-9" /><path d="M16 7l2 2" /><path d="M14 9l2 2" /></Icon>
)
export const IconGuide = (p: IconProps) => (
  <Icon {...p}><path d="M2 5h6a4 4 0 0 1 4 4v11a3 3 0 0 0-3-3H2z" /><path d="M22 5h-6a4 4 0 0 0-4 4v11a3 3 0 0 1 3-3h7z" /></Icon>
)
export const IconDocs = (p: IconProps) => (
  <Icon {...p}><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" /><polyline points="14 3 14 9 20 9" /><line x1="8" y1="13" x2="16" y2="13" /><line x1="8" y1="17" x2="13" y2="17" /></Icon>
)
export const IconExternal = (p: IconProps) => (
  <Icon {...p}><path d="M14 4h6v6" /><path d="M20 4l-9 9" /><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" /></Icon>
)
export const IconLogout = (p: IconProps) => (
  <Icon {...p}><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><polyline points="16 17 21 12 16 7" /><line x1="21" y1="12" x2="9" y2="12" /></Icon>
)
export const IconMenu = (p: IconProps) => (
  <Icon {...p}><line x1="4" y1="6" x2="20" y2="6" /><line x1="4" y1="12" x2="20" y2="12" /><line x1="4" y1="18" x2="20" y2="18" /></Icon>
)
export const IconClose = (p: IconProps) => (
  <Icon {...p}><line x1="6" y1="6" x2="18" y2="18" /><line x1="18" y1="6" x2="6" y2="18" /></Icon>
)
export const IconCollapse = (p: IconProps) => (
  <Icon {...p}><polyline points="11 17 6 12 11 7" /><polyline points="18 17 13 12 18 7" /></Icon>
)
export const IconExpand = (p: IconProps) => (
  <Icon {...p}><polyline points="13 17 18 12 13 7" /><polyline points="6 17 11 12 6 7" /></Icon>
)
export const IconSun = (p: IconProps) => (
  <Icon {...p}><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></Icon>
)
export const IconMoon = (p: IconProps) => (
  <Icon {...p}><path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z" /></Icon>
)
