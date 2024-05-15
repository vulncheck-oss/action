export interface ScanThreshold {
  base: string
  temporal: string
  baseMatches: ScanResultVuln[]
  temporalMatches: ScanResultVuln[]
}

export interface ScanResultVuln {
  name: string
  version: string
  cve: string
  cvss_base_score: string
  cvss_temporal_score: string
  fixed_versions: string
}

export interface ScanResult {
  vulnerabilities: ScanResultVuln[]
  failed?: string
  success?: string
}

export interface ScanResultVulnDiff {
  cve: string
  added?: boolean
  removed?: boolean
}

export interface Comment {
  signature: string
  result: ScanResult
}

export interface TableCell {
  value: string
  link?: string
}

export interface TableRow {
  cells: TableCell[]
  added?: boolean
  removed?: boolean
}
