export interface ScanThreshold {
  base: string
  temporal: string
  baseMatches: ScanResultVuln[]
  temporalMatches: ScanResultVuln[]
  baseMatchesBelow: ScanResultVuln[]
  temporalMatchesBelow: ScanResultVuln[]
  total: number
  totalBelow: number
}

export interface ScanResultVuln {
  name: string
  version: string
  cve: string
  in_kev: boolean
  cvss_base_score: string
  cvss_temporal_score: string
  fixed_versions: string
  purl_detail?: PurlDetail
}

export interface PurlDetail {
  purl: string
  type: string
  cataloger: string
  locations: string[]
}

// Reason is passed through from the API; treat it as an open set.
export interface UnprocessedPurl {
  purl: string
  reason: string
}

export interface ScanResult {
  vulnerabilities: ScanResultVuln[]
  failed?: string
  success?: string
  // Omitted when empty: this field alone must not change the hashed document.
  unprocessed?: UnprocessedPurl[]
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

export interface TableHeader {
  value: string
  link?: string
}

export interface TableRow {
  cells: TableCell[]
  bold?: boolean
  underline?: boolean
  added?: boolean
  removed?: boolean
}
