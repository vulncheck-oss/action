export interface ScanResult {
  vulnerabilities: ScanResultVuln[]
  failed?: string
  success?: string
}

export interface ScanResultVuln {
  name: string
  version: string
  cve: string
  cvss_base_score: string
  cvss_temporal_score: string
  fixed_versions: string
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
