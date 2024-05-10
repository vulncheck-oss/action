export interface ScanResult {
  vulnerabilities: ScanResultVulnerability[]
  failed?: string
  success?: string
}

export interface ScanResultVulnerability {
  name: string
  version: string
  cve: string
  cvss_base_score: string
  cvss_temporal_score: string
  fixed_versions: string
}

export interface Comment {
  signature: string
  result: ScanResult
}
