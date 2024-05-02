import { getExecOutput } from '@actions/exec'
import * as core from '@actions/core'

interface ScanResult {
  vulnerabilities: ScanResultVulnerability[]
}

interface ScanResultVulnerability {
  name: string
  version: string
  cve: string
  cvss_base_score: string
  cvss_temporal_score: string
  fixed_versions: string
}

export async function scan(): Promise<void> {
  core.info('Running CLI command: scan')
  const { stdout } = await getExecOutput('vc scan . --json')
  const result: ScanResult = JSON.parse(stdout)
  console.log(result)
}
