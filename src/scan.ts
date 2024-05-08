import { exec } from '@actions/exec'
import * as fs from 'fs/promises'
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
  await exec('vc scan . -f')
  const output:ScanResult = JSON.parse(await fs.readFile("output.json", "utf8"))
  console.log(output)
}
