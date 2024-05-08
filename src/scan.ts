import { exec } from '@actions/exec'
import * as fs from 'fs/promises'
import * as core from '@actions/core'
import { context } from '@actions/github'

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
  await exec('vc scan ./repos/npm-two -f')
  const output: ScanResult = JSON.parse(
    await fs.readFile('output.json', 'utf8'),
  )

  if (context.payload.pull_request) {
    core.info('This is a pull request')
  } else {
    core.info('This is not a pull request')
  }

  core.setOutput('scan-count', output.vulnerabilities.length.toString())
  core.setOutput('scan-output', JSON.stringify(output))
}
