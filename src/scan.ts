import crypto from 'crypto'
import { exec } from '@actions/exec'
import * as fs from 'fs/promises'
import * as core from '@actions/core'
import * as github from '@actions/github'

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

  const hash = crypto.createHash('sha256')
  hash.update(JSON.stringify(output))

  core.setOutput('scan-count', output.vulnerabilities.length.toString())
  core.setOutput('scan-signature', hash.digest('hex'))
  core.setOutput('scan-output', JSON.stringify(output))

  if (
    github.context.payload.pull_request &&
    output.vulnerabilities.length > 0
  ) {
    const token = core.getInput('github-token', { required: true })
    comment(output, token)
  }
}

async function comment(output: ScanResult, token: string): Promise<void> {
  const octokit = github.getOctokit(token)

  let commentBody = `<img src="https://vulncheck.com/logo.png" alt="logo" height="15px" /> VulnCheck has detected **${output.vulnerabilities.length}** vulnerabilities\n\n`

  commentBody +=
    '| Name | Version | CVE | CVSS Base Score | CVSS Temporal Score | Fixed Versions |\n| ---- | ------- | --- | --------------- | ------------------ | -------------- |\n'

  output.vulnerabilities.map(
    vuln =>
      (commentBody += `| ${vuln.name} | ${vuln.version} | [${vuln.cve}](https://vulncheck.com/browse/cve/${vuln.cve}) | ${vuln.cvss_base_score} | ${vuln.cvss_temporal_score} | ${vuln.fixed_versions} |\n`),
  )

  commentBody += `\n\n
<br />
<sup>Report generated by <a href="https://github.com/vulncheck-oss/action">The VulnCheck Action</a></sup>`

  if (github.context.payload.pull_request) {
    await octokit.rest.pulls.createReview({
      owner: github.context.repo.owner,
      repo: github.context.repo.repo,
      pull_number: github.context.payload.pull_request.number,
      body: commentBody,
      event: 'COMMENT',
    })
  }
}
