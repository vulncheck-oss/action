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

  if (
    github.context.payload.pull_request &&
    output.vulnerabilities.length > 0
  ) {
    console.log('token', process.env.GITHUB_TOKEN)
    const octokit = github.getOctokit(process.env.GITHUB_TOKEN as string)

    let commentBody =
      '| Name | Version | CVE | CVSS Base Score | CVSS Temporal Score | Fixed Versions |\n| ---- | ------- | --- | --------------- | ------------------ | -------------- |\n'

    output.vulnerabilities.map(
      vuln =>
        (commentBody += `| ${vuln.name} | ${vuln.version} | ${vuln.cve} | ${vuln.cvss_base_score} | ${vuln.cvss_temporal_score} | ${vuln.fixed_versions} |\n`),
    )

    await octokit.rest.pulls.createReview({
      owner: github.context.repo.owner,
      repo: github.context.repo.repo,
      pull_number: github.context.payload.pull_request.number,
      body: commentBody,
      event: 'COMMENT',
    })
  }

  core.setOutput('scan-count', output.vulnerabilities.length.toString())
  core.setOutput('scan-output', JSON.stringify(output))
}
