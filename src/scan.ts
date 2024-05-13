import type { ScanResult, Comment, ScanResultVulnDiff, TableRow } from './types'

import crypto from 'crypto'
import { exec } from '@actions/exec'
import * as fs from 'fs/promises'
import * as core from '@actions/core'
import * as github from '@actions/github'

export async function scan(): Promise<ScanResult> {
  core.info('Running CLI command: scan')
  await exec('vci scan ./repos/npm-one -f')
  const result: ScanResult = JSON.parse(
    await fs.readFile('output.json', 'utf8'),
  )

  const hash = crypto.createHash('sha256')
  hash.update(JSON.stringify(result))
  const signature = hash.digest('hex')

  core.setOutput('scan-count', result.vulnerabilities.length.toString())
  core.setOutput('scan-signature', signature)
  core.setOutput('scan-output', JSON.stringify(result))

  if (
    github.context.payload.pull_request &&
    result.vulnerabilities.length > 0
  ) {
    const token = core.getInput('github-token', { required: true })
    const lastComment = await getLastComment(token)

    if (!lastComment) {
      core.info('No scan result found yet, commenting')
      comment(token, result, signature)
    }
    if (lastComment && lastComment.signature !== signature) {
      core.info('Different scan result found, commenting the change')
      // console.log('scanDiff', scanDiff(result, lastComment.result))
      comment(token, result, signature, scanDiff(result, lastComment.result))
    }
    if (lastComment && lastComment.signature === signature) {
      core.info('Same scan result found, skipping comment')
    }
  }

  if (result.vulnerabilities.length > 0) {
    result.failed = `VulnCheck has detected ${result.vulnerabilities.length} vulnerabilities`
  }

  return result
}

function scanDiff(cur: ScanResult, prev: ScanResult): ScanResultVulnDiff[] {
  const diff: ScanResultVulnDiff[] = []
  cur.vulnerabilities.map(vuln => {
    if (!prev.vulnerabilities.find(pv => pv.cve === vuln.cve))
      diff.push({ cve: vuln.cve, added: true })
  })
  prev.vulnerabilities.map(vuln => {
    if (!cur.vulnerabilities.find(cv => cv.cve === vuln.cve))
      diff.push({ cve: vuln.cve, removed: true })
  })

  return diff
}

async function getLastComment(token: string): Promise<Comment | undefined> {
  if (!github.context.payload.pull_request) {
    return undefined
  }

  const octokit = github.getOctokit(token)
  const { data: comments } = await octokit.rest.issues.listComments({
    owner: github.context.repo.owner,
    repo: github.context.repo.repo,
    issue_number: github.context.payload.pull_request.number,
  })

  const regex =
    /<!-- vulncheck-scan-signature: ([a-f0-9]{64}) -->([\s\S]*?)<!-- vulncheck-scan-report: ({.*?}) -->/

  for (const cmt of comments) {
    const match = regex.exec(cmt.body ?? '')
    if (match) {
      return {
        signature: match[1],
        result: JSON.parse(match[3]),
      }
    }
  }
  return undefined
}

async function comment(
  token: string,
  output: ScanResult,
  signature: string,
  diff?: ScanResultVulnDiff[],
): Promise<void> {
  const added = 'https://img.shields.io/badge/new-FF0000'
  const removed = 'https://img.shields.io/badge/removed-6ee7b7'
  const octokit = github.getOctokit(token)

  let body
  const headers = []

  if (diff) {
    body = `<img src="https://vulncheck.com/logo.png" alt="logo" height="15px" /> VulnCheck has detected **${diff.length} ${diff.length === 1 ? 'change' : 'changes'}**\n\n`
    headers.push('Diff')
  } else {
    body = `<img src="https://vulncheck.com/logo.png" alt="logo" height="15px" /> VulnCheck has detected **${output.vulnerabilities.length}** ${output.vulnerabilities.length === 1 ? 'vulnerability' : 'vulnerabilities'}\n\n`
  }

  headers.push(
    'Name',
    'Version',
    'CVE',
    'CVSS Base Score',
    'CVSS Temporal Score',
    'Fixed Versions',
  )
  const rows: TableRow[] = output.vulnerabilities.map(vuln => {
    const cells = []

    const difference = diff?.find(d => d.cve === vuln.cve)
    if (difference)
      cells.push({
        value: `<img src="${difference.added ? added : removed}" alt="${difference.added ? 'added' : 'removed'}" />`,
      })
    cells.push(
      { value: vuln.name },
      { value: vuln.version },
      { value: vuln.cve, link: `https://vulncheck.com/browse/cve/${vuln.cve}` },
      { value: vuln.cvss_base_score },
      { value: vuln.cvss_temporal_score },
      { value: vuln.fixed_versions },
    )
    return { cells }
  })
  body += table(headers, rows)

  body += `\n\n
<br />
<sup>Report generated by <a href="https://github.com/vulncheck-oss/action">The VulnCheck Action</a></sup>
<!-- vulncheck-scan-signature: ${signature} -->
<!-- vulncheck-scan-report: ${JSON.stringify(output)} -->
`

  if (github.context.payload.pull_request) {
    await octokit.rest.issues.createComment({
      owner: github.context.repo.owner,
      repo: github.context.repo.repo,
      issue_number: github.context.payload.pull_request.number,
      body,
      event: 'COMMENT',
    })
  }
}

function table(headers: string[], rows: TableRow[]): string {
  let output = '<table>\n'
  output += '<tr>\n'
  headers.map(header => {
    output += `<th>${header}</th>\n`
  })
  output += '</tr>\n'

  rows.map(row => {
    output += '<tr>\n'
    row.cells.map(
      cell =>
        (output += cell.link
          ? `<td><a href="${cell.link}">${cell.value}</a></td>`
          : `<td>${cell.value}</td>\n`),
    )
    output += '</tr>\n'
  })

  return output
}
