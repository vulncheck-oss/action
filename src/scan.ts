import type {
  ScanResult,
  Comment,
  ScanResultVulnDiff,
  TableRow,
  ScanResultVuln,
} from './types'

import crypto from 'crypto'
import { exec } from '@actions/exec'
import * as fs from 'fs/promises'
import * as core from '@actions/core'
import * as github from '@actions/github'

export async function scan(): Promise<ScanResult> {
  core.info('Running CLI command: scan')
  await exec('vci scan ./repos/npm-seven -f')
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

      comment(
        token,
        result,
        signature,
        scanDiff(result, lastComment.result),
        lastComment.result,
      )
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

  comments.reverse()

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
  previous?: ScanResult,
): Promise<void> {
  const octokit = github.getOctokit(token)

  let body = ''

  const copyTotal = `**${output.vulnerabilities.length}** ${output.vulnerabilities.length === 1 ? 'vulnerability' : 'vulnerabilities'}`
  const logo = `<img src="https://vulncheck.com/logo.png" alt="logo" height="15px" />`

  if (diff) {
    const added = diff.filter(d => d.added).length
    const fixed = diff.filter(d => d.removed).length
    if (added > 0 && fixed > 0)
      body = `${logo} VulnCheck has detected a total of ${copyTotal} with **${added}** added and **${fixed}** fixed\n\n`
    else if (added > 0 && fixed === 0)
      body = `${logo} VulnCheck has detected a total of ${copyTotal} with **${added}** added\n\n`
    else if (added === 0 && fixed > 0)
      body = `${logo} VulnCheck has detected a total of ${copyTotal} with  **${fixed}** fixed\n\n`
  } else {
    body = `${logo} VulnCheck has detected a total of ${copyTotal}\n\n`
  }

  const headers = [
    'Name',
    'Version',
    'CVE',
    'CVSS Base',
    'CVSS Temporal',
    'Fixed Versions',
  ]

  if (diff && previous)
    body += table(
      headers,
      rows([...output.vulnerabilities, ...previous.vulnerabilities], diff),
    )
  else body += table(headers, rows(output.vulnerabilities))

  body += `\n\n
<br />
<sup>Report generated by <a href="https://github.com/vulncheck-oss/action">VulnCheck</a></sup>
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

function rows(
  vulns: ScanResultVuln[],
  diff?: ScanResultVulnDiff[],
): TableRow[] {
  const added = '<img src="https://img.shields.io/badge/found-dc2626" />'
  const fixed = '<img src="https://img.shields.io/badge/fixed-10b981" />'
  const cves: string[] = []
  const output: TableRow[] = []
  for (const vuln of vulns) {
    const difference = diff?.find(d => d.cve === vuln.cve)
    if (!cves.includes(vuln.cve)) {
      output.push({
        cells: [
          {
            value: difference
              ? `${difference.added ? added : fixed} ${vuln.name}`
              : vuln.name,
          },
          {
            value: vuln.version,
            bold: difference?.added,
            strike: difference?.removed,
          },
          {
            value: vuln.cve,
            link: `https://vulncheck.com/browse/cve/${vuln.cve}`,
            bold: difference?.added,
            strike: difference?.removed,
          },
          {
            value: vuln.cvss_base_score,
            bold: difference?.added,
            strike: difference?.removed,
          },
          {
            value: vuln.cvss_temporal_score,
            bold: difference?.added,
            strike: difference?.removed,
          },
          {
            value: vuln.fixed_versions,
            bold: difference?.added,
            strike: difference?.removed,
          },
        ],
      })
    }
    cves.push(vuln.cve)
  }
  return output
}

function table(headers: string[], tableRows: TableRow[]): string {
  let output = `$[headers.join(' | ')}  \n ${headers.map(() => '---').join(' | ')} \n`

  // Add rows
  tableRows.map(row => {
    output = `${output}${row.cells
      .map(cell => {
        let cellValue = cell.link ? `[${cell.value}](${cell.link})` : cell.value

        switch (true) {
          case cell.strike:
            cellValue = `~~${cellValue}~~`
            break
          case cell.bold:
            cellValue = `**${cellValue}**`
            break
          // Add more cases here as needed
        }

        return cellValue
      })
      .join(' | ')} \n`
  })

  return output
}

/*
function table(headers: string[], tableRows: TableRow[]): string {
  let output = '<table>\n'
  output += '<tr>\n'
  headers.map(header => {
    output += `<th>${header}</th>\n`
  })
  output += '</tr>\n'

  tableRows.map(row => {
    output += '<tr>\n'
    row.cells.map(
      cell =>
        (output += cell.link
          ? `<td><a href="${cell.link}">${cell.value}</a></</td>`
          : `<td>${cell.value}</td>\n`),
    )
    output += '</tr>\n'
  })

  output += '</table>\n'

  return output
}
*/
