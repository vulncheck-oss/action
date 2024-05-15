import type {
  ScanThreshold,
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

  const thresholds: ScanThreshold = {
    base: core.getInput('scan-cvss-base-threshold'),
    temporal: core.getInput('scan-cvss-temporal-threshold'),
    baseMatches: [],
    temporalMatches: [],
  }

  const result: ScanResult = JSON.parse(
    await fs.readFile('output.json', 'utf8'),
  )

  if (thresholds.base !== '') {
    thresholds.baseMatches = result.vulnerabilities.filter(
      vuln => parseFloat(vuln.cvss_base_score) >= parseFloat(thresholds.base),
    )
  }

  if (thresholds.temporal !== '') {
    thresholds.temporalMatches = result.vulnerabilities.filter(
      vuln =>
        parseFloat(vuln.cvss_temporal_score) >= parseFloat(thresholds.temporal),
    )
  }

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
      comment(thresholds, token, result, signature)
    }
    if (lastComment && lastComment.signature !== signature) {
      core.info('Different scan result found, commenting the change')

      comment(
        thresholds,
        token,
        result,
        signature,
        scanDiff(result, lastComment.result),
        lastComment.result,
      )
    }
    if (lastComment && lastComment.signature === signature) {
      core.info('Same scan result signature matches, skipping comment')
    }
  }
  let copy = `VulnCheck has detected ${result.vulnerabilities.length} vulnerabilities`

  if (result.vulnerabilities.length > 0) {
    if (thresholds.baseMatches.length > 0) {
      copy += ` | ${thresholds.baseMatches.length} found above or equal to the CVSS base score threshold of ${thresholds.base}`
    }

    if (thresholds.temporalMatches.length > 0) {
      copy += ` | ${thresholds.temporalMatches.length} found above or equal to the CVSS temporal score threshold of ${thresholds.temporal}`
    }

    // if we have matches, we have thresholds, fail
    if (
      thresholds.baseMatches.length > 0 ||
      thresholds.temporalMatches.length > 0
    ) {
      result.failed = copy
      return result
    }

    // if we have no thresholds, fail for vulns found
    if (thresholds.base === '' && thresholds.temporal === '') {
      result.failed = copy
      return result
    }

    if (thresholds.base !== '' && thresholds.baseMatches.length > 0) {
      result.failed = copy
      return result
    }

    if (thresholds.temporal !== '' && thresholds.temporalMatches.length > 0) {
      result.failed = copy
      return result
    }
  } else {
    result.success = copy
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
  thresholds: ScanThreshold,
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
      rows(
        thresholds,
        [...output.vulnerabilities, ...previous.vulnerabilities],
        diff,
      ),
    )
  else body += table(headers, rows(thresholds, output.vulnerabilities))

  if (thresholds.base !== '')
    body += `\n> CVSS base threshold set to **${thresholds.base}** - matches are underlined`
  if (thresholds.temporal !== '')
    body += `\n> CVSS temporal threshold set to **${thresholds.temporal}** - matches are underlined`

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
  thresholds: ScanThreshold,
  vulns: ScanResultVuln[],
  diff?: ScanResultVulnDiff[],
): TableRow[] {
  const cves: string[] = []
  const output: TableRow[] = []
  for (const vuln of vulns) {
    const difference = diff?.find(d => d.cve === vuln.cve)
    const inThreshold: boolean =
      thresholds.baseMatches.find(v => v.cve === vuln.cve) !== undefined ||
      thresholds.temporalMatches.find(v => v.cve === vuln.cve) !== undefined
    if (!cves.includes(vuln.cve)) {
      output.push({
        underline: inThreshold,
        added: difference?.added,
        removed: difference?.removed,
        cells: [
          { value: vuln.name },
          { value: vuln.version },
          {
            value: vuln.cve,
            link: `https://vulncheck.com/browse/cve/${vuln.cve}`,
          },
          { value: vuln.cvss_base_score },
          { value: vuln.cvss_temporal_score },
          { value: vuln.fixed_versions },
        ],
      })
    }
    cves.push(vuln.cve)
  }
  return output
}

function table(headers: string[], tableRows: TableRow[]): string {
  const added = '[![Found](https://img.shields.io/badge/found-dc2626)](#)'
  const fixed = '[![Fixed](https://img.shields.io/badge/fixed-10b981)](#)'
  let output = `${headers.join(' | ')}  \n ${headers.map(() => '---').join(' | ')} \n`

  // Add rows
  tableRows.map(row => {
    let badge = ''
    let prefix = ''
    let suffix = ''

    if (row.removed) {
      badge = fixed
      prefix = '~~'
      suffix = '~~'
    }

    if (row.added) {
      badge = added
      prefix = '**'
      suffix = '**'
    }

    if (row.underline) {
      prefix = '<ins>'
      suffix = '</ins>'
    }

    output = `${output}${row.cells
      .map((cell, index) => {
        let cellValue = cell.link ? `[${cell.value}](${cell.link})` : cell.value
        // Add badge to the first cell
        if (index === 0) {
          cellValue = `${badge} ${prefix}${cellValue}${suffix}`
        } else {
          cellValue = `${prefix}${cellValue}${suffix}`
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
