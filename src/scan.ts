import type {
  ScanThreshold,
  ScanResult,
  Comment,
  ScanResultVulnDiff,
} from './types'

import crypto from 'crypto'
import { exec } from '@actions/exec'
import * as fs from 'fs/promises'
import * as core from '@actions/core'
import * as github from '@actions/github'

import { table, rows } from './table'

export async function scan(): Promise<ScanResult> {
  const command = `vulncheck scan ${core.getInput('scan-path')} -f`
  core.info(`Running CLI command: ${command}`)
  await exec(command)

  const result: ScanResult = JSON.parse(
    await fs.readFile('output.json', 'utf8'),
  )

  const hash = crypto.createHash('sha256')
  hash.update(JSON.stringify(result))
  const signature = hash.digest('hex')

  if (result.vulnerabilities === null) {
    core.setOutput('scan-count', 0)
    core.setOutput('scan-signature', signature)
    core.setOutput('scan-output', JSON.stringify(result))
    result.success = 'No vulnerabilities found'
    result.vulnerabilities = []
  }

  core.setOutput('scan-count', result.vulnerabilities.length.toString())
  core.setOutput('scan-signature', signature)
  core.setOutput('scan-output', JSON.stringify(result))

  const thresholds = processThresholds(result)

  if (github.context.payload.pull_request && result.vulnerabilities.length) {
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

    if (core.getInput('scan-cve-details')) {
      result.vulnerabilities.map(vuln => {
        if (vuln.purl_detail === undefined) return
        core.notice(
          `${vuln.cve} found in ${vuln.purl_detail.type} package ${vuln.name} in ${vuln.purl_detail.locations.join(', ')} using ${vuln.purl_detail.cataloger}`,
        )
      })
    }

    if (core.getInput('scan-cve-npm-rel')) {
      const options = {
        listeners: {
          stdout: (data: Buffer) => {
            core.notice(data.toString())
          },
        },
        ignoreReturnCode: true,
        silent: true,
      }
      result.vulnerabilities.map(
        async vuln =>
          await exec(`npm ls ${vuln.name}@${vuln.version}`, [], options),
      )
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

export function processThresholds(result: ScanResult): ScanThreshold {
  const thresholds: ScanThreshold = {
    base: core.getInput('scan-cvss-base-threshold'),
    temporal: core.getInput('scan-cvss-temporal-threshold'),
    baseMatches: [],
    temporalMatches: [],
    baseMatchesBelow: [],
    temporalMatchesBelow: [],
    total: 0,
    totalBelow: 0,
  }

  if (thresholds.base !== '') {
    thresholds.baseMatches = result.vulnerabilities.filter(
      vuln => parseFloat(vuln.cvss_base_score) >= parseFloat(thresholds.base),
    )
    thresholds.baseMatchesBelow = result.vulnerabilities.filter(
      vuln => parseFloat(vuln.cvss_base_score) < parseFloat(thresholds.base),
    )
  }

  if (thresholds.temporal !== '') {
    thresholds.temporalMatches = result.vulnerabilities.filter(
      vuln =>
        parseFloat(vuln.cvss_temporal_score) >= parseFloat(thresholds.temporal),
    )
    thresholds.temporalMatchesBelow = result.vulnerabilities.filter(
      vuln =>
        parseFloat(vuln.cvss_temporal_score) < parseFloat(thresholds.temporal),
    )
  }

  thresholds.total =
    thresholds.temporalMatches.length + thresholds.baseMatches.length
  thresholds.totalBelow =
    thresholds.temporalMatchesBelow.length + thresholds.baseMatchesBelow.length

  return thresholds
}

export function scanDiff(
  cur: ScanResult,
  prev: ScanResult,
): ScanResultVulnDiff[] {
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
    { value: 'Name' },
    { value: 'Version' },
    { value: 'CVE' },
    { value: 'In KEV', link: 'https://vulncheck.com/kev' },
    { value: 'CVSS Base' },
    { value: 'CVSS Temporal' },
    { value: 'Fixed Versions' },
  ]

  if (thresholds.base !== '')
    body += `\n* CVSS base threshold set to **${thresholds.base}**\n\n`
  if (thresholds.temporal !== '')
    body += `\n* CVSS temporal threshold set to **${thresholds.temporal}**\n\n`

  if (thresholds.total > 0) {
    let allMatches
    let allMatchesBelow

    allMatches = [...thresholds.baseMatches, ...thresholds.temporalMatches]
    allMatchesBelow = [
      ...thresholds.baseMatchesBelow,
      ...thresholds.temporalMatchesBelow,
    ]

    if (diff && previous) {
      const prevThresholds = processThresholds(previous)
      allMatches = [
        ...allMatches,
        ...prevThresholds.baseMatches,
        ...prevThresholds.temporalMatches,
      ]
      allMatchesBelow = [
        ...allMatchesBelow,
        ...prevThresholds.baseMatchesBelow,
        ...prevThresholds.temporalMatchesBelow,
      ]
    }

    body += table(
      headers,
      rows(allMatches, diff),
      'Vulnerabillites found equal to or above the threshold',
    )
    body += table(
      headers,
      rows(allMatchesBelow, diff),
      'Vulnerabillites found below the threshold',
    )
  } else {
    const vulns =
      diff && previous
        ? [...output.vulnerabilities, ...previous.vulnerabilities]
        : output.vulnerabilities
    body += table(headers, rows(vulns, diff))
  }

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
