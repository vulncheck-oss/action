import { ScanResultVuln, ScanResultVulnDiff, TableRow } from "./types"

export function table(
  headers: string[],
  tableRows: TableRow[],
  title?: string,
): string {
  const added = '[![Found](https://img.shields.io/badge/found-dc2626)](#)'
  const fixed = '[![Fixed](https://img.shields.io/badge/fixed-10b981)](#)'
  let output = title ? `> ${title} \n\n` : ''
  output += `${headers.join(' | ')}  \n ${headers.map(() => '---').join(' | ')} \n`

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

export function rows(
  vulns: ScanResultVuln[],
  diff?: ScanResultVulnDiff[],
): TableRow[] {
  const cves: string[] = []
  const output: TableRow[] = []
  for (const vuln of vulns) {
    const difference = diff?.find(d => d.cve === vuln.cve)
    if (!cves.includes(vuln.cve)) {
      output.push({
        added: difference?.added,
        removed: difference?.removed,
        cells: [
          { value: vuln.name },
          { value: vuln.version },
          {
            value: vuln.cve,
            link: `https://vulncheck.com/browse/cve/${vuln.cve}`,
          },
          {
            value: vuln.in_kev
              ? ':white_check_mark:'
              : ':heavy_multiplication_x:',
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
