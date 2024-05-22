import { table, rows } from '../src/table'
import type { ScanResultVuln, ScanResultVulnDiff, TableRow } from '../src/types'

describe('table.ts tests', () => {
  test('table function should generate a markdown table', () => {
    const headers = ['Header1', 'Header2']
    const tableRows: TableRow[] = [
      {
        added: false,
        removed: false,
        cells: [{ value: 'Cell1' }, { value: 'Cell2' }],
      },
    ]
    const title = 'Test Title'

    const result = table(headers, tableRows, title)

    expect(result).toContain(title)
    expect(result).toContain(headers.join(' | '))
    expect(result).toContain(
      tableRows[0].cells.map(cell => cell.value).join(' | '),
    )
  })

  test('rows function should generate table rows', () => {
    const vulns: ScanResultVuln[] = [
      {
        name: 'Test Vuln',
        version: '1.0.0',
        cve: 'CVE-2021-1234',
        in_kev: true,
        cvss_base_score: '5.0',
        cvss_temporal_score: '4.0',
        fixed_versions: '1.0.1',
      },
    ]
    const diff: ScanResultVulnDiff[] = [
      {
        cve: 'CVE-2021-1234',
        added: true,
        removed: false,
      },
    ]

    const result = rows(vulns, diff)

    expect(result).toHaveLength(1)
    expect(result[0].added).toBe(true)
    expect(result[0].removed).toBe(false)
    expect(result[0].cells[0].value).toBe(vulns[0].name)
    expect(result[0].cells[2].link).toBe(
      `https://vulncheck.com/browse/cve/${vulns[0].cve}`,
    )
  })
})
