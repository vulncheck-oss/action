import { table, rows } from '../src/table'
import type { ScanResultVuln, ScanResultVulnDiff, TableRow } from '../src/types'

const baseVuln: ScanResultVuln = {
  name: 'Test Vuln',
  version: '1.0.0',
  cve: 'CVE-2021-1234',
  in_kev: true,
  cvss_base_score: '5.0',
  cvss_temporal_score: '4.0',
  fixed_versions: '1.0.1',
}

describe('table', () => {
  it('should generate a markdown table with a title', () => {
    const headers = ['Header1', 'Header2'].map(value => ({ value }))
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
    expect(result).toContain(headers.map(header => header.value).join('  |  '))
    expect(result).toContain(
      tableRows[0].cells.map(cell => cell.value).join(' | '),
    )
  })

  it('should generate a table without a title', () => {
    const headers = [{ value: 'Col1' }]
    const tableRows: TableRow[] = [
      { cells: [{ value: 'Val1' }] },
    ]

    const result = table(headers, tableRows)

    expect(result).not.toContain('> ')
    expect(result).toContain('Col1')
  })

  it('should render a removed row with strikethrough', () => {
    const headers = [{ value: 'Name' }, { value: 'CVE' }]
    const tableRows: TableRow[] = [
      {
        removed: true,
        cells: [{ value: 'pkg' }, { value: 'CVE-1' }],
      },
    ]

    const result = table(headers, tableRows)

    expect(result).toContain('fixed')
    expect(result).toContain('~~pkg~~')
    expect(result).toContain('~~CVE-1~~')
  })

  it('should render an added row with bold', () => {
    const headers = [{ value: 'Name' }, { value: 'CVE' }]
    const tableRows: TableRow[] = [
      {
        added: true,
        cells: [{ value: 'pkg' }, { value: 'CVE-1' }],
      },
    ]

    const result = table(headers, tableRows)

    expect(result).toContain('found')
    expect(result).toContain('**pkg**')
    expect(result).toContain('**CVE-1**')
  })

  it('should render an underline row with ins tags', () => {
    const headers = [{ value: 'Name' }, { value: 'CVE' }]
    const tableRows: TableRow[] = [
      {
        underline: true,
        cells: [{ value: 'pkg' }, { value: 'CVE-1' }],
      },
    ]

    const result = table(headers, tableRows)

    expect(result).toContain('<ins>pkg</ins>')
    expect(result).toContain('<ins>CVE-1</ins>')
  })

  it('should render a header with a link', () => {
    const headers = [{ value: 'In KEV', link: 'https://vulncheck.com/kev' }]
    const tableRows: TableRow[] = [{ cells: [{ value: 'yes' }] }]

    const result = table(headers, tableRows)

    expect(result).toContain('[In KEV](https://vulncheck.com/kev)')
  })

  it('should render a cell with a link', () => {
    const headers = [{ value: 'CVE' }]
    const tableRows: TableRow[] = [
      {
        cells: [
          { value: 'CVE-2021-1234', link: 'https://vulncheck.com/browse/cve/CVE-2021-1234' },
        ],
      },
    ]

    const result = table(headers, tableRows)

    expect(result).toContain('[CVE-2021-1234](https://vulncheck.com/browse/cve/CVE-2021-1234)')
  })
})

describe('rows', () => {
  it('should generate table rows from vulns', () => {
    const diff: ScanResultVulnDiff[] = [
      { cve: 'CVE-2021-1234', added: true, removed: false },
    ]

    const result = rows([baseVuln], diff)

    expect(result).toHaveLength(1)
    expect(result[0].added).toBe(true)
    expect(result[0].removed).toBe(false)
    expect(result[0].cells[0].value).toBe(baseVuln.name)
    expect(result[0].cells[2].link).toBe(
      `https://vulncheck.com/browse/cve/${baseVuln.cve}`,
    )
  })

  it('should deduplicate rows with the same CVE', () => {
    const vulns = [baseVuln, { ...baseVuln }]

    const result = rows(vulns)

    expect(result).toHaveLength(1)
  })

  it('should mark in_kev with checkmark emoji', () => {
    const result = rows([{ ...baseVuln, in_kev: true }])

    expect(result[0].cells[3].value).toBe(':white_check_mark:')
  })

  it('should mark not in_kev with multiplication emoji', () => {
    const result = rows([{ ...baseVuln, in_kev: false }])

    expect(result[0].cells[3].value).toBe(':heavy_multiplication_x:')
  })

  it('should handle rows without a diff', () => {
    const result = rows([baseVuln])

    expect(result).toHaveLength(1)
    expect(result[0].added).toBeUndefined()
    expect(result[0].removed).toBeUndefined()
  })
})
