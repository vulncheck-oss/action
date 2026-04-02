import type { ScanThreshold, ScanResult, ScanResultVuln } from '../src/types'
import { scan, processThresholds, scanDiff } from '../src/scan'
import * as core from '@actions/core'
import * as github from '@actions/github'
import * as fsPromises from 'fs/promises'
import { exec } from '@actions/exec'

jest.mock('@actions/core')
jest.mock('@actions/exec', () => ({ exec: jest.fn().mockResolvedValue(0) }))
jest.mock('fs/promises')
jest.mock('@actions/github', () => ({
  context: {
    payload: {},
    repo: { owner: 'test-owner', repo: 'test-repo' },
  },
  getOctokit: jest.fn(),
}))

const makeVuln = (overrides: Partial<ScanResultVuln> = {}): ScanResultVuln => ({
  name: 'test-pkg',
  version: '1.0.0',
  cve: 'CVE-2021-1234',
  in_kev: false,
  cvss_base_score: '5.0',
  cvss_temporal_score: '4.0',
  fixed_versions: '1.0.1',
  ...overrides,
})

describe('Scan', () => {
  describe('processThresholds', () => {
    it('should process thresholds correctly with no vulnerabilities', () => {
      const mockInput = jest.spyOn(core, 'getInput')
      mockInput.mockImplementation(name => {
        switch (name) {
          case 'scan-cvss-base-threshold':
            return '7.0'
          case 'scan-cvss-temporal-threshold':
            return '5.0'
          default:
            return ''
        }
      })

      const result: ScanResult = {
        vulnerabilities: [],
        failed: '',
        success: '',
      }

      const expected: ScanThreshold = {
        base: '7.0',
        temporal: '5.0',
        baseMatches: [],
        temporalMatches: [],
        baseMatchesBelow: [],
        temporalMatchesBelow: [],
        total: 0,
        totalBelow: 0,
      }

      expect(processThresholds(result)).toEqual(expected)
    })

    it('should filter vulnerabilities by base threshold', () => {
      jest.spyOn(core, 'getInput').mockImplementation(name => {
        if (name === 'scan-cvss-base-threshold') return '7.0'
        if (name === 'scan-cvss-temporal-threshold') return ''
        return ''
      })

      const result: ScanResult = {
        vulnerabilities: [
          makeVuln({ cve: 'CVE-1', cvss_base_score: '9.0' }),
          makeVuln({ cve: 'CVE-2', cvss_base_score: '7.0' }),
          makeVuln({ cve: 'CVE-3', cvss_base_score: '4.0' }),
        ],
        failed: '',
        success: '',
      }

      const thresholds = processThresholds(result)

      expect(thresholds.baseMatches).toHaveLength(2)
      expect(thresholds.baseMatchesBelow).toHaveLength(1)
      expect(thresholds.total).toBe(2)
      expect(thresholds.totalBelow).toBe(1)
    })

    it('should filter vulnerabilities by temporal threshold', () => {
      jest.spyOn(core, 'getInput').mockImplementation(name => {
        if (name === 'scan-cvss-base-threshold') return ''
        if (name === 'scan-cvss-temporal-threshold') return '6.0'
        return ''
      })

      const result: ScanResult = {
        vulnerabilities: [
          makeVuln({ cve: 'CVE-1', cvss_temporal_score: '8.0' }),
          makeVuln({ cve: 'CVE-2', cvss_temporal_score: '3.0' }),
        ],
        failed: '',
        success: '',
      }

      const thresholds = processThresholds(result)

      expect(thresholds.temporalMatches).toHaveLength(1)
      expect(thresholds.temporalMatchesBelow).toHaveLength(1)
    })
  })

  describe('scanDiff', () => {
    it('should calculate differences correctly', () => {
      const prevScan: ScanResult = {
        vulnerabilities: [
          makeVuln({ cve: 'CVE-2021-1234' }),
          makeVuln({ cve: 'CVE-2021-2345', cvss_base_score: '7.0' }),
        ],
        failed: '',
        success: '',
      }

      const currentScan: ScanResult = {
        vulnerabilities: [
          makeVuln({ cve: 'CVE-2021-2345', cvss_base_score: '7.0' }),
          makeVuln({ cve: 'CVE-2021-3456', cvss_base_score: '8.0' }),
        ],
        failed: '',
        success: '',
      }

      const expectedDiff = [
        { cve: 'CVE-2021-1234', added: true },
        { cve: 'CVE-2021-3456', removed: true },
      ]

      expect(scanDiff(prevScan, currentScan)).toEqual(expectedDiff)
    })
  })

  describe('scan', () => {
    beforeEach(() => {
      jest.clearAllMocks()
      ;(github.context as { payload: unknown }).payload = {}

      jest.spyOn(core, 'getInput').mockImplementation(name => {
        switch (name) {
          case 'scan-path':
            return '.'
          case 'scan-cvss-base-threshold':
            return ''
          case 'scan-cvss-temporal-threshold':
            return ''
          case 'github-token':
            return 'test-token'
          default:
            return ''
        }
      })
    })

    it('should handle null vulnerabilities and set success', async () => {
      jest
        .mocked(fsPromises.readFile)
        .mockResolvedValue(JSON.stringify({ vulnerabilities: null }))

      const result = await scan()

      expect(result.vulnerabilities).toEqual([])
      expect(result.success).toBeDefined()
      expect(core.setOutput).toHaveBeenCalledWith('scan-count', 0)
      expect(core.setOutput).toHaveBeenCalledWith(
        'scan-signature',
        expect.any(String),
      )
    })

    it('should fail when vulnerabilities found with no threshold set', async () => {
      jest
        .mocked(fsPromises.readFile)
        .mockResolvedValue(JSON.stringify({ vulnerabilities: [makeVuln()] }))

      const result = await scan()

      expect(result.failed).toContain('1 vulnerabilities')
    })

    it('should fail when vulnerabilities exceed base threshold', async () => {
      jest.spyOn(core, 'getInput').mockImplementation(name => {
        switch (name) {
          case 'scan-path':
            return '.'
          case 'scan-cvss-base-threshold':
            return '7.0'
          case 'scan-cvss-temporal-threshold':
            return ''
          case 'github-token':
            return 'test-token'
          default:
            return ''
        }
      })
      ;(fsPromises.readFile as jest.Mock).mockResolvedValue(
        JSON.stringify({
          vulnerabilities: [makeVuln({ cvss_base_score: '9.0' })],
        }),
      )

      const result = await scan()

      expect(result.failed).toBeDefined()
    })

    it('should succeed when vulnerabilities are all below threshold', async () => {
      jest.spyOn(core, 'getInput').mockImplementation(name => {
        switch (name) {
          case 'scan-path':
            return '.'
          case 'scan-cvss-base-threshold':
            return '9.0'
          case 'scan-cvss-temporal-threshold':
            return '9.0'
          case 'github-token':
            return 'test-token'
          default:
            return ''
        }
      })
      ;(fsPromises.readFile as jest.Mock).mockResolvedValue(
        JSON.stringify({
          vulnerabilities: [
            makeVuln({ cvss_base_score: '4.0', cvss_temporal_score: '3.0' }),
          ],
        }),
      )

      const result = await scan()

      expect(result.failed).toBeUndefined()
    })

    it('should emit notices when scan-cve-details is set', async () => {
      jest.spyOn(core, 'getInput').mockImplementation(name => {
        switch (name) {
          case 'scan-path':
            return '.'
          case 'scan-cvss-base-threshold':
            return ''
          case 'scan-cvss-temporal-threshold':
            return ''
          case 'scan-cve-details':
            return 'true'
          case 'github-token':
            return 'test-token'
          default:
            return ''
        }
      })

      const vuln = makeVuln({
        purl_detail: {
          purl: 'pkg:npm/test-pkg@1.0.0',
          type: 'npm',
          cataloger: 'npm-cataloger',
          locations: ['package-lock.json'],
        },
      })
      ;(fsPromises.readFile as jest.Mock).mockResolvedValue(
        JSON.stringify({ vulnerabilities: [vuln] }),
      )

      await scan()

      expect(core.notice).toHaveBeenCalled()
    })

    it('should handle PR context with no previous comment and post one', async () => {
      const mockCreateComment = jest.fn().mockResolvedValue({})
      const mockListComments = jest.fn().mockResolvedValue({ data: [] })
      ;(github.getOctokit as jest.Mock).mockReturnValue({
        rest: {
          issues: {
            listComments: mockListComments,
            createComment: mockCreateComment,
          },
        },
      })
      ;(github.context as { payload: unknown }).payload = {
        pull_request: { number: 42 },
      }
      ;(fsPromises.readFile as jest.Mock).mockResolvedValue(
        JSON.stringify({ vulnerabilities: [] }),
      )

      const result = await scan()

      // Flush microtasks so the unawaited comment() call completes
      await new Promise(resolve => setImmediate(resolve))
      await new Promise(resolve => setImmediate(resolve))

      expect(result.success).toBeDefined()
      expect(mockListComments).toHaveBeenCalled()
      expect(mockCreateComment).toHaveBeenCalled()
    })

    it('should skip comment when signature matches previous', async () => {
      jest
        .mocked(fsPromises.readFile)
        .mockResolvedValue(JSON.stringify({ vulnerabilities: [] }))

      // Compute what the signature will be for this result
      const crypto = await import('crypto')
      const resultObj = { vulnerabilities: [] }
      const hash = crypto.createHash('sha256')
      hash.update(JSON.stringify(resultObj))
      const sig = hash.digest('hex')

      const existingBody = `<!-- vulncheck-scan-signature: ${sig} -->content<!-- vulncheck-scan-report: ${JSON.stringify(resultObj)} -->`
      const mockListComments = jest
        .fn()
        .mockResolvedValue({ data: [{ body: existingBody }] })
      ;(github.getOctokit as jest.Mock).mockReturnValue({
        rest: { issues: { listComments: mockListComments } },
      })
      ;(github.context as { payload: unknown }).payload = {
        pull_request: { number: 42 },
      }

      const result = await scan()

      expect(result.success).toBeDefined()
      expect(core.info).toHaveBeenCalledWith(
        'Same scan result signature matches, skipping comment',
      )
    })

    it('should comment with diff when signature differs from previous', async () => {
      const currentVulns = [makeVuln({ cve: 'CVE-NEW' })]
      ;(fsPromises.readFile as jest.Mock).mockResolvedValue(
        JSON.stringify({ vulnerabilities: currentVulns }),
      )

      const prevResult: ScanResult = {
        vulnerabilities: [makeVuln({ cve: 'CVE-OLD' })],
      }
      const oldSig = 'a'.repeat(64)
      const existingBody = `<!-- vulncheck-scan-signature: ${oldSig} -->content<!-- vulncheck-scan-report: ${JSON.stringify(prevResult)} -->`

      const mockListComments = jest
        .fn()
        .mockResolvedValue({ data: [{ body: existingBody }] })
      const mockCreateComment = jest.fn().mockResolvedValue({})
      ;(github.getOctokit as jest.Mock).mockReturnValue({
        rest: {
          issues: {
            listComments: mockListComments,
            createComment: mockCreateComment,
          },
        },
      })
      ;(github.context as { payload: unknown }).payload = {
        pull_request: { number: 42 },
      }

      jest.spyOn(core, 'getInput').mockImplementation(name => {
        switch (name) {
          case 'scan-path':
            return '.'
          case 'scan-cvss-base-threshold':
            return ''
          case 'scan-cvss-temporal-threshold':
            return ''
          case 'github-token':
            return 'test-token'
          default:
            return ''
        }
      })

      await scan()
      await new Promise(resolve => setImmediate(resolve))
      await new Promise(resolve => setImmediate(resolve))

      expect(core.info).toHaveBeenCalledWith(
        'Different scan result found, commenting the change',
      )
      expect(mockCreateComment).toHaveBeenCalled()
    })

    it('should fail and comment when temporal threshold is exceeded', async () => {
      jest.spyOn(core, 'getInput').mockImplementation(name => {
        switch (name) {
          case 'scan-path':
            return '.'
          case 'scan-cvss-base-threshold':
            return ''
          case 'scan-cvss-temporal-threshold':
            return '5.0'
          case 'github-token':
            return 'test-token'
          default:
            return ''
        }
      })
      ;(fsPromises.readFile as jest.Mock).mockResolvedValue(
        JSON.stringify({
          vulnerabilities: [makeVuln({ cvss_temporal_score: '8.0' })],
        }),
      )

      const result = await scan()

      expect(result.failed).toContain('temporal score threshold')
    })

    it('should run npm ls and emit stdout notices when scan-cve-npm-rel is set', async () => {
      jest.spyOn(core, 'getInput').mockImplementation(name => {
        switch (name) {
          case 'scan-path':
            return '.'
          case 'scan-cve-npm-rel':
            return 'true'
          case 'scan-cvss-base-threshold':
            return ''
          case 'scan-cvss-temporal-threshold':
            return ''
          case 'github-token':
            return 'test-token'
          default:
            return ''
        }
      })
      ;(exec as jest.Mock).mockImplementation(
        async (
          _cmd: string,
          _args: string[],
          options: { listeners?: { stdout?: (d: Buffer) => void } },
        ) => {
          options?.listeners?.stdout?.(Buffer.from('test-pkg@1.0.0\n'))
          return 0
        },
      )
      ;(fsPromises.readFile as jest.Mock).mockResolvedValue(
        JSON.stringify({ vulnerabilities: [makeVuln()] }),
      )

      await scan()

      expect(core.notice).toHaveBeenCalledWith('test-pkg@1.0.0\n')
    })

    it('should post comment with threshold headers when in PR context with threshold matches', async () => {
      jest.spyOn(core, 'getInput').mockImplementation(name => {
        switch (name) {
          case 'scan-path':
            return '.'
          case 'scan-cvss-base-threshold':
            return '7.0'
          case 'scan-cvss-temporal-threshold':
            return '5.0'
          case 'github-token':
            return 'test-token'
          default:
            return ''
        }
      })

      const mockCreateComment = jest.fn().mockResolvedValue({})
      ;(github.getOctokit as jest.Mock).mockReturnValue({
        rest: {
          issues: {
            listComments: jest.fn().mockResolvedValue({ data: [] }),
            createComment: mockCreateComment,
          },
        },
      })
      ;(github.context as { payload: unknown }).payload = {
        pull_request: { number: 42 },
      }
      ;(fsPromises.readFile as jest.Mock).mockResolvedValue(
        JSON.stringify({
          vulnerabilities: [
            makeVuln({
              cve: 'CVE-HIGH',
              cvss_base_score: '9.0',
              cvss_temporal_score: '8.0',
            }),
            makeVuln({
              cve: 'CVE-LOW',
              cvss_base_score: '3.0',
              cvss_temporal_score: '2.0',
            }),
          ],
        }),
      )

      const result = await scan()
      await new Promise(resolve => setImmediate(resolve))
      await new Promise(resolve => setImmediate(resolve))

      expect(result.failed).toBeDefined()
      expect(mockCreateComment).toHaveBeenCalled()
      const body = mockCreateComment.mock.calls[0][0].body
      expect(body).toContain('CVSS base threshold set to')
      expect(body).toContain('CVSS temporal threshold set to')
      expect(body).toContain(
        'Vulnerabillites found equal to or above the threshold',
      )
      expect(body).toContain('Vulnerabillites found below the threshold')
    })

    it('should include previous threshold matches in comment when diff exists', async () => {
      jest.spyOn(core, 'getInput').mockImplementation(name => {
        switch (name) {
          case 'scan-path':
            return '.'
          case 'scan-cvss-base-threshold':
            return '7.0'
          case 'scan-cvss-temporal-threshold':
            return ''
          case 'github-token':
            return 'test-token'
          default:
            return ''
        }
      })

      const prevResult: ScanResult = {
        vulnerabilities: [makeVuln({ cve: 'CVE-OLD', cvss_base_score: '9.0' })],
      }
      const oldSig = 'b'.repeat(64)
      const existingBody = `<!-- vulncheck-scan-signature: ${oldSig} -->x<!-- vulncheck-scan-report: ${JSON.stringify(prevResult)} -->`

      const mockCreateComment = jest.fn().mockResolvedValue({})
      ;(github.getOctokit as jest.Mock).mockReturnValue({
        rest: {
          issues: {
            listComments: jest
              .fn()
              .mockResolvedValue({ data: [{ body: existingBody }] }),
            createComment: mockCreateComment,
          },
        },
      })
      ;(github.context as { payload: unknown }).payload = {
        pull_request: { number: 42 },
      }
      ;(fsPromises.readFile as jest.Mock).mockResolvedValue(
        JSON.stringify({
          vulnerabilities: [
            makeVuln({ cve: 'CVE-NEW', cvss_base_score: '9.0' }),
          ],
        }),
      )

      const result = await scan()
      await new Promise(resolve => setImmediate(resolve))
      await new Promise(resolve => setImmediate(resolve))

      expect(result.failed).toBeDefined()
      expect(mockCreateComment).toHaveBeenCalled()
    })

    it('should post comment with added-only diff body', async () => {
      const prevResult: ScanResult = {
        vulnerabilities: [makeVuln({ cve: 'CVE-SAME' })],
      }
      const oldSig = 'c'.repeat(64)
      const existingBody = `<!-- vulncheck-scan-signature: ${oldSig} -->x<!-- vulncheck-scan-report: ${JSON.stringify(prevResult)} -->`

      const mockCreateComment = jest.fn().mockResolvedValue({})
      ;(github.getOctokit as jest.Mock).mockReturnValue({
        rest: {
          issues: {
            listComments: jest
              .fn()
              .mockResolvedValue({ data: [{ body: existingBody }] }),
            createComment: mockCreateComment,
          },
        },
      })
      ;(github.context as { payload: unknown }).payload = {
        pull_request: { number: 42 },
      }

      // Current has CVE-SAME (kept) + CVE-NEW (added), nothing removed
      ;(fsPromises.readFile as jest.Mock).mockResolvedValue(
        JSON.stringify({
          vulnerabilities: [
            makeVuln({ cve: 'CVE-SAME' }),
            makeVuln({ cve: 'CVE-NEW' }),
          ],
        }),
      )

      await scan()
      await new Promise(resolve => setImmediate(resolve))
      await new Promise(resolve => setImmediate(resolve))

      expect(mockCreateComment).toHaveBeenCalled()
      const body = mockCreateComment.mock.calls[0][0].body
      // Use specific phrasing from the header sentence rather than 'added' alone,
      // and check for the prose suffix 'fixed\n\n' rather than bare 'fixed', because
      // the table always renders a 'Fixed Versions' column header which would cause
      // both plain-string checks to match regardless of the diff branch taken.
      expect(body).toContain('with **1** added')
      expect(body).not.toContain('fixed\n\n')
    })

    it('should post comment with fixed-only diff body', async () => {
      const prevResult: ScanResult = {
        vulnerabilities: [
          makeVuln({ cve: 'CVE-SAME' }),
          makeVuln({ cve: 'CVE-FIXED' }),
        ],
      }
      const oldSig = 'd'.repeat(64)
      const existingBody = `<!-- vulncheck-scan-signature: ${oldSig} -->x<!-- vulncheck-scan-report: ${JSON.stringify(prevResult)} -->`

      const mockCreateComment = jest.fn().mockResolvedValue({})
      ;(github.getOctokit as jest.Mock).mockReturnValue({
        rest: {
          issues: {
            listComments: jest
              .fn()
              .mockResolvedValue({ data: [{ body: existingBody }] }),
            createComment: mockCreateComment,
          },
        },
      })
      ;(github.context as { payload: unknown }).payload = {
        pull_request: { number: 42 },
      }

      // Current only has CVE-SAME; CVE-FIXED was removed, nothing added
      ;(fsPromises.readFile as jest.Mock).mockResolvedValue(
        JSON.stringify({
          vulnerabilities: [makeVuln({ cve: 'CVE-SAME' })],
        }),
      )

      await scan()
      await new Promise(resolve => setImmediate(resolve))
      await new Promise(resolve => setImmediate(resolve))

      expect(mockCreateComment).toHaveBeenCalled()
      const body = mockCreateComment.mock.calls[0][0].body
      expect(body).toContain('fixed')
      expect(body).not.toContain('added')
    })
  })
})
