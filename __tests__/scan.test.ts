import type { ScanThreshold, ScanResult } from '../src/types'
import { processThresholds, scanDiff } from '../src/scan'
import * as core from '@actions/core'

jest.mock('@actions/core')

describe('Scan', () => {
  describe('processThresholds', () => {
    it('should process thresholds correctly', () => {
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
  })

  describe('scanDiff', () => {
    it('should calculate differences correctly', () => {
      const prevScan: ScanResult = {
        vulnerabilities: [
          {
            name: 'vuln1',
            version: '1.0.0',
            cve: 'CVE-2021-1234',
            in_kev: false,
            cvss_base_score: '5.0',
            cvss_temporal_score: '4.0',
            fixed_versions: '1.0.1',
          },
          {
            name: 'vuln2',
            version: '2.0.0',
            cve: 'CVE-2021-2345',
            in_kev: false,
            cvss_base_score: '7.0',
            cvss_temporal_score: '6.0',
            fixed_versions: '2.0.1',
          },
        ],
        failed: '',
        success: '',
      }

      const currentScan: ScanResult = {
        vulnerabilities: [
          {
            name: 'vuln2',
            version: '2.0.0',
            cve: 'CVE-2021-2345',
            in_kev: false,
            cvss_base_score: '7.0',
            cvss_temporal_score: '6.0',
            fixed_versions: '2.0.1',
          },
          {
            name: 'vuln3',
            version: '3.0.0',
            cve: 'CVE-2021-3456',
            in_kev: false,
            cvss_base_score: '8.0',
            cvss_temporal_score: '7.0',
            fixed_versions: '3.0.1',
          },
        ],
        failed: '',
        success: '',
      }

      const expectedDiff = [
        {
          cve: 'CVE-2021-1234',
          added: true,
        },
        {
          cve: 'CVE-2021-3456',
          removed: true,
        },
      ]

      expect(scanDiff(prevScan, currentScan)).toEqual(expectedDiff)
    })
  })
})
