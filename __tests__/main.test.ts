import type { ScanResult } from '../src/types'
import * as core from '@actions/core'
import * as main from '../src/main'
import * as installModule from '../src/install'
import * as scanModule from '../src/scan'

const runMock = jest.spyOn(main, 'run')

let getInputMock: jest.SpiedFunction<typeof core.getInput>

describe('action', () => {
  beforeEach(() => {
    jest.clearAllMocks()

    getInputMock = jest.spyOn(core, 'getInput').mockImplementation()
    jest.spyOn(core, 'setFailed').mockImplementation()
    jest.spyOn(core, 'notice').mockImplementation()

    jest.spyOn(installModule, 'install').mockResolvedValue()
    jest.spyOn(scanModule, 'scan').mockResolvedValue({ vulnerabilities: [] })
  })

  it('runs scan command and calls notice on success', async () => {
    getInputMock.mockImplementation(name => {
      switch (name) {
        case 'command':
          return 'scan'
        case 'github-token':
          return 'test-token'
        case 'token':
          return 'vc-token'
        default:
          return ''
      }
    })

    jest.spyOn(scanModule, 'scan').mockResolvedValue({
      vulnerabilities: [],
      success: 'No vulnerabilities found',
    })

    await main.run()

    expect(runMock).toHaveReturned()
    expect(core.notice).toHaveBeenCalledWith('No vulnerabilities found')
  })

  it('calls setFailed when scan returns a failure', async () => {
    getInputMock.mockImplementation(name => {
      switch (name) {
        case 'command':
          return 'scan'
        case 'github-token':
          return 'test-token'
        case 'token':
          return 'vc-token'
        default:
          return ''
      }
    })

    jest.spyOn(scanModule, 'scan').mockResolvedValue({
      vulnerabilities: [],
      failed: 'Found 1 vulnerability',
    })

    await main.run()

    expect(core.setFailed).toHaveBeenCalledWith('Found 1 vulnerability')
  })

  it('calls setFailed for unknown command', async () => {
    getInputMock.mockImplementation(name => {
      switch (name) {
        case 'command':
          return 'unknown-command'
        case 'github-token':
          return 'test-token'
        case 'token':
          return 'vc-token'
        default:
          return ''
      }
    })

    await main.run()

    expect(core.setFailed).toHaveBeenCalledWith(
      'Unknown command: unknown-command',
    )
  })

  it('calls setFailed when an error is thrown', async () => {
    getInputMock.mockImplementation(name => {
      switch (name) {
        case 'command':
          return 'scan'
        case 'github-token':
          return 'test-token'
        case 'token':
          return 'vc-token'
        default:
          return ''
      }
    })

    jest
      .spyOn(installModule, 'install')
      .mockRejectedValue(new Error('network failure'))

    await main.run()

    expect(core.setFailed).toHaveBeenCalledWith('network failure')
  })
})
