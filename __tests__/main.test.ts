/**
 * Unit tests for the action's main functionality, src/main.ts
 *
 * These should be run as if the action was called from a workflow.
 * Specifically, the inputs listed in `action.yml` should be set as environment
 * variables following the pattern `INPUT_<INPUT_NAME>`.
 */

import type { ScanResult } from '../src/types'
import * as core from '@actions/core'
import * as main from '../src/main'
import * as installModule from '../src/install'
import * as scanModule from '../src/scan'

// Mock the action's main function
const runMock = jest.spyOn(main, 'run')

/* Mock the GitHub Actions core library
let debugMock: jest.SpiedFunction<typeof core.debug>
let errorMock: jest.SpiedFunction<typeof core.error>
*/
let getInputMock: jest.SpiedFunction<typeof core.getInput>
/*
let setFailedMock: jest.SpiedFunction<typeof core.setFailed>
let setOutputMock: jest.SpiedFunction<typeof core.setOutput>
*/

describe('action', () => {
  beforeEach(() => {
    jest.clearAllMocks()

    // debugMock = jest.spyOn(core, 'debug').mockImplementation()
    // errorMock = jest.spyOn(core, 'error').mockImplementation()
    getInputMock = jest.spyOn(core, 'getInput').mockImplementation()
    // setFailedMock = jest.spyOn(core, 'setFailed').mockImplementation()
    // setOutputMock = jest.spyOn(core, 'setOutput').mockImplementation()

    // Create a mock of the install function
    const installMock = jest.spyOn(installModule, 'install')
    installMock.mockImplementation(async () => {})

    // Mock the scan function to be a no-op
    const scanMock = jest.spyOn(scanModule, 'scan')
    scanMock.mockImplementation(async (): Promise<ScanResult> => {
      return { vulnerabilities: [] }
    })
  })

  it('test placeholder', async () => {
    getInputMock.mockImplementation(name => {
      switch (name) {
        case 'cli_pat':
          return 'foo'
        case 'command':
          return 'scan'
        default:
          return ''
      }
    })

    // Mock the install function to be a no-op
    const installMock = installModule.install as jest.MockedFunction<
      typeof installModule.install
    >
    installMock.mockImplementation(async () => {})

    const scanMock = scanModule.scan as jest.MockedFunction<
      typeof scanModule.scan
    >
    scanMock.mockImplementation(async (): Promise<ScanResult> => {
      return { vulnerabilities: [] }
    })

    await main.run()
    expect(runMock).toHaveReturned()
  })
})
