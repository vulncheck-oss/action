import * as github from '@actions/github'
import axios from 'axios'
import * as fs from 'fs'
import { install } from '../src/install'

jest.mock('@actions/github')
jest.mock('axios')
jest.mock('@actions/exec', () => ({ exec: jest.fn().mockResolvedValue(0) }))
jest.mock('fs')

const mockAsset = {
  name: 'vulncheck_1.0.0_linux_amd64.tar.gz',
  browser_download_url:
    'https://example.com/vulncheck_1.0.0_linux_amd64.tar.gz',
  url: 'https://api.github.com/repos/vulncheck-oss/cli/releases/assets/123',
}

describe('install', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('should install the latest release successfully', async () => {
    const mockGetLatestRelease = jest.fn().mockResolvedValue({
      data: { assets: [mockAsset] },
    })
    jest.mocked(github.getOctokit).mockReturnValue({
      rest: { repos: { getLatestRelease: mockGetLatestRelease } },
    } as never)
    const getMock = jest
      .spyOn(axios, 'get')
      .mockResolvedValue({ data: Buffer.from('binary') })
    const writeFileSyncMock = jest
      .spyOn(fs, 'writeFileSync')
      .mockImplementation(() => {})

    await install({ token: 'test-token', owner: 'vulncheck-oss', repo: 'cli' })

    expect(mockGetLatestRelease).toHaveBeenCalledWith({
      owner: 'vulncheck-oss',
      repo: 'cli',
    })
    expect(getMock).toHaveBeenCalledWith(mockAsset.url, expect.any(Object))
    expect(writeFileSyncMock).toHaveBeenCalledWith(
      mockAsset.name,
      expect.anything(),
    )
  })

  it('should throw when no matching linux_amd64 asset is found', async () => {
    jest.mocked(github.getOctokit).mockReturnValue({
      rest: {
        repos: {
          getLatestRelease: jest.fn().mockResolvedValue({
            data: {
              assets: [
                {
                  name: 'vulncheck_1.0.0_darwin_arm64.tar.gz',
                  browser_download_url: 'https://example.com/darwin',
                  url: 'https://api.github.com/repos/vulncheck-oss/cli/releases/assets/456',
                },
              ],
            },
          }),
        },
      },
    } as never)

    await expect(
      install({ token: 'test-token', owner: 'vulncheck-oss', repo: 'cli' }),
    ).rejects.toThrow('Unable to find the asset in the release.')
  })

  it('should throw when assets list is empty', async () => {
    jest.mocked(github.getOctokit).mockReturnValue({
      rest: {
        repos: {
          getLatestRelease: jest.fn().mockResolvedValue({
            data: { assets: [] },
          }),
        },
      },
    } as never)

    await expect(
      install({ token: 'test-token', owner: 'vulncheck-oss', repo: 'cli' }),
    ).rejects.toThrow('Unable to find the asset in the release.')
  })
})
