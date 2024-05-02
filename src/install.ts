import * as github from '@actions/github'
import axios from 'axios'
import * as exec from '@actions/exec'
import * as fs from 'fs'
import { GitHub } from '@actions/github/lib/utils'
import { Endpoints } from '@octokit/types'

type Release =
  Endpoints['GET /repos/{owner}/{repo}/releases/latest']['response']['data']
type Asset = Release['assets'][number]

export async function getLatestRelease(
  octokit: InstanceType<typeof GitHub>,
  owner: string,
  repo: string,
): Promise<Release> {
  const { data: release } = await octokit.rest.repos.getLatestRelease({
    owner,
    repo,
  })

  return release
}

export function findAsset(release: Release): Asset {
  const asset = release.assets.find(a =>
    a.name.match(/vc_.*_linux_amd64.tar.gz/),
  )

  if (!asset || !asset.browser_download_url) {
    throw new Error('Unable to find the asset in the release.')
  }

  return asset
}

export async function downloadAsset(
  asset: Asset,
  pat: string,
): Promise<ArrayBuffer> {
  const response = await axios.get(asset.browser_download_url, {
    responseType: 'arraybuffer',
    headers: {
      Accept: 'application/octet-stream',
      Authorization: `token ${pat}`,
    },
  })

  return response.data
}

export async function install(
  {
    pat,
    owner,
    repo,
  }: {
    pat: string
    owner: string
    repo: string
  },
  execParam = exec,
  fsParam = fs,
): Promise<void> {
  const octokit = github.getOctokit(pat)
  const release = await getLatestRelease(octokit, owner, repo)
  const asset = findAsset(release)
  const data = await downloadAsset(asset, pat)

  fsParam.writeFileSync(asset.name, Buffer.from(data))
  await execParam.exec(`tar zxvf ${asset.name}`)
  await execParam.exec(`rm ${asset.name}`)
  await execParam.exec(
    `sudo mv ${asset.name.replace('.tar.gz', '')}/bin/vc /usr/local/bin/vc`,
  )
  await execParam.exec(`rm -rf  ${asset.name.replace('.tar.gz', '')}`)
  await execParam.exec(`vc version`)
}
