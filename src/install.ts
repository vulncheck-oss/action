import * as github from '@actions/github'
import axios from 'axios'
import { exec } from '@actions/exec'
import * as fs from 'fs'

/**
 * Install the latest release of the VulnCheck CLI
 * @param token The GitHub Token to use for the installation.
 * @param owner The owner of the repository to install from.
 * @param repo The repository to install from.
 * @returns {Promise<void>} Resolves when the installation is complete.
 */
export async function install({
  token,
  owner,
  repo,
}: {
  token: string
  owner: string
  repo: string
}): Promise<void> {
  const octokit = github.getOctokit(token)

  /* get a prerelease 
  const { data: releases } = await octokit.rest.repos.listReleases({
    owner,
    repo,
  })

  const prereleases = releases.filter(release => release.prerelease)
  const release = prereleases[0]
  */

  // get the latest release
  const { data: release } = await octokit.rest.repos.getLatestRelease({
    owner,
    repo,
  })

  const asset = release.assets.find(a =>
    a.name.match(/vci_.*_linux_amd64.tar.gz/),
  )

  if (!asset || !asset.browser_download_url) {
    throw new Error('Unable to find the asset in the release.')
  }

  const response = await axios.get(asset.url, {
    responseType: 'arraybuffer',
    headers: {
      Accept: 'application/octet-stream',
    },
  })

  fs.writeFileSync(asset.name, response.data)
  await exec(`tar zxvf ${asset.name}`)
  await exec(`rm ${asset.name}`)
  await exec(
    `sudo mv ${asset.name.replace('.tar.gz', '')}/bin/vci /usr/local/bin/vci`,
  )
  await exec(`rm -rf  ${asset.name.replace('.tar.gz', '')}`)
  await exec(`vci version`)
}
