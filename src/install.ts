import * as github from '@actions/github'
import axios from 'axios'
import * as exec from '@actions/exec'
import * as fs from 'fs'

/**
 * Install the latest release of the VulnCheck CLI
 * @param pat The GitHub Personal Access Token to use for the installation.
 * @param owner The owner of the repository to install from.
 * @param repo The repository to install from.
 * @returns {Promise<void>} Resolves when the installation is complete.
 */
export async function install({
  pat,
  owner,
  repo,
}: {
  pat: string
  owner: string
  repo: string
}): Promise<void> {
  const octokit = github.getOctokit(pat)

  const { data: release } = await octokit.rest.repos.getLatestRelease({
    owner,
    repo,
  })

  const asset = release.assets.find(a =>
    a.name.match(/vc_.*_linux_amd64.tar.gz/),
  )

  if (!asset || !asset.browser_download_url) {
    throw new Error('Unable to find the asset in the release.')
  }

  const response = await axios.get(asset.url, {
    responseType: 'arraybuffer',
    headers: {
      Accept: 'application/octet-stream',
      Authorization: `token ${pat}`,
    },
  })

  fs.writeFileSync(asset.name, response.data)
  await exec.exec(`tar zxvf ${asset.name}`)
  await exec.exec(`rm ${asset.name}`)
  await exec.exec(
    `sudo mv ${asset.name.replace('.tar.gz', '')}/bin/vc /usr/local/bin/vc`,
  )
  await exec.exec(`rm -rf  ${asset.name.replace('.tar.gz', '')}`)
  await exec.exec(`vc version`)
}