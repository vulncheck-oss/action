import * as core from '@actions/core'
import * as github from '@actions/github'
import * as exec from '@actions/exec'
import * as fs from 'fs'
import axios from 'axios'

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    // const token = core.getInput('token', { required: true })
    const pat = core.getInput('cli_pat', { required: true })
    const octokit = github.getOctokit(pat)

    const { data: release } = await octokit.rest.repos.getLatestRelease({
      owner: 'vulncheck-oss',
      repo: 'cli'
    })

    // walk through release.assets and look for  vc_*_linux_amd64.tar.gz
    const asset = release.assets.find(a =>
      a.name.match(/vc_.*_linux_amd64.tar.gz/)
    )

    if (!asset || !asset.browser_download_url) {
      throw new Error('Unable to find the asset in the release.')
    }

    // Download the asset using wget
    await exec.exec(
      `curl -o "${asset.name}" -H "Authorization: token ${pat}" ${asset.browser_download_url}`
    )

    // Download the asset
    const response = await axios.get(asset.browser_download_url, {
      responseType: 'arraybuffer',
      headers: {
        Authorization: `token ${pat}`,
        Accept: 'application/octet-stream'
      }
    })

    // Write the downloaded data to a file
    fs.writeFileSync(asset.name, response.data)

    // Extract the file
    await exec.exec(`tar -zxvf ${asset.name}`)

    // Execute ls -la and log the output
    let output = ''
    const options = {
      listeners: {
        stdout: (data: Buffer) => {
          output += data.toString()
        }
      }
    }
    await exec.exec('ls -la', [], options)
    console.log(output)
  } catch (error) {
    // Fail the workflow run if an error occurs
    if (error instanceof Error) core.setFailed(error.message)
  }
}
