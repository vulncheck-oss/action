import * as core from '@actions/core'
import * as github from '@actions/github'
import * as exec from '@actions/exec'
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

    /*
    await exec.exec(
      `wget --auth-no-challenge --header 'Authorization: token ${pat}' --header='Accept:application/octet-stream' https://api.github.com/repos/vulncheck-oss/cli/releases/assets/${asset.id} -O ${asset.name}`
    )
    */

    await exec.exec(`
      curl -L \
        -H "Accept: application/octet-stream" \ 
        -H "Authorization: Bearer ${pat}"\
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -o ${asset.name} \
        https://api.github.com/repos/vulncheck-oss/cli/releases/assets/${asset.id}
    `)

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

    await exec.exec(`file ${asset.name}`)
    await exec.exec(`cat ${asset.name}`)
  } catch (error) {
    // Fail the workflow run if an error occurs
    if (error instanceof Error) core.setFailed(error.message)
  }
}
