import * as core from '@actions/core'
import { install } from './install'

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    const pat = core.getInput('cli_pat', { required: true })

    await install({
      pat,
      owner: 'vulncheck-oss',
      repo: 'cli',
    })
  } catch (error) {
    // Fail the workflow run if an error occurs
    if (error instanceof Error) core.setFailed(error.message)
  }
}
