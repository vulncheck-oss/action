import * as core from '@actions/core'
import { install } from './install'
import { scan } from './scan'

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    const command = core.getInput('command')
    const token = core.getInput('github-token', { required: true })
    process.env.VC_TOKEN = core.getInput('token', { required: true })

    await install({
      token,
      owner: 'vulncheck-oss',
      repo: 'cli',
    })

    switch (command) {
      case 'scan': {
        const result = await scan()
        if (result.failed) core.setFailed(result.failed)
        if (result.success) core.notice(result.success)
        break
      }
      default:
        core.setFailed(`Unknown command: ${command}`)
    }
  } catch (error) {
    // Fail the workflow run if an error occurs
    if (error instanceof Error) core.setFailed(error.message)
  }
}
