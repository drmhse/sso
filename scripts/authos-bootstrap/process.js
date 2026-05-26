const { spawn } = require('node:child_process');

async function assertCommand(command, args, root) {
  await run(command, args, root, { quiet: true });
}

function run(command, args, cwd, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: options.env ? { ...process.env, ...options.env } : process.env,
      stdio: options.quiet ? 'pipe' : 'inherit',
    });
    let stdout = '';
    let stderr = '';
    if (options.quiet) {
      child.stdout?.on('data', (chunk) => {
        stdout += chunk.toString();
      });
    }
    if (options.quiet) {
      child.stderr?.on('data', (chunk) => {
        stderr += chunk.toString();
      });
    }
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve({ stdout, stderr });
      else {
        reject(
          new Error(
            `${command} ${args.join(' ')} exited with ${code}${stderr ? `: ${stderr}` : ''}`,
          ),
        );
      }
    });
  });
}

module.exports = {
  assertCommand,
  run,
};
