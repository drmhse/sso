#!/usr/bin/env node
/**
 * Docker Publish Native Script - Fast builds using cargo-zigbuild (cross-compilation on host)
 * 
 * This is a faster alternative to docker-publish.js for local development.
 * Instead of building inside Docker (slow), this cross-compiles on the host machine
 * using cargo-zigbuild and only uses Docker for the final image packaging.
 * 
 * Requirements:
 * - zig (zigbuild backend): brew install zig
 * - cargo-zigbuild: cargo install cargo-zigbuild
 * - x86_64-unknown-linux-musl target: rustup target add x86_64-unknown-linux-musl
 * 
 * Usage: node docker-publish.js [--backends sqlite,psql,mysql]
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');
const readline = require('readline');

// Colors
const colors = {
    red: '\x1b[0;31m',
    green: '\x1b[0;32m',
    yellow: '\x1b[1;33m',
    blue: '\x1b[0;34m',
    cyan: '\x1b[0;36m',
    reset: '\x1b[0m'
};

const log = {
    info: (msg) => console.log(`${colors.yellow}→${colors.reset} ${msg}`),
    success: (msg) => console.log(`${colors.green}✓${colors.reset} ${msg}`),
    error: (msg) => console.log(`${colors.red}❌${colors.reset} ${msg}`),
    warn: (msg) => console.log(`${colors.yellow}!${colors.reset} ${msg}`)
};

// Configuration
const IMAGE_NAME = 'sso';
const ALL_BACKENDS = ['sqlite', 'psql', 'mysql'];
const BACKEND_COLORS = { sqlite: colors.cyan, psql: colors.blue, mysql: colors.yellow };
const TARGET = 'x86_64-unknown-linux-musl';

// Helpers
function exec(cmd, options = {}) {
    try {
        return execSync(cmd, { encoding: 'utf8', stdio: options.silent ? 'pipe' : 'inherit', ...options });
    } catch (e) {
        if (options.ignoreError) return '';
        throw e;
    }
}

function execOutput(cmd) {
    return execSync(cmd, { encoding: 'utf8', stdio: 'pipe' }).trim();
}

async function prompt(question, defaultValue = '') {
    if (process.env.AUTHOS_KITCHEN === 'true') {
        console.log(`${question}${defaultValue} (AuthOS Kitchen auto-confirm)`);
        return defaultValue;
    }
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => {
        rl.question(question, (answer) => {
            rl.close();
            resolve(answer || defaultValue);
        });
    });
}

async function fetchJson(url) {
    return new Promise((resolve, reject) => {
        https.get(url, { timeout: 10000 }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try { resolve(JSON.parse(data)); }
                catch { resolve(null); }
            });
        }).on('error', () => resolve(null));
    });
}

// Get Docker Hub tags
async function getRemoteTags(image) {
    const data = await fetchJson(`https://hub.docker.com/v2/repositories/${image}/tags?page_size=100`);
    return data?.results?.map(t => t.name) || [];
}

// Get Docker username from config
function getDockerUsername() {
    if (process.env.DOCKER_USERNAME) return process.env.DOCKER_USERNAME;
    if (process.env.DOCKERHUB_NAMESPACE) return process.env.DOCKERHUB_NAMESPACE;

    const dockerConfigPath = path.join(require('os').homedir(), '.docker', 'config.json');
    if (!fs.existsSync(dockerConfigPath)) return null;

    try {
        const config = JSON.parse(fs.readFileSync(dockerConfigPath, 'utf8'));
        const auth = config.auths?.['https://index.docker.io/v1/']?.auth;
        if (auth) {
            return Buffer.from(auth, 'base64').toString().split(':')[0];
        }
        if (config.credsStore) {
            const creds = execOutput(`echo "https://index.docker.io/v1/" | docker-credential-${config.credsStore} get 2>/dev/null || true`);
            if (creds) {
                try { return JSON.parse(creds).Username; } catch { }
            }
        }
    } catch { }
    return null;
}

// Get version from Cargo.toml
function getCargoVersion() {
    const cargo = fs.readFileSync('Cargo.toml', 'utf8');
    const match = cargo.match(/^version\s*=\s*"([^"]+)"/m);
    return match ? match[1] : null;
}

// Set version in Cargo.toml
function setCargoVersion(version) {
    const cargo = fs.readFileSync('Cargo.toml', 'utf8');
    const updated = cargo.replace(/^version\s*=\s*"[^"]+"/m, `version = "${version}"`);
    fs.writeFileSync('Cargo.toml', updated);
    
    log.info('Syncing Cargo.lock...');
    try {
        exec('cargo check', { silent: true });
    } catch (e) {
        log.warn('Failed to sync Cargo.lock via cargo check.');
    }
}

// Bump version
function bumpVersion(version, type) {
    const [major, minor, patch] = version.split('.').map(Number);
    switch (type) {
        case 'major': return `${major + 1}.0.0`;
        case 'minor': return `${major}.${minor + 1}.0`;
        case 'patch': return `${major}.${minor}.${patch + 1}`;
        default: return version;
    }
}

// Check prerequisites
function checkPrerequisites() {
    log.info('Checking prerequisites...');
    
    try {
        execOutput('zig version');
    } catch {
        throw new Error('zig not found. Install with: brew install zig');
    }
    
    try {
        // cargo-zigbuild is invoked as a cargo subcommand OR as cargo-zigbuild directly
        execOutput('cargo-zigbuild --version');
    } catch {
        throw new Error('cargo-zigbuild not found. Install with: cargo install cargo-zigbuild');
    }
    
    const targets = execOutput('rustup target list --installed');
    if (!targets.includes(TARGET)) {
        throw new Error(`Target ${TARGET} not installed. Install with: rustup target add ${TARGET}`);
    }
    
    log.success('All prerequisites met (zig, cargo-zigbuild, musl target)');
}

// Native build for a single backend
async function buildBackendNative(backend, imageName, version) {
    const color = BACKEND_COLORS[backend] || colors.reset;
    const prefix = `${color}[${backend}]${colors.reset}`;
    
    // WebAuthn requires OpenSSL (vendored for static linking)
    console.log(`${prefix} Using Native Static Build (Vendored OpenSSL)...`);

    const binaryName = `sso_${backend}`;
    const distDir = 'target/dist';
    const binaryPath = path.join(distDir, binaryName);
    
    console.log(`${prefix} Building ${backend} backend using cargo-zigbuild...`);
    
    // Step 1: Cross-compile on host
    try {
        const cargoCmd = [
            'cargo', 'zigbuild',
            '--release',
            '--locked',
            `--target=${TARGET}`,
            '--no-default-features',
            `--features=db_${backend}`
        ].join(' ');
        
        exec(cargoCmd, { stdio: 'inherit' });
        
        // Copy binary to dist
        fs.mkdirSync(distDir, { recursive: true });
        const targetBinary = `target/${TARGET}/release/sso_${backend}`;
        fs.copyFileSync(targetBinary, binaryPath);
        
        // Strip binary (essential for size)
        exec(`strip ${binaryPath}`, { silent: true, ignoreError: true });

        // Compress binary with UPX (Ultimate Packer for eXecutables)
        // This effectively crushes the binary size (often >60% reduction)
        // restoring the small image size despite static linking bloat.
        console.log(`${prefix} Compressing binary with UPX...`);
        try {
            exec(`upx --best --lzma ${binaryPath}`, { silent: true });
        } catch (e) {
            console.log(`${prefix} ${colors.yellow}! UPX compression failed (is upx installed? brew install upx). Continuing uncompressed.${colors.reset}`);
        }
        
        console.log(`${prefix} ${colors.green}✓ Cross-compilation & Compression complete${colors.reset}`);
    } catch (e) {
        console.log(`${prefix} ${colors.red}❌ Cargo build failed${colors.reset}`);
        throw e;
    }
    
    // Step 2: Build minimal Docker image (FAST - just copies binary)
    console.log(`${prefix} Building Docker image...`);
    
    const tags = [
        '-t', `${imageName}:${backend}-${version}`,
        '-t', `${imageName}:${backend}-latest`
    ];
    
    if (backend === 'sqlite') {
        tags.push('-t', `${imageName}:${version}`);
        tags.push('-t', `${imageName}:latest`);
    }
    
    // Use Dockerfile which just copies the pre-built binary
    const dockerCmd = [
        'docker', 'build',
        '--platform', 'linux/amd64',
        '-f', 'Dockerfile',
        '--build-arg', `BINARY_NAME=${binaryName}`,
        ...tags,
        '.'
    ];
    
    try {
        exec(dockerCmd.join(' '), { stdio: 'inherit' });
        console.log(`${prefix} ${colors.green}✓ Docker image built${colors.reset}`);
    } catch (e) {
        console.log(`${prefix} ${colors.red}❌ Docker build failed${colors.reset}`);
        throw e;
    }
    
    // Step 3: Push to registry
    console.log(`${prefix} Pushing to Docker Hub...`);
    
    for (let i = 0; i < tags.length; i += 2) {
        const tag = tags[i + 1];
        try {
            exec(`docker push ${tag}`, { stdio: 'inherit' });
        } catch (e) {
            console.log(`${prefix} ${colors.red}❌ Push failed for ${tag}${colors.reset}`);
            throw e;
        }
    }
    
    console.log(`${prefix} ${colors.green}✓ Build and push successful${colors.reset}`);
    return true;
}

// Main
async function main() {
    const scriptDir = path.dirname(__filename);
    const apiDir = path.resolve(scriptDir, '..');
    process.chdir(apiDir);

    // Check prerequisites first
    checkPrerequisites();

    // Parse args
    const args = process.argv.slice(2);
    let backends = ALL_BACKENDS;

    if (process.env.SELECTED_BACKENDS) {
        backends = process.env.SELECTED_BACKENDS.split(',').map(b => b.trim());
    }

    const backendArg = args.find(a => a.startsWith('--backends='));
    if (backendArg) {
        backends = backendArg.split('=')[1].split(',').map(b => b.trim());
    }

    log.success(`Selected backends: ${backends.join(', ')}`);

    // Update from git
    log.info('Updating from origin...');
    const branch = execOutput('git rev-parse --abbrev-ref HEAD');
    exec(`git fetch origin ${branch} --tags`, { silent: true });
    try {
        exec(`git pull --ff-only origin ${branch}`, { silent: true });
    } catch {
        log.error('Failed to pull latest changes. Resolve conflicts and retry.');
        process.exit(1);
    }

    // Get versions
    const currentVersion = getCargoVersion();
    log.info(`Current Cargo version: ${currentVersion}`);

    // Get Docker username
    const dockerUsername = getDockerUsername();
    if (!dockerUsername) {
        log.error('Could not determine Docker username. Set DOCKER_USERNAME env var.');
        process.exit(1);
    }

    const fullImageName = `${dockerUsername}/${IMAGE_NAME}`;

    // Check remote tags
    log.info('Checking Docker Hub for existing tags...');
    const remoteTags = await getRemoteTags(fullImageName);

    const existingBackends = backends.filter(b => remoteTags.includes(`${b}-${currentVersion}`));
    const missingBackends = backends.filter(b => !remoteTags.includes(`${b}-${currentVersion}`));

    if (existingBackends.length > 0) {
        log.success(`Already published at ${currentVersion}: ${existingBackends.join(', ')}`);
    }

    // Determine if we should bump
    const isPartialPublish = existingBackends.length > 0 && missingBackends.length > 0;
    const allPublished = missingBackends.length === 0;

    if (allPublished) {
        log.success(`All backends already published for version ${currentVersion}`);
        const bumpChoice = await prompt(`Bump version for new publish? (patch/minor/major/none) [patch]: `, 'patch');
        if (bumpChoice === 'none') {
            log.success('Nothing to do.');
            process.exit(0);
        }
        const newVersion = bumpVersion(currentVersion, bumpChoice);
        setCargoVersion(newVersion);
        log.success(`Bumped version to ${newVersion}`);
        backends = ALL_BACKENDS;
    } else if (isPartialPublish) {
        log.warn(`Partial publish detected - continuing with ${currentVersion}`);
        backends = missingBackends;
    } else {
        const suggestedBump = 'none';
        const bumpChoice = await prompt(`Bump version before publishing? (patch/minor/major/none) [${suggestedBump}]: `, suggestedBump);
        if (bumpChoice !== 'none') {
            const newVersion = bumpVersion(currentVersion, bumpChoice);
            setCargoVersion(newVersion);
            log.success(`Bumped version to ${newVersion}`);
        }
    }

    const version = getCargoVersion();
    log.info(`Building version: ${version}`);
    log.info(`Backends to build: ${backends.join(', ')}`);

    // Confirm
    console.log('\n==================================================');
    console.log('NATIVE BUILD - Fast Docker Image Publishing');
    console.log('==================================================');
    console.log(`Image Base: ${fullImageName}`);
    console.log(`Version:    ${version}`);
    console.log(`Backends:   ${backends.join(', ')}`);
    console.log(`Method:     cargo-zigbuild (host cross-compilation)`);
    console.log('==================================================\n');

    const confirm = await prompt('Continue? (y/N): ', 'y');
    if (confirm.toLowerCase() !== 'y') {
        console.log('Aborted.');
        process.exit(0);
    }

    // Build backends in parallel (Cargo will serialize compilation via locks, but UPX/Docker steps will run concurrently)
    console.log(`\n${colors.blue}Starting native builds for: ${backends.join(', ')}${colors.reset}\n`);

    let failures = 0;
    const results = await Promise.allSettled(backends.map(b => buildBackendNative(b, fullImageName, version)));

    results.forEach((result, idx) => {
        if (result.status === 'rejected') {
            failures++;
            log.error(`Build failed for ${backends[idx]}: ${result.reason.message}`);
        }
    });
    if (failures === 0) {
        log.success('All images successfully built and pushed!');
        console.log('\nTags published:');
        backends.forEach(b => {
            console.log(`  - ${fullImageName}:${b}-${version}`);
            console.log(`  - ${fullImageName}:${b}-latest`);
        });
        if (backends.includes('sqlite')) {
            console.log(`  - ${fullImageName}:${version}`);
            console.log(`  - ${fullImageName}:latest`);
        }
    } else {
        log.error(`${failures} build(s) failed. Check output above.`);
        process.exit(1);
    }
}

main().catch(e => {
    log.error(e.message);
    process.exit(1);
});
