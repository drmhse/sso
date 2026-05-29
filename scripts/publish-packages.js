const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Configuration
const SDK_PACKAGE_PATH = path.join(__dirname, '../sso-sdk/package.json');
const PACKAGES_DIR = path.join(__dirname, '../packages');
const DRY_RUN = process.argv.includes('--dry-run');

// Helper to log
const log = (msg) => console.log(`[Publish] ${msg}`);

// Main execution
(async () => {
  try {
    // 1. Get SDK Version
    const sdkPackage = JSON.parse(fs.readFileSync(SDK_PACKAGE_PATH, 'utf8'));
    const sdkVersion = sdkPackage.version;
    log(`Detected SDK version: ${sdkVersion}`);

    // 2. Find all packages in packages/ dir
    const packages = fs.readdirSync(PACKAGES_DIR).filter(file => {
      return fs.statSync(path.join(PACKAGES_DIR, file)).isDirectory();
    });

    log(`Found packages: ${packages.join(', ')}`);

    // 3. Process each package
    for (const pkgName of packages) {
      const pkgJsonPath = path.join(PACKAGES_DIR, pkgName, 'package.json');

      if (!fs.existsSync(pkgJsonPath)) {
        log(`Skipping ${pkgName} (no package.json)`);
        continue;
      }

      // Read original content
      const originalContent = fs.readFileSync(pkgJsonPath, 'utf8');
      const pkgJson = JSON.parse(originalContent);

      // Check dependency
      if (pkgJson.dependencies && pkgJson.dependencies['@drmhse/sso-sdk'] === '*') {
        log(`Updating ${pkgName} dependency to ^${sdkVersion}`);

        // Update to concrete version
        pkgJson.dependencies['@drmhse/sso-sdk'] = `^${sdkVersion}`;
        fs.writeFileSync(pkgJsonPath, JSON.stringify(pkgJson, null, 2) + '\n');

        try {
          // Publish
          log(`Publishing ${pkgName}...`);
          const cmd = DRY_RUN ? 'npm publish --dry-run' : 'npm publish --access public';
          execSync(cmd, {
            cwd: path.join(PACKAGES_DIR, pkgName),
            stdio: 'inherit'
          });
        } catch (err) {
          console.error(`Failed to publish ${pkgName}`);
          throw err;
        } finally {
          // Revert changes
          log(`Reverting ${pkgName} package.json`);
          fs.writeFileSync(pkgJsonPath, originalContent);
        }
      } else {
        log(`Skipping ${pkgName} (dependency not set to *)`);
      }
    }

    log('All packages published successfully!');

  } catch (error) {
    console.error('Publishing failed:', error);
    process.exit(1);
  }
})();
