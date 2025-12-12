# NPM Supply-Chain Detector

This directory hosts a Bash-based scanner that flags compromised npm packages and payload breadcrumbs associated with documented supply chain attacks (September 2025 qix incident, Shai-Hulud 2.0) as well as known CVE vulnerabilities (CVE-2025-55184 and CVE-2025-55183 affecting Next.js and React). Indicators are stored under `attacks/` so that new campaigns and vulnerabilities can be onboarded without rewriting the script.

## Quick Start

```bash
# Scan current directory for all known attacks
./npm-supply-chain-detector

# Scan a specific project
./npm-supply-chain-detector /path/to/project

# Check for specific attack only
./npm-supply-chain-detector -a shai-hulud-2

# Check for CVE-2025-55184 and CVE-2025-55183 (Next.js/React vulnerabilities)
./npm-supply-chain-detector -a vercel-react-nextjs-2025

# List all available attacks
./npm-supply-chain-detector --list-attacks

# Run the bundled sparkSec recipe runner (lists commands if no args are passed)
./sparkSec/sparkSec.sh security-scan-npm
```

> Tip: Symlink `sparkSec/sparkSec.sh` somewhere in your `PATH` (e.g., `/usr/local/bin/sparkSec`) to invoke the same commands from anywhere.

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/sparkfabrik/supply-chain-security-detectors.git
   ```
2. (Optional) Symlink `sparkSec/sparkSec.sh` into your `PATH` so you can run `sparkSec security-*` directly from this repo.
3. Keep the repository up to date to receive new attack signatures.

The detector can be executed directly (`./npm-supply-chain-detector`).

## Features

- **Multi-Attack Detection**: Checks for multiple supply chain attacks simultaneously
- **Package Version Scanning**: Detects compromised package versions in package.json, package-lock.json, and yarn.lock
- **Malicious Code Detection**: Scans JavaScript files for known attack signatures
- **Payload Artifact Detection**: Identifies malicious files dropped by attacks
- **Workflow Backdoor Detection**: Checks for malicious GitHub Actions workflows
- **Node.js Optimization**: Uses a Node.js helper for faster dependency parsing when available

## Supported Attacks

### CVE-2025-55184 and CVE-2025-55183 - Next.js/React Vulnerabilities (December 2025)
- **Date**: December 11, 2025
- **Packages**: ~190 vulnerable package versions
- **Targets**: Next.js 13.3+, React 19.0.0-19.2.2, and related server component packages
- **CVEs**: 
  - CVE-2025-55183: Source code exposure (Medium severity)
  - CVE-2025-55184: Denial of Service via infinite loop (High severity)
- **Affected**: Next.js applications using App Router with React Server Components
- **Reference**: [Next.js Security Update](https://nextjs.org/blog/security-update-2025-12-11)
- **Fix**: Upgrade to patched versions (Next.js 14.2.35+, 15.0.7+, 15.1.11+, etc. and React 19.0.3+, 19.1.4+, or 19.2.3+)

### Shai-Hulud 2.0 (November 2025)
- **Date**: November 21-23, 2025
- **Packages**: ~700 compromised packages
- **Targets**: posthog-node, @postman/*, @ensdomains/*, @zapier/* and many others
- **Reference**: [Wiz.io Blog](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)

### September 2025 qix- Account Hijacking
- **Date**: September 8-15, 2025
- **Packages**: ~70 compromised packages
- **Targets**: chalk, ansi-styles, color, debug and related packages

## Usage

### Basic Scanning

```bash
# Scan current directory
npm-supply-chain-detector

# Scan specific directory
npm-supply-chain-detector /path/to/project
```

### Attack Selection

```bash
# Check for all attacks (default)
npm-supply-chain-detector -a all

# Check for Shai-Hulud 2.0 only
npm-supply-chain-detector -a shai-hulud-2

# Check for September 2025 qix attack only
npm-supply-chain-detector -a september-2025-qix

# Check for CVE-2025-55184 and CVE-2025-55183 only
npm-supply-chain-detector -a vercel-react-nextjs-2025
```

### Information Commands

```bash
# Show help
npm-supply-chain-detector --help

# List all available attacks
npm-supply-chain-detector --list-attacks
```

## What Gets Scanned

1. **Package Manifests**:
   - `package.json` - all dependency types (dependencies, devDependencies, etc.)
   - `package-lock.json` - locked versions
   - `yarn.lock` - Yarn lockfile

2. **Installed Packages**:
   - `node_modules/` - checks installed package versions
   - Scopes packages (e.g., `@postman/*`, `@ensdomains/*`)

3. **Source Code**:
   - `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs` files
   - Checks for malicious signatures and heavily obfuscated code

4. **Artifacts**:
   - Payload files (e.g., `setup_bun.js`, `cloud.json`)
   - Backdoor workflows (e.g., `.github/workflows/discussion.yaml`)

## Exit Codes

- `0` - No issues found, scan successful
- `1` - Compromised packages or malicious code detected
- `2` - No package manifests found to scan

## Example Output

### Detecting CVE-2025-55184 and CVE-2025-55183

```bash
$ ./npm-supply-chain-detector -a vercel-react-nextjs-2025

🔍 NPM Compromise Checker - 
📂 Scanning directory: /path/to/project
🎯 Attack filter: vercel-react-nextjs-2025
─────────────────────────────────────────────────────────────
[INFO] Loading packages from CVE-2025-55184 and CVE-2025-55183...
[SUCCESS] Loaded 190 compromised packages from CVE-2025-55184 and CVE-2025-55183
[INFO] Checking ./package.json...
[ERROR] COMPROMISED VERSION FOUND: next@15.0.5 in ./package.json
  ↳ Compromised versions tracked: 15.0.0||15.0.1||15.0.2||...
[ERROR] COMPROMISED VERSION FOUND: react@19.0.1 in ./package.json
  ↳ Compromised versions tracked: 19.0.0||19.0.1||19.0.2||...
─────────────────────────────────────────────────────────────
✅ Scan completed in 0s
📊 Packages checked: 3
⚠️  Issues found: 2

🚨 CRITICAL SECURITY ALERT: 2 issues found!
```

### Clean Scan Result

```bash
$ ./npm-supply-chain-detector

✅ Scan completed in 2s
📊 Packages checked: 145
📄 Files scanned: 23
⚠️  Issues found: 0

✅ No compromised packages or malicious code detected!
Your project appears to be safe from known supply chain attacks.
```

## Adding New Attacks

To add a new attack signature:

1. **Update `attacks/attacks.json`**:
   ```json
   {
     "id": "new-attack-2025",
     "name": "New Attack 2025",
     "file": "new-attack-2025.txt",
     "date": "2025-12-01",
     "packages": 100,
     "description": "Description of the attack",
     "signatures": ["malicious-signature-1", "malicious-signature-2"],
     "payloadFiles": ["malicious-file.js"],
     "workflowPaths": [".github/workflows/malicious.yaml"]
   }
   ```

2. **Create `attacks/new-attack-2025.txt`**:
   ```bash
   # New Attack 2025 - Compromised Packages
   # Format: ["package-name"]="version"
   ["compromised-package"]="1.2.3"
   ["another-package"]="4.5.6"
   ```

3. **Update the script's case statement** (if needed) in the `load_compromised_packages()` function to handle the new attack ID.

## Architecture

```
supply-chain-security-detectors/
├── npm-supply-chain-detector    # Main scanner script
├── scripts/
│   └── list-deps.js             # Node.js helper for dependency extraction
├── attacks/
│   ├── attacks.json             # Attack metadata
│   ├── shai-hulud-2.txt         # Shai-Hulud 2.0 package list
│   ├── september-2025-qix.txt   # September 2025 qix package list
│   └── vercel-react-nextjs-2025.txt  # CVE-2025-55184/55183 vulnerable versions
└── README.md                    # This file
```

## Requirements

- **Bash 4.0+**: Required for associative arrays
- **Node.js** (optional): Enables faster dependency parsing
- **Standard Unix tools**: grep, sed, find, cut

## Performance

- **With Node.js**: Uses optimized dependency parser (~2-5 seconds for medium projects)
- **Without Node.js**: Falls back to grep-based parsing (~5-10 seconds for medium projects)
- **Scan depth**: Default maximum depth of 5 subdirectories (configurable)

## Security Notes

- This tool checks for **known** compromised versions and signatures
- A clean scan does **not** guarantee complete security
- Always run `npm audit` for additional vulnerability checks
- Keep the attack definitions up to date
- Review and investigate any warnings about version ranges

## What to Do If Issues Are Found

### For Supply Chain Attacks (Shai-Hulud 2.0, September 2025 qix)

1. **Isolate**: Disconnect affected systems from the network
2. **Rotate credentials**: GitHub, cloud providers, npm, API keys
3. **Clean**: Remove node_modules, clear npm cache, reinstall dependencies
4. **Audit**: Review GitHub Actions, commits, and published packages
5. **Report**: Contact security team and relevant package maintainers

### For CVE-2025-55184 and CVE-2025-55183 (Next.js/React Vulnerabilities)

If the scanner detects vulnerable versions of Next.js or React:

1. **Upgrade Immediately**: Update to the patched versions
   ```bash
   # For Next.js 14.x
   npm install next@14.2.35 react@19.0.3 react-dom@19.0.3
   
   # For Next.js 15.0.x
   npm install next@15.0.7 react@19.0.3 react-dom@19.0.3
   
   # For Next.js 15.1.x
   npm install next@15.1.11 react@19.1.4 react-dom@19.1.4
   
   # Or update to latest
   npm install next@latest react@latest react-dom@latest
   ```

2. **Verify the Fix**: Run the scanner again to confirm
   ```bash
   ./npm-supply-chain-detector -a vercel-react-nextjs-2025
   ```

3. **Test Your Application**: Ensure all functionality still works after the upgrade

4. **Review Logs**: Check for any suspicious activity that may have occurred before patching
   - Review server logs for unusual requests
   - Check for any source code that may have been exposed

5. **Update CI/CD**: Ensure your continuous integration pipelines use the patched versions

6. **Monitor**: Watch for any unusual behavior after the update

**Note**: These CVEs do not involve malicious code injection, so credential rotation is not necessary unless you suspect unauthorized access occurred due to source code exposure.

## References

- [CVE-2025-55184 and CVE-2025-55183 Security Update](https://nextjs.org/blog/security-update-2025-12-11)
- [Shai-Hulud 2.0 Analysis](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [NPM Security Best Practices](https://docs.npmjs.com/packages-and-modules/securing-your-code)
- [GitHub Actions Security](https://docs.github.com/en/actions/security-guides)

## License

Released under the GNU General Public License v3.0.
