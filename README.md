# Ector

A command-line tool for detecting and managing known supply chain threats in JavaScript/TypeScript projects.

> **Disclaimer**: This is a highly experimental project provided without any warranty. We are using it as a playground to explore and automate the scanning of npm dependencies for known supply chain threats. Use at your own risk and do not rely on it as your sole security measure.

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Developer Guide](#developer-guide)
- [Project Structure](#project-structure)
- [License](#license)

---

## Quick Start

Get up and running in under a minute:

```bash
# Install from GitHub
curl -sSL https://raw.githubusercontent.com/sparkfabrik/ector-supply-chain-scanner/main/script/install.sh | sh

# Scan your project for known threats
cd /path/to/your/js/ts-project
ector check --all

# If you want to uninstall it
curl -sSL https://raw.githubusercontent.com/sparkfabrik/ector-supply-chain-scanner/main/script/uninstall.sh | sh
```

That's it! Ector will scan your project against all known supply chain threats and report any matches.

### Alternative: Build from Source

```bash
git clone <REPO>
cd ector
cargo build --release
./target/release/ector check --all
```

### Quick Examples

```bash
# List all known threats in the database
ector list

# Check a specific project directory
ector check --all --directory ~/projects/my-app

# Add a new threat to track
ector add --interactive
```

---

## Installation

### Using Cargo (Recommended)

Install directly from GitHub:

```bash
cargo install --git <REPO_URL>
```

This clones, compiles, and installs the latest version to `~/.cargo/bin/`.

To install a specific branch or tag:

```bash
# Install from a specific branch
cargo install --git <REPO_URL> --branch <BRANCH_NAME>

# Install a specific tag/version
cargo install --git <REPO_URL> --tag <TAG_VERSION>
```

### From Source

For development or to make local modifications:

#### Prerequisites

- Rust toolchain (1.70+)
- Cargo

#### Build Steps

```bash
# Clone the repository
git clone <REPO>
cd ector

# Build in release mode
cargo build --release

# The binary will be at target/release/ector
```

#### Install System-Wide

```bash
# Option 1: Using cargo install
cargo install --path .

# Option 2: Manual installation
sudo cp target/release/ector /usr/local/bin/

# Option 3: User-local installation
cp target/release/ector ~/.local/bin/
# Make sure ~/.local/bin is in your PATH
```

#### Verify Installation

```bash
ector help
```

---

## Usage

### Basic Workflow

1. **Check your project** for known supply chain threats:
   ```bash
   cd your-project
   ector check --all
   ```

2. **Review the threats database** to see what Ector detects:
   ```bash
   ector list 
   ```

3. **Add custom threats** specific to your needs:
   ```bash
   ector add --interactive
   ```

### Command Reference

| Command | Purpose |
|---------|---------|
| `add` | Register a new supply chain threat |
| `list` | Display all registered threats |
| `check` | Scan a project for known threats |
| `help` | Show help information |

### Detailed Command Usage

#### `ector check` — Scan for Threats

```bash
# Check current directory against all threats
ector check --all

# Check specific directory
ector check --all --directory /path/to/project

# Check for a specific threat only
ector check --threat "event-stream-compromise"
```

**Options:**
- `--all` — Check all registered threats
- `--name <NAME>` — Check specific threat by name
- `--directory <DIR>` — Project directory to scan (default: current directory)

#### `ector list` — View Registered Threats

```bash
# List all threats (summary view)
ector list

#### `ector add` — Register a New Threat

```bash
# Interactive mode (recommended for new users)
ector add --interactive

# Full command-line specification
ector add \
  --name "Event Stream Compromise" \
  --date "2018-11-26" \
  --description "Malicious code injection in event-stream" \
  --cve "CVE-2018-3728" \
  -p "event-stream@3.3.6" \
  -p "flatmap-stream@0.1.1" \
  -s "eval(Buffer.from(" \
  -f "flatmap-stream/index.js"
```

**Options:**
- `--name <NAME>` — Threat name (required)
- `--date <DATE>` — Discovery date in YYYY-MM-DD format (required)
- `--description <DESC>` — Threat description (required)
- `--cve <CVE>` — CVE identifier (optional)
- `-p, --package <PKG>` — Affected package (repeatable)
- `-s, --signature <SIG>` — Code signature to detect (repeatable)
- `-f, --payload <FILE>` — Payload filename (repeatable)
- `-w, --workflow <PATH>` — Workflow path (repeatable)
- `--interactive` — Interactive mode

---

## Developer Guide

This section covers how to extend Ector with new functionality.

### Setting Up the Development Environment

```bash
# Clone the repository
git clone <REPO>
cd ector

# Install development dependencies
cargo install cargo-insta   # Snapshot testing
cargo install bacon         # Continuous testing (optional)

# Build in debug mode
cargo build

# Run the test suite
cargo test
```

### Architecture Overview

Ector follows a modular architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                      CLI Layer                          │
│                    (src/cli/)                           │
│  Parses arguments, orchestrates commands, formats output│
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│                    Core Layer                           │
│                   (src/core/)                           │
│    Threat models, detection logic, matching rules       │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│              Scanner & Store Layers                     │
│          (src/scanner.rs, src/store/)                   │
│     File system traversal, threat persistence           │
└─────────────────────────────────────────────────────────┘
```

### Testing

#### Running Tests

```bash
# Run all tests
cargo test

# Run specific test suite
cargo test --test cli          # E2E tests
cargo test --lib               # Unit tests only

# Run tests with output
cargo test -- --nocapture
```

#### Snapshot Testing

Ector uses `cargo-insta` for snapshot testing, which captures expected outputs:

```bash
# Run tests and review new/changed snapshots
cargo insta test
cargo insta review

# Accept all snapshot changes (use with caution)
cargo insta accept
```

When you change output formats, update snapshots:

1. Run `cargo insta test`
2. Review each change with `cargo insta review`
3. Accept valid changes, reject regressions

#### Continuous Testing

For rapid development feedback:

```bash
# Watch and run tests on file changes
bacon test

# Watch specific test suite
bacon test -- --test cli

# Watch compilation only
bacon check
```

### Code Quality

#### Formatting

```bash
# Check formatting
cargo fmt --check

# Apply formatting
cargo fmt
```

#### Linting

```bash
# Run clippy
cargo clippy

# Run with all features enabled
cargo clippy --all-features
```

### Contributing Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes with tests
4. Run the full test suite: `cargo test`
5. Check formatting and lints: `cargo fmt --check && cargo clippy`
6. Submit a pull request

---

## License

GNU General Public License v3.0

See [LICENSE](LICENSE) for details.
