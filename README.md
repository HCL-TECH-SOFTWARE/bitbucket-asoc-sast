# Bitbucket Pipe for HCL AppScan

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)]()

> Seamless Docker-based Bitbucket pipeline integrations for HCL AppScan on Cloud and HCL AppScan 360° with SAST & SCA scanning capabilities.

## Overview

This repository provides production-ready Docker images and pipeline configurations for integrating HCL AppScan security scanning into your Bitbucket CI/CD workflows. Supports both static application security testing (SAST) and software composition analysis (SCA) scans.

### Supported Platforms

| Platform | Runner Type | Execution Method |
|----------|-------------|------------------|
| **Linux** | Bitbucket Cloud Hosted | `pipe:` syntax |
| **Linux** | Self-Hosted | `docker run` |
| **Windows** | Self-Hosted (Windows Containers) | `docker run` |

## Table of Contents

- [Quick Start](#quick-start)
- [Repository Layout](#repository-layout)
- [Runtime Flow](#runtime-flow)
- [Configuration Variables](#configuration-variables)
- [Generated Output](#generated-output)
- [Usage Examples](#usage-examples)
- [Viewing Reports](#viewing-reports-in-bitbucket-pipelines)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Repository Layout

- `common/` — Shared Python implementation used by both Linux and Windows images
- `linux/` — Linux Dockerfile, pipe metadata, and Linux-specific wrapper implementation
- `windows/` — Windows Dockerfile, pipe metadata, and Windows-specific wrapper implementation

## Quick Start

### Prerequisites

- Bitbucket repository with pipelines enabled
- HCL AppScan on Cloud credentials (API Key ID and Secret)
- Target Application ID in AppScan
- Docker runtime (self-hosted runners only)

### Basic Linux Example (Bitbucket Cloud)

```yaml
- step:
    name: Security Scan
    script:
      - pipe: docker://cwtravis1/bitbucket_asoc_sast:linux
        variables:
          API_KEY_ID: $API_KEY_ID
          API_KEY_SECRET: $API_KEY_SECRET
          APP_ID: $APP_ID
          TARGET_DIR: $BITBUCKET_CLONE_DIR/build
    artifacts:
      - reports/**
```

For comprehensive setup instructions, see [linux/README.md](linux/README.md) or [windows/README.md](windows/README.md).

---

## Repository Layout

- `common/`: shared Python implementation used by Linux and Windows images
- `linux/`: Linux Dockerfile, pipe metadata, and Linux-specific thin wrapper
- `windows/`: Windows Dockerfile, pipe metadata, and Windows-specific thin wrapper

## Runtime Flow

The pipe executes these stages:
1. Validate inputs and prepare working folders
2. Download and extract SAClientUtil
3. Generate IRX from `TARGET_DIR`
4. Submit scan(s) (SAST, SCA, or both depending on flags)
5. Optionally wait for completion (`WAIT_FOR_ANALYSIS=true`)
6. Export results and download HTML reports (only when waiting for completion)

If `WAIT_FOR_ANALYSIS=false`, the pipe exits after scan submission and does not generate summary/report files.

## Configuration Variables

All pipeline variables are defined in the schema. Below is the complete reference:

### Required Variables

| Variable | Description |
|----------|-------------|
| `API_KEY_ID` | AppScan API key ID for authentication |
| `API_KEY_SECRET` | AppScan API key secret for authentication |
| `APP_ID` | Target Application ID in AppScan |
| `TARGET_DIR` | Directory to package and scan (default: `./`) |

### Optional Variables

| Variable | Default | Description |
|---------|---------|-------------|
| `SCAN_NAME` | auto-generated | Custom scan name. If empty, auto-generated from repo/app id + timestamp |
| `DATACENTER` | `NA` | AppScan datacenter: `NA`, `EU`, or custom base URL |
| `CONFIG_FILE_PATH` | empty | Path to AppScan config file (absolute or relative to container working dir) |
| `SECRET_SCANNING` | `None` | Enables/disables secrets scan mode when supported by SAClient |
| `STATIC_ANALYSIS_ONLY` | `false` | Run SAST only (cannot be combined with `OPEN_SOURCE_ONLY=true`) |
| `OPEN_SOURCE_ONLY` | `false` | Run SCA only (cannot be combined with `STATIC_ANALYSIS_ONLY=true`) |
| `SCAN_SPEED` | empty | Optional SAClient scan speed value |
| `PERSONAL_SCAN` | `false` | Create a personal scan |
| `WAIT_FOR_ANALYSIS` | `true` | Wait for completion and export results |
| `FAIL_FOR_NONCOMPLIANCE` | `false` | Fail pipeline step when issues at/above threshold exist |
| `FAILURE_THRESHOLD` | `Low` | Threshold level: `Critical`, `High`, `Medium`, `Low`, `Informational` |
| `ALLOW_UNTRUSTED` | `false` | Disable TLS certificate validation for API calls (not recommended for production) |
| `DEBUG` | `false` | Enable debug logging for troubleshooting |
| `BUILD_NUM` | `0` | Optional build metadata used in report notes |
| `OUTPUT_DIR` | empty | Additional location to copy generated output files (useful for self-hosted runners) |
| `REPO` | empty | Reserved for legacy compatibility |

**Important Notes:**
- Cannot use `STATIC_ANALYSIS_ONLY=true` and `OPEN_SOURCE_ONLY=true` together
- `OUTPUT_DIR` is particularly useful with self-hosted `docker run` to output reports on a mounted host path
- Avoid using `ALLOW_UNTRUSTED=true` outside controlled test environments

## Generated Output

When `WAIT_FOR_ANALYSIS=true`, the pipe writes outputs under `reports/` directory (and optionally to `OUTPUT_DIR`).

### Output Files

| File | Description |
|------|-------------|
| `scan_results.txt` | Flat `KEY=VALUE` summary values with all metrics |
| `scan_env.sh` | Shell exports for use in downstream steps (`source reports/scan_env.sh`) |
| `report_paths.txt` | Full paths to all generated report and summary files |
| `{scanName}_sast.html` | SAST findings as an interactive HTML report (if SAST ran) |
| `{scanName}_sca.html` | SCA/open-source findings as an interactive HTML report (if SCA ran) |
| `{scanName}_sast.json` | Raw SAST execution JSON with detailed results (if SAST ran) |
| `{scanName}_sca.json` | Raw SCA execution JSON with detailed results (if SCA ran) |
| `{scanName}_stdout.txt` | IRX generation stdout capture for debugging |
| `{scanName}_logs.zip` | SAClient logs archive when generated |

### Exported Output Variables

The following environment variables are set in `scan_env.sh` and `scan_results.txt`:

- **Scan Identifiers:** `SAST_SCAN_ID`, `SCA_SCAN_ID`, `SCAN_NAME`
- **Scan URLs:** `SAST_SCAN_URL`, `SCA_SCAN_URL` (if scans completed)
- **Issue Counts:** `TOTAL_ISSUES`, `CRITICAL_ISSUES`, `HIGH_ISSUES`, `MEDIUM_ISSUES`, `LOW_ISSUES`, `INFO_ISSUES`
- **Performance:** `SCAN_DURATION_SECONDS`

## Viewing Reports in Bitbucket Pipelines

When `WAIT_FOR_ANALYSIS=true`, the pipe generates HTML reports, JSON results, and a summary file under `reports/`. To make these accessible in the Bitbucket UI:

1. Declare `artifacts` in the pipeline step that runs the scan (see examples below)
2. After the pipeline runs, open the step in the Bitbucket Pipelines UI and click the **Artifacts** tab
3. All files matching `reports/**` will be listed and available for download directly from the browser

### Typical Artifacts Available

| Artifact | Contents |
|----------|----------|
| `reports/{scanName}_sast.html` | SAST findings as a browsable HTML report |
| `reports/{scanName}_sca.html` | SCA/open-source findings as a browsable HTML report |
| `reports/scan_results.txt` | Key=Value summary (issue counts, scan IDs, URLs) |
| `reports/scan_env.sh` | Shell-sourceable exports for use in downstream steps |
| `reports/report_paths.txt` | Full paths to every generated file |

> **Note:** Artifacts are only produced when `WAIT_FOR_ANALYSIS=true`. If set to `false`, the step exits after submission and no report files are written.

## Usage Examples

### Bitbucket Cloud Example (Linux Hosted)

```yaml
image: node:20.9.0

pipelines:
  default:
    - step:
        name: Build and Test
        caches:
          - node
        script:
          - echo "Starting Build and Test step"
          - node --version
          - npm --version
          - npm ci
          - npm run build
        artifacts:
          - .next/**
    - step:
        name: ASoC SAST Scan
        oidc: true
        script:
          - pipe: docker://vndpal/bitbucket_asoc_sast:linux-2.0.0
            variables:
              API_KEY_ID: $API_KEY_ID
              API_KEY_SECRET: $API_KEY_SECRET
              APP_ID: $APP_ID
              TARGET_DIR: $BITBUCKET_CLONE_DIR/.next
              DATACENTER: "NA"
              SECRET_SCANNING: "true"
              STATIC_ANALYSIS_ONLY: "true"
              WAIT_FOR_ANALYSIS: "true"
              FAIL_FOR_NONCOMPLIANCE: "true"
              FAILURE_THRESHOLD: "critical"
              BITBUCKET_REPO_SLUG: $BITBUCKET_REPO_SLUG
        artifacts:
          - reports/*
    - step:
        name: Fail Build on Security Violations
        script:
          - |
            source "$BITBUCKET_CLONE_DIR/reports/scan_env.sh"
            echo "Critical=$CRITICAL_ISSUES  High=$HIGH_ISSUES  Medium=$MEDIUM_ISSUES"
            if [ "$CRITICAL_ISSUES" -gt 10 ] || [ "$HIGH_ISSUES" -gt 1 ] || [ "$MEDIUM_ISSUES" -gt 1 ]; then
              echo -e "\033[31mSecurity thresholds exceeded (allowed: Critical<=10, High<=1, Medium<=1). Failing build.\033[0m"
              exit 1
            fi
            echo "Security thresholds passed. Build continues."
```

In the pipeline example above:
- Build step demonstrates building a Node.js application
- Scan step executes SAST using the HCL AppScan pipe
- Final step shows how to enforce security thresholds and fail the build if violated

### Self-Hosted Linux Example (`docker run`)

```yaml
- step:
    name: ASoC Scan
    runs-on:
      - self.hosted
      - linux.shell
    script:
      - mkdir -p "$BITBUCKET_CLONE_DIR/reports"
      - docker run --rm \
          -e API_KEY_ID="$API_KEY_ID" \
          -e API_KEY_SECRET="$API_KEY_SECRET" \
          -e APP_ID="$APP_ID" \
          -e TARGET_DIR="$BITBUCKET_CLONE_DIR/.next" \
          -e DATACENTER="NA" \
          -e WAIT_FOR_ANALYSIS="true" \
          -e OUTPUT_DIR="$BITBUCKET_CLONE_DIR/reports" \
          -v "$BITBUCKET_CLONE_DIR:$BITBUCKET_CLONE_DIR" \
          cwtravis1/bitbucket_asoc_sast:linux-2.0.0
      - source "$BITBUCKET_CLONE_DIR/reports/scan_env.sh"
      - echo "Total issues: $TOTAL_ISSUES"
    artifacts:
      - reports/**
```

In this self-hosted example:
- Prepares a reports directory
- Runs the AppScan pipe in a Docker container with all required environment variables
- Mounts the repository directory so the container can access source code
- Sources the environment file to access scan results in downstream steps

### Self-Hosted Windows Example (`docker run`)

```yaml
pipelines:
  default:
    - step:
        name: Build and Test
        runs-on:
          - self.hosted
          - windows
        script:
          - dotnet restore
          - dotnet build --configuration Release
          - dotnet test --no-build --verbosity normal
        artifacts:
          - bin/Release/net9.0/**

    - step:
        name: ASoC SAST Scan
        runs-on:
          - self.hosted
          - windows
        script:
          - $env:DOCKER_HOST = "npipe:////./pipe/docker_engine"
          - $localPath = (Resolve-Path "$env:BITBUCKET_CLONE_DIR").Path
          - New-Item -ItemType Directory -Force -Path "$localPath\reports" | Out-Null
          - $ErrorActionPreference = "Continue"
          - docker run --rm `
              -v "$($localPath):C:\src" `
              -v "$($localPath)\reports:C:\reports" `
              -e API_KEY_ID=$env:API_KEY_ID `
              -e API_KEY_SECRET=$env:API_KEY_SECRET `
              -e APP_ID=$env:APP_ID `
              -e CONFIG_FILE_PATH="C:\src\appscan-config.xml" `
              -e DATACENTER="https://blmycldtl446131.nonprod.hclpnp.com/" `
              -e ALLOW_UNTRUSTED="true" `
              -e SECRET_SCANNING="true" `
              -e STATIC_ANALYSIS_ONLY="true" `
              -e WAIT_FOR_ANALYSIS="true" `
              -e DEBUG="true" `
              -e BITBUCKET_REPO_SLUG=$env:BITBUCKET_REPO_SLUG `
              vndpal/bitbucket_asoc_sast:windows-after-mend-scan-1
          - $SCAN_EXIT = $LASTEXITCODE
          - $ErrorActionPreference = "Stop"
          - if ($SCAN_EXIT -ne 0) { exit $SCAN_EXIT }
        artifacts:
          - reports/*

    - step:
        name: Fail Build on Security Violations
        runs-on:
          - self.hosted
          - windows
        script:
          - |
            $r = Get-Content "$env:BITBUCKET_CLONE_DIR\reports\scan_results.txt" | ConvertFrom-StringData
            $critical = [int]$r.CRITICAL_ISSUES
            $high     = [int]$r.HIGH_ISSUES
            $medium   = [int]$r.MEDIUM_ISSUES
            Write-Host "Critical=$critical  High=$high  Medium=$medium"
            if ($critical -gt 10 -or $high -gt 0 -or $medium -gt 1) {
              Write-Output "$([char]27)[31mSecurity thresholds exceeded (allowed: Critical<=10, High<=0, Medium<=1). Failing build.$([char]27)[0m"
              exit 1
            }
            Write-Host "Security thresholds passed. Build continues."
```

In the Windows example:
- `DOCKER_HOST` environment variable directs Docker commands to the Windows container daemon
- Volume mounts map host path to container path (`C:\src`), allowing the container to access source code
- Results are copied from container to host-mounted reports directory for artifact collection

---

## Bitbucket Cloud Example (Linux Hosted)

```yaml
image: node:20.9.0

pipelines:
  default:
    - step:
        name: Build and Test
        caches:
          - node
        script:
          - echo "Starting Build and Test step"
          - node --version
          - npm --version
          - npm ci
          - npm run build
        artifacts:
          - .next/**
    - step:
        name: ASoC SAST Scan
        oidc: true
        script:
          - pipe: docker://vndpal/bitbucket_asoc_sast:linux-2.0.0
            variables:
              API_KEY_ID: $API_KEY_ID
              API_KEY_SECRET: $API_KEY_SECRET
              APP_ID: $APP_ID
              TARGET_DIR: $BITBUCKET_CLONE_DIR/.next
              DATACENTER: "NA"
              SECRET_SCANNING: "true"
              STATIC_ANALYSIS_ONLY: "true"
              WAIT_FOR_ANALYSIS: "true"
              FAIL_FOR_NONCOMPLIANCE: "true"
              FAILURE_THRESHOLD: "critical"
              BITBUCKET_REPO_SLUG: $BITBUCKET_REPO_SLUG
        artifacts:
          - reports/*
    - step:
        name: Fail Build on Security Violations
        script:
          - |
            source "$BITBUCKET_CLONE_DIR/reports/scan_env.sh"
            echo "Critical=$CRITICAL_ISSUES  High=$HIGH_ISSUES  Medium=$MEDIUM_ISSUES"
            if [ "$CRITICAL_ISSUES" -gt 10 ] || [ "$HIGH_ISSUES" -gt 1 ] || [ "$MEDIUM_ISSUES" -gt 1 ]; then
              echo -e "\033[31mSecurity thresholds exceeded (allowed: Critical<=10, High<=1, Medium<=1). Failing build.\033[0m"
              exit 1
            fi
            echo "Security thresholds passed. Build continues."
```
> In the pipeline example above, the initial step demonstrates building a Node.js application, followed by executing a SAST scan using the HCL AppScan pipe.

> You can tailor the build step to fit your specific codebase requirements.

> The final step, which is optional, illustrates how to leverage the output variables generated by the pipe. In this case, the pipeline is configured to fail if certain issue thresholds are exceeded; however, you may implement any custom logic based on these output values to suit your workflow.


## Self-Hosted Linux Example (`docker run`)


```yaml
- step:
    name: ASoC Scan
    runs-on:
      - self.hosted
      - linux.shell
    script:
      - mkdir -p "$BITBUCKET_CLONE_DIR/reports"
      - docker run --rm \
          -e API_KEY_ID="$API_KEY_ID" \
          -e API_KEY_SECRET="$API_KEY_SECRET" \
          -e APP_ID="$APP_ID" \
          -e TARGET_DIR="$BITBUCKET_CLONE_DIR/.next" \
          -e DATACENTER="NA" \
          -e WAIT_FOR_ANALYSIS="true" \
          -e OUTPUT_DIR="$BITBUCKET_CLONE_DIR/reports" \
          -v "$BITBUCKET_CLONE_DIR:$BITBUCKET_CLONE_DIR" \
          cwtravis1/bitbucket_asoc_sast:linux-2.0.0
      - source "$BITBUCKET_CLONE_DIR/reports/scan_env.sh"
      - echo "Total issues: $TOTAL_ISSUES"
    artifacts:
      - reports/**
```

> In the self-hosted Linux example above, the scan step prepares a reports directory, then runs the AppScan pipe in a Docker container with all required environment variables and volume mounts.

> The scan results and reports are written to the mounted reports directory, making them available to the Bitbucket pipeline as artifacts.

> After the scan, the script sources the environment file and prints the total issues found. You can further customize this step to add logic based on scan results, similar to the Bitbucket Cloud example.


## Self-Hosted Windows Example (`docker run`)


```yaml
pipelines:
  default:
    - step:
        name: Build and Test
        runs-on:
          - self.hosted
          - windows
        script:
          - dotnet restore
          - dotnet build --configuration Release
          - dotnet test --no-build --verbosity normal
        artifacts:
          - bin/Release/net9.0/**

    - step:
        name: ASoC SAST Scan
        runs-on:
          - self.hosted
          - windows
        script:
          - $env:DOCKER_HOST = "npipe:////./pipe/docker_engine"
          - $localPath = (Resolve-Path "$env:BITBUCKET_CLONE_DIR").Path
          - New-Item -ItemType Directory -Force -Path "$localPath\reports" | Out-Null
          - $ErrorActionPreference = "Continue"
          - docker run --rm `
              -v "$($localPath):C:\src" `
              -v "$($localPath)\reports:C:\reports" `
              -e API_KEY_ID=$env:API_KEY_ID `
              -e API_KEY_SECRET=$env:API_KEY_SECRET `
              -e APP_ID=$env:APP_ID `
              -e CONFIG_FILE_PATH="C:\src\appscan-config.xml" `
              -e DATACENTER="https://blmycldtl446131.nonprod.hclpnp.com/" `
              -e ALLOW_UNTRUSTED="true" `
              -e SECRET_SCANNING="true" `
              -e STATIC_ANALYSIS_ONLY="true" `
              -e WAIT_FOR_ANALYSIS="true" `
              -e DEBUG="true" `
              -e BITBUCKET_REPO_SLUG=$env:BITBUCKET_REPO_SLUG `
              vndpal/bitbucket_asoc_sast:windows-after-mend-scan-1
          - $SCAN_EXIT = $LASTEXITCODE
          - $ErrorActionPreference = "Stop"
          - if ($SCAN_EXIT -ne 0) { exit $SCAN_EXIT }
        artifacts:
          - reports/*

    - step:
        name: Fail Build on Security Violations
        runs-on:
          - self.hosted
          - windows
        script:
          - |
            $r = Get-Content "$env:BITBUCKET_CLONE_DIR\reports\scan_results.txt" | ConvertFrom-StringData
            $critical = [int]$r.CRITICAL_ISSUES
            $high     = [int]$r.HIGH_ISSUES
            $medium   = [int]$r.MEDIUM_ISSUES
            Write-Host "Critical=$critical  High=$high  Medium=$medium"
            if ($critical -gt 10 -or $high -gt 0 -or $medium -gt 1) {
              Write-Output "$([char]27)[31mSecurity thresholds exceeded (allowed: Critical<=10, High<=0, Medium<=1). Failing build.$([char]27)[0m"
              exit 1
            }
            Write-Host "Security thresholds passed. Build continues."
```

> In the self-hosted Windows example above, the scan step sets up the Docker environment for Windows containers, prepares a reports directory, and runs the AppScan pipe in a Windows container with all necessary environment variables and volume mounts.

> The scan results and reports are copied from inside the container to the host-mounted reports directory, making them available as pipeline artifacts.

> After the scan, the script checks the exit code to ensure the scan completed successfully. You can further process the results or add custom logic based on the scan output, similar to the Linux and Bitbucket Cloud examples.

> **Windows note:** Because the scan runs inside a Windows container, the `OUTPUT_DIR` variable is used to copy reports from inside the container to the host-mounted volume path (`C:\src\reports` → `$BITBUCKET_CLONE_DIR\reports`). The `artifacts` declaration then picks them up for the Artifacts tab.

## Building and Publishing Images

### Prerequisites

- Docker installed on your system
- Access to Docker Hub or your preferred container registry
- Docker Hub account (or registry credentials for private registries)

### Build Linux Image

Run from repository root:

```bash
docker build -f linux/Dockerfile -t <YOUR_REGISTRY>/bitbucket_asoc_sast:linux .
```

### Build Windows Image

Run from repository root (requires Windows host with Windows containers mode):

```powershell
docker build -f windows/Dockerfile -t <YOUR_REGISTRY>/bitbucket_asoc_sast:windows .
```

### Push Images to Registry

First, authenticate with Docker (if not already logged in):

```bash
docker login
# For other registries (Azure ACR, AWS ECR, etc.), use the registry-specific login
```

Push images:

```bash
# Linux
docker push <YOUR_REGISTRY>/bitbucket_asoc_sast:linux

# Windows
docker push <YOUR_REGISTRY>/bitbucket_asoc_sast:windows
```

Replace `<YOUR_REGISTRY>` with your Docker Hub username or registry hostname (e.g., `myorg/`, `myregistry.azurecr.io/`, etc.).

---

## Architecture and Implementation

### Key Files

| File | Purpose |
|------|---------|
| `common/RunSASTBase.py` | Shared pipeline orchestration and output export logic |
| `common/ASoC.py` | AppScan API client wrapper for scan submission and polling |
| `linux/pipe/RunSAST.py` | Linux platform-specific implementation overrides |
| `windows/pipe/RunSAST.py` | Windows platform-specific implementation overrides |

### Project Structure

```
├── common/              # Shared implementation
├── linux/               # Linux Docker image and wrapper
│   ├── Dockerfile
│   └── pipe/
│       └── RunSAST.py
├── windows/             # Windows Docker image and wrapper
│   ├── Dockerfile
│   └── pipe/
│       └── RunSAST.py
└── README.md            # This file
```

---

## Platform-Specific Guides

For platform-specific information, see:

- **Linux:** [linux/README.md](linux/README.md) — Bitbucket Cloud and self-hosted Linux runners
- **Windows:** [windows/README.md](windows/README.md) — Self-hosted Windows runners

---

## Troubleshooting

### Common Issues

#### Issue: "Unable to connect to AppScan API"

**Causes:** Invalid API credentials, incorrect datacenter URL, network connectivity issues

**Solutions:**
- Verify `API_KEY_ID` and `API_KEY_SECRET` are correct
- Confirm `DATACENTER` is set correctly (`NA`, `EU`, or the correct custom URL)
- Check network connectivity from the runner
- Enable `DEBUG=true` to see detailed API logs

#### Issue: "Reports directory not created"

**Cause:** `WAIT_FOR_ANALYSIS=false` (default behavior exits after submission)

**Solution:** Set `WAIT_FOR_ANALYSIS=true` to wait for scan completion and generate reports

#### Issue: "Target directory not found during scan"

**Cause:** `TARGET_DIR` path doesn't exist or is incorrectly mounted on self-hosted runners

**Solutions:**
- Verify `TARGET_DIR` exists before running the scan
- For self-hosted runners, ensure volume mount includes the correct host path
- Check that path is specified relative to the container working directory

#### Issue: "Docker authentication failed"

**Cause:** Not authenticated with the container registry

**Solutions:**
- Run `docker login` and provide your Docker Hub credentials
- For private registries, ensure you have credentials configured properly
- Check that Docker daemon is running

### Debug Mode

Enable detailed logging by setting `DEBUG=true`:

```yaml
DEBUG: "true"
```

This will output verbose logs from SAClient and the pipe implementation, helping identify issues.

### Logs and Artifacts

When `WAIT_FOR_ANALYSIS=true`, the pipe generates:

- `scan_env.sh` / `scan_results.txt` — Scan metrics and variables
- `{scanName}_logs.zip` — Complete SAClient execution logs
- `{scanName}_stdout.txt` — IRX generation output

These files are available in the `reports/` directory and can be helpful for debugging.

---

## Contributing

We welcome contributions! To participate:

1. **Report issues:** Open an issue in the repository with detailed information
2. **Propose changes:** Discuss your idea by opening an issue or pull request
3. **Submit code:**
   - Fork the repository
   - Create a feature branch with a descriptive name
   - Make changes with clear, atomic commits
   - Follow existing code style and conventions
   - Test your changes thoroughly
   - Open a pull request with a detailed description

### Development

- Ensure changes are backward compatible when possible
- Update documentation if behavior changes
- Test on both Linux and Windows environments before submitting PR
- Include tests or validation steps in the PR description

---

## Support

- **Documentation:** See [linux/README.md](linux/README.md) and [windows/README.md](windows/README.md) for detailed guides
- **Issues:** [GitHub Issues](https://github.com/your-org/bitbucket-asoc-sast/issues)
- **AppScan Support:** [HCL AppScan Documentation](https://www.hcltechsw.com/appscan)

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


