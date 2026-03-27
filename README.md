# Bitbucket pipe for HCL AppScan

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)]()

> Seamless Docker-based Bitbucket pipeline integrations for HCL AppScan on Cloud and HCL AppScan 360° with SAST and SCA scanning capabilities.

## Overview

This repository provides production-ready Docker images and pipeline configurations for integrating HCL AppScan security scanning into your Bitbucket CI/CD workflows. It supports both static application security testing (SAST) and software composition analysis (SCA) scans.

### Supported platforms

| Platform | Runner type | Execution method |
|----------|-------------|------------------|
| **Linux** | Bitbucket Cloud hosted | `pipe:` syntax |
| **Linux** | Self-hosted | `docker run` |
| **Windows** | Self-hosted (Windows containers) | `docker run` |

## Table of contents

- [Quick start](#quick-start)
- [Repository layout](#repository-layout)
- [Runtime flow](#runtime-flow)
- [Configuration variables](#configuration-variables)
- [Generated output](#generated-output)
- [Usage examples](#usage-examples)
- [Viewing rports](#viewing-reports-in-bitbucket-pipelines)
- [Troubleshooting](#troubleshooting)
- [License](#license)



## Quick Start

### Prerequisites

- Bitbucket repository with pipelines enabled
- HCL AppScan on Cloud credentials (API key ID and secret)
- Target Application ID in AppScan
- Docker runtime (self-hosted runners only)

### Basic Linux example (Bitbucket Cloud)

```yaml
- step:
    name: Security Scan
    script:
      - pipe: docker://hclcr.io/appscan/bitbucket:linux-2.0.0
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

## Repository layout

- `common/`: Shared Python implementation used by Linux and Windows images.
- `linux/`: Linux Dockerfile, pipe metadata, and Linux-specific thin wrapper.
- `windows/`: Windows Dockerfile, pipe metadata, and Windows-specific thin wrapper.

## Runtime flow

The pipe executes these stages:
1. Validate inputs and prepare working folders.
2. Download and extract SAClientUtil.
3. Generate IRX from `TARGET_DIR`.
4. Submit scan(s) (SAST, SCA, or both, depending on flags).
5. Optionally wait for completion (`WAIT_FOR_ANALYSIS=true`).
6. Export results and download HTML reports (only when waiting for completion).

If `WAIT_FOR_ANALYSIS=false`, the pipe exits after scan submission and doesn't generate summary or report files.

## Configuration variables

All pipeline variables are defined in the schema. The following tables provide the complete reference:

### Required variables

| Variable | Description |
|----------|-------------|
| `API_KEY_ID` | AppScan API key ID for authentication |
| `API_KEY_SECRET` | AppScan API key secret for authentication |
| `APP_ID` | Target Application ID in AppScan |
| `TARGET_DIR` | Directory to package and scan (default: `./`) |

### Optional variables

| Variable | Default | Description |
|---------|---------|-------------|
| `SCAN_NAME` | auto-generated | Custom scan name. If empty, auto-generated from repo, app ID, and timestamp |
| `DATACENTER` | `NA` | AppScan datacenter: `NA`, `EU`, or custom base URL |
| `CONFIG_FILE_PATH` | empty | Path to AppScan config file (absolute or relative to container working directory) |
| `SECRET_SCANNING` | `None` | Enables or disables secrets scan mode when supported by SAClient |
| `STATIC_ANALYSIS_ONLY` | `false` | Run SAST only (you can’t combine with `OPEN_SOURCE_ONLY=true`) |
| `OPEN_SOURCE_ONLY` | `false` | Run SCA only (you can't combine this with `STATIC_ANALYSIS_ONLY=true`) |
| `SCAN_SPEED` | empty | Optional SAClient scan speed value |
| `PERSONAL_SCAN` | `false` | Create a personal scan |
| `WAIT_FOR_ANALYSIS` | `true` | Wait for completion and export results |
| `FAIL_FOR_NONCOMPLIANCE` | `false` | Fail pipeline step when issues at or above threshold exist |
| `FAILURE_THRESHOLD` | `Low` | Threshold level: `Critical`, `High`, `Medium`, `Low`, or `Informational` |
| `ALLOW_UNTRUSTED` | `false` | Disable TLS certificate validation for API calls (not recommended for production) |
| `DEBUG` | `false` | Enable debug logging for troubleshooting |
| `BUILD_NUM` | `0` | Optional build metadata used in report notes |
| `OUTPUT_DIR` | empty | Additional location to copy generated output files (useful for self-hosted runners) |
| `REPO` | empty | Reserved for legacy compatibility |

**Important notes:**
- You can't use `STATIC_ANALYSIS_ONLY=true` and `OPEN_SOURCE_ONLY=true` together
- `OUTPUT_DIR` is particularly useful with self-hosted `docker run` to output reports to a mounted host path
- Avoid using `ALLOW_UNTRUSTED=true` outside controlled test environments

## Generated output

When `WAIT_FOR_ANALYSIS=true`, the pipe writes outputs to the `reports/` directory (and optionally to `OUTPUT_DIR`).

### Output Files

| File | Description |
|------|-------------|
| `scan_results.txt` | Flat `KEY=VALUE` summary values with all metrics |
| `scan_env.sh` | Shell exports for use in downstream steps (`source reports/scan_env.sh`) |
| `report_paths.txt` | Full paths to all generated reports and summary files |
| `{scanName}_sast.html` | SAST findings as an interactive HTML report (if SAST ran) |
| `{scanName}_sca.html` | SCA/open-source findings as an interactive HTML report (if SCA ran) |
| `{scanName}_sast.json` | Raw SAST execution JSON with detailed results (if SAST ran) |
| `{scanName}_sca.json` | Raw SCA execution JSON with detailed results (if SCA ran) |
| `{scanName}_stdout.txt` | IRX generation stdout capture for debugging |
| `{scanName}_logs.zip` | SAClient logs archive when generated |

### Exported output variables

The following environment variables are set in `scan_env.sh` and `scan_results.txt`:

- **Scan identifiers:** `SAST_SCAN_ID`, `SCA_SCAN_ID`, and `SCAN_NAME`
- **Scan URLs:** `SAST_SCAN_URL`, and `SCA_SCAN_URL` (if scans completed)
- **Issue counts:** `TOTAL_ISSUES`, `CRITICAL_ISSUES`, `HIGH_ISSUES`, `MEDIUM_ISSUES`, `LOW_ISSUES`, and `INFO_ISSUES`
- **Performance:** `SCAN_DURATION_SECONDS`

## Viewing reports in Bitbucket Pipelines

When `WAIT_FOR_ANALYSIS=true`, the pipe generates HTML reports, JSON results, and a summary file under `reports/`. To make these accessible in the Bitbucket UI:

1. Declare `artifacts` in the pipeline step that runs the scan (see examples below).
2. After the pipeline runs, open the step in the Bitbucket Pipelines UI and click the **Artifacts** tab.
3. All files matching `reports/**` will be listed and available for download directly from the browser.

### Typical artifacts available

| Artifact | Contents |
|----------|----------|
| `reports/{scanName}_sast.html` | SAST findings as a browsable HTML report |
| `reports/{scanName}_sca.html` | SCA and open-source findings as a browsable HTML report |
| `reports/scan_results.txt` | Key=Value summary (issue counts, scan IDs, URLs) |
| `reports/scan_env.sh` | Shell-sourceable exports for use in downstream steps |
| `reports/report_paths.txt` | Full paths to every generated file |

> **Note:** Artifacts are only produced when `WAIT_FOR_ANALYSIS=true`. If set to `false`, the step exits after submission, and no report files are written.

## Usage examples

### Bitbucket Cloud example (Linux hosted)

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
          - pipe: docker://hclcr.io/appscan/bitbucket:linux-2.0.0
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

In the preceding pipeline example:
- The build step demonstrates building a Node.js application
- The scan step executes SAST using the HCL AppScan pipe
- The final step shows how to enforce security thresholds and fail the build if violated

### Self-hosted Linux example (`docker run`)

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
          hclcr.io/appscan/bitbucket:linux-2.0.0
      - source "$BITBUCKET_CLONE_DIR/reports/scan_env.sh"
      - echo "Total issues: $TOTAL_ISSUES"
    artifacts:
      - reports/**
```

In this self-hosted example, the step:
- Prepares a reports directory
- Runs the AppScan pipe in a Docker container with all required environment variables
- Mounts the repository directory so the container can access source code
- Source the environment file to access scan results in downstream steps

### Self-hosted Windows example (`docker run`)

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
              hclcr.io/appscan/bitbucket:windows-2.0.0
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
-  The `DOCKER_HOST` environment variable directs Docker commands to the Windows container daemon.
- Volume mounts map host path to container path (`C:\src`), allowing the container to access the source code.
- Results are copied from inside the container to the host-mounted reports directory for artifact collection.

---

## Bitbucket Cloud example (Linux hosted)

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
          - pipe: docker://hclcr.io/appscan/bitbucket:linux-2.0.0
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
> In the preceding pipeline example, the initial step demonstrates building a Node.js application, followed by executing a SAST scan using the HCL AppScan pipe.

> Customize the build step to fit your codebase requirements.

> The optional final step illustrates how to use the output variables generated by the pipe. In this example, the pipeline is configured to fail if certain issue thresholds are exceeded. Implement custom logic based on these output values to suit your workflow.


## Self-hosted Linux example (`docker run`)


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
          hclcr.io/appscan/bitbucket:linux-2.0.0
      - source "$BITBUCKET_CLONE_DIR/reports/scan_env.sh"
      - echo "Total issues: $TOTAL_ISSUES"
    artifacts:
      - reports/**
```

> In the preceding self-hosted Linux example, the scan step prepares a reports directory, then runs the AppScan pipe in a Docker container with all required environment variables and volume mounts.

> The scan results and reports are written to the mounted reports directory, making them available to the Bitbucket pipeline as artifacts.

> After the scan, the script sources the environment file and prints the total issues found. Customize this step further to add logic based on scan results, similar to the Bitbucket Cloud example.


## Self-hosted Windows example (`docker run`)


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
              hclcr.io/appscan/bitbucket:windows-2.0.0
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

> In the preceding self-hosted Windows example, the scan step sets up the Docker environment for Windows containers, prepares a reports directory, and runs the AppScan pipe in a Windows container with all necessary environment variables and volume mounts.

> The scan results and reports are copied from inside the container to the host-mounted reports directory, making them available as pipeline artifacts.

> After the scan, the script checks the exit code to ensure the scan completed successfully. Process the results further or add custom logic based on the scan output, similar to the Linux and Bitbucket Cloud examples.

> **Windows note:** Because the scan runs inside a Windows container, the `OUTPUT_DIR` variable is used to copy reports from inside the container to the host-mounted volume path (`C:\src\reports` → `$BITBUCKET_CLONE_DIR\reports`). The `artifacts` declaration then picks them up for the Artifacts tab.

## Building and publishing Images

### Prerequisites

- Docker is installed on your system
- Access to Docker Hub or your preferred container registry
- Docker Hub account (or registry credentials for private registries)

### Build the Linux image

Run this command from the repository root:

```bash
docker build -f linux/Dockerfile -t <YOUR_REGISTRY>/bitbucket_asoc_sast:linux .
```

### Build the Windows image

Run this command from the repository root (requires a Windows host with Windows containers mode):

```powershell
docker build -f windows/Dockerfile -t <YOUR_REGISTRY>/bitbucket_asoc_sast:windows .
```

### Push images to a registry

First, authenticate with Docker if you aren't already signed in:

```bash
docker login
# For other registries (Azure ACR, AWS ECR, etc.), use the registry-specific login
```

Push the images:

```bash
# Linux
docker push <YOUR_REGISTRY>/bitbucket_asoc_sast:linux

# Windows
docker push <YOUR_REGISTRY>/bitbucket_asoc_sast:windows
```

Replace `<YOUR_REGISTRY>` with your Docker Hub username or registry hostname (for example, `myorg/`, `myregistry.azurecr.io/`, etc.).

---

## Architecture and implementation

### Key files

| File | Purpose |
|------|---------|
| `common/RunSASTBase.py` | Shared pipeline orchestration and output export logic |
| `common/ASoC.py` | AppScan API client wrapper for scan submission and polling |
| `linux/pipe/RunSAST.py` | Linux platform-specific implementation overrides |
| `windows/pipe/RunSAST.py` | Windows platform-specific implementation overrides |

### Project structure

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

## Platform-specific Guides

For platform-specific information, see:

- **Linux:** [linux/README.md](linux/README.md) — Bitbucket Cloud and self-hosted Linux runners
- **Windows:** [windows/README.md](windows/README.md) — Self-hosted Windows runners

---

## Troubleshooting

### Common issues

#### Issue: "Unable to connect to AppScan API"

**Causes:** Invalid API credentials, incorrect datacenter URL, network connectivity issues

**Solutions:**
- Verify `API_KEY_ID` and `API_KEY_SECRET` are correct
- Confirm `DATACENTER` is set correctly (`NA`, `EU`, or the correct custom URL)
- Check network connectivity from the runner
- Enable `DEBUG=true` to see detailed API logs

#### Issue: "Reports directory not created"

**Cause:** `WAIT_FOR_ANALYSIS=false` (the default behavior exits after submission)

**Solution:** Set `WAIT_FOR_ANALYSIS=true` to wait for scan completion and generate reports

#### Issue: "Target directory not found during scan"

**Cause:** `TARGET_DIR` path doesn't exist or is mounted incorrectly on self-hosted runners

**Solutions:**
- Verify `TARGET_DIR` exists before running the scan
- For self-hosted runners, ensure that the volume mount includes the correct host path
- Check that the path is specified relative to the container working directory

#### Issue: "Docker authentication failed"

**Cause:** You aren't authenticated with the container registry

**Solutions:**
- Run `docker login` and provide your Docker Hub credentials
- For private registries, ensure that your credentials are configured correctly
- Check that the Docker daemon is running

### Debug mode

Enable detailed logging by setting `DEBUG=true`:

```yaml
DEBUG: "true"
```

This will output verbose logs from SAClient and the pipe implementation to help identify issues.

### Logs and artifacts

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
- Test on both Linux and Windows environments before submitting a PR
- Include tests or validation steps in the PR description

---

## Support

- **Documentation:** See [linux/README.md](linux/README.md) and [windows/README.md](windows/README.md) for detailed guides
- **Issues:** [GitHub Issues](https://github.com/your-org/bitbucket-asoc-sast/issues)
- **AppScan Support:** [HCL AppScan Documentation](https://www.hcltechsw.com/appscan)

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.