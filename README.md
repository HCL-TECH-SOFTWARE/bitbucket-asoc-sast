# Bitbucket Pipe for HCL AppScan on Cloud SAST

This repository provides Docker-based Bitbucket pipeline integrations for HCL AppScan on Cloud SAST scanning.

It supports:
- Linux-based usage in Bitbucket Cloud and self-hosted Linux runners
- Windows-based usage in self-hosted Windows runners

The scan flow is:
1. Build your application
2. Run the ASoC scan pipe
3. Read scan output variables from generated files
4. Apply your own security policy logic in pipeline code

## What This Repo Contains

- `common/`: shared Python scan logic for Linux and Windows
- `linux/`: Linux image and Linux docs
- `windows/`: Windows image and Windows docs
- `run-asoc-scan.sh`: local Linux test helper
- `run-asoc-scan.ps1`: local Windows test helper

## Hosted vs Self-Hosted

### Bitbucket Cloud (hosted Linux runners)
Use Bitbucket `pipe:` syntax (recommended).

### Self-hosted Linux runners
Use `docker run` and set `OUTPUT_DIR` so output files are copied to your mounted host path.

### Self-hosted Windows runners
Use `docker run` in Windows container mode and load `reports\\scan_env.ps1`.

## Variables

The pipe supports 20 variables.

| Variable | Required | Description |
|---|---|---|
| `API_KEY_ID` | Yes | HCL AppScan on Cloud API key ID |
| `API_KEY_SECRET` | Yes | HCL AppScan on Cloud API key secret |
| `APP_ID` | Yes | Target application ID in AppScan |
| `TARGET_DIR` | Yes | Directory to scan |
| `DATACENTER` | No | `NA` (default), `EU`, or custom AppScan 360 URL |
| `SCAN_NAME` | No | Scan name in AppScan. If empty, auto-derived |
| `CONFIG_FILE_PATH` | No | Path to appscan config file |
| `SECRET_SCANNING` | No | `true` or `false` |
| `STATIC_ANALYSIS_ONLY` | No | `true` or `false` |
| `OPEN_SOURCE_ONLY` | No | `true` or `false` |
| `SCAN_SPEED` | No | `simple`, `balanced`, `deep`, `thorough` |
| `PERSONAL_SCAN` | No | `true` or `false` |
| `WAIT_FOR_ANALYSIS` | No | Wait for completion before exit. Default: `true` |
| `FAIL_FOR_NONCOMPLIANCE` | No | Fail the step based on severity threshold |
| `FAILURE_THRESHOLD` | No | `Critical`, `High`, `Medium`, `Low`, `Informational` |
| `ALLOW_UNTRUSTED` | No | Disable TLS certificate validation |
| `DEBUG` | No | Enable debug logging |
| `REPO` | No | Optional repo name metadata |
| `BUILD_NUM` | No | Optional build number metadata |
| `OUTPUT_DIR` | No | Additional output location (mainly for self-hosted `docker run`) |

Notes:
- `OUTPUT_DIR` is optional. It is most useful in self-hosted Docker usage.
- If `CONFIG_FILE_PATH` is provided, it may override other scan settings.
- Do not use `ALLOW_UNTRUSTED=true` in production.

## Output Files and Variables

After scan completion, the pipe writes output into `reports/` and exports variables in multiple formats:

| File | Format | Purpose |
|---|---|---|
| `scan_results.txt` | `KEY=VALUE` | Easy cross-platform parsing |
| `scan_output.json` | JSON | Programmatic parsing |
| `scan_env.sh` | bash exports | Linux shell `source` support |
| `scan_env.ps1` | PowerShell | Windows `.` dot-source support |
| `report_paths.txt` | `KEY=VALUE` | Paths to generated reports |
| `{scanName}_sast.html` | HTML | SAST report |
| `{scanName}_sca.html` | HTML | SCA report (if SCA ran) |
| `{scanName}_sast.json` | JSON | SAST execution summary |
| `{scanName}_sca.json` | JSON | SCA execution summary (if SCA ran) |

Common exported variables:
- `SAST_SCAN_ID`, `SAST_SCAN_URL`
- `SCA_SCAN_ID`, `SCA_SCAN_URL` (when SCA runs)
- `SCAN_NAME`
- `TOTAL_ISSUES`
- `CRITICAL_ISSUES`, `HIGH_ISSUES`, `MEDIUM_ISSUES`, `LOW_ISSUES`, `INFO_ISSUES`
- `SCAN_DURATION_SECONDS`
- `CREATED_AT` (when available)

## Quick Start: Bitbucket Cloud (Linux Hosted)

```yaml
image: node:20.9.0

pipelines:
  default:
    - step:
        name: Build
        script:
          - npm ci
          - npm run build
        artifacts:
          - .next/**

    - step:
        name: ASoC Scan
        script:
          - pipe: docker://cwtravis1/bitbucket_asoc_sast:linux
            variables:
              API_KEY_ID: $API_KEY_ID
              API_KEY_SECRET: $API_KEY_SECRET
              APP_ID: $APP_ID
              TARGET_DIR: $BITBUCKET_CLONE_DIR/.next
              DATACENTER: "NA"
              WAIT_FOR_ANALYSIS: "true"
        artifacts:
          - reports/**

    - step:
        name: Evaluate Results
        script:
          - source reports/scan_env.sh
          - echo "Critical=$CRITICAL_ISSUES High=$HIGH_ISSUES Medium=$MEDIUM_ISSUES"
          - |
            if [ "$CRITICAL_ISSUES" -gt 10 ] || [ "$HIGH_ISSUES" -gt 1 ] || [ "$MEDIUM_ISSUES" -gt 1 ]; then
              echo "Security thresholds exceeded"
              exit 1
            fi
          - echo "Security thresholds passed"
```

## Quick Start: Self-Hosted Linux (`docker run`)

Use `OUTPUT_DIR` to avoid container-copy plumbing.

```yaml
image: node:20.9.0

pipelines:
  default:
    - step:
        name: Build
        runs-on:
          - self.hosted
          - linux.shell
        script:
          - npm ci
          - npm run build
        artifacts:
          - .next/**

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
              -e OUTPUT_DIR="$BITBUCKET_CLONE_DIR/reports" \
              -e DATACENTER="NA" \
              -e WAIT_FOR_ANALYSIS="true" \
              -v "$BITBUCKET_CLONE_DIR:$BITBUCKET_CLONE_DIR" \
              cwtravis1/bitbucket_asoc_sast:linux
          - source "$BITBUCKET_CLONE_DIR/reports/scan_env.sh"
          - echo "Critical=$CRITICAL_ISSUES High=$HIGH_ISSUES Medium=$MEDIUM_ISSUES"
          - |
            if [ "$CRITICAL_ISSUES" -gt 10 ] || [ "$HIGH_ISSUES" -gt 1 ] || [ "$MEDIUM_ISSUES" -gt 1 ]; then
              echo "Security thresholds exceeded"
              exit 1
            fi
        artifacts:
          - reports/**
```

## Quick Start: Self-Hosted Windows

```yaml
pipelines:
  default:
    - step:
        name: ASoC Scan (Windows)
        runs-on:
          - self.hosted
          - windows
        script:
          - $env:DOCKER_HOST = "npipe:////./pipe/docker_engine"
          - $localPath = (Resolve-Path "$env:BITBUCKET_CLONE_DIR").Path
          - docker run --rm `
                  -e API_KEY_ID=$env:API_KEY_ID `
                  -e API_KEY_SECRET=$env:API_KEY_SECRET `
                  -e APP_ID=$env:APP_ID `
                  -e TARGET_DIR="C:\src\bin" `
                  -e WAIT_FOR_ANALYSIS="true" `
                  -v "${localPath}:C:\src" `
                  cwtravis1/bitbucket_asoc_sast:windows
          - . reports\scan_env.ps1
          - Write-Host "Critical=$env:CRITICAL_ISSUES High=$env:HIGH_ISSUES Medium=$env:MEDIUM_ISSUES"
          - |
            if ([int]$env:CRITICAL_ISSUES -gt 10 -or [int]$env:HIGH_ISSUES -gt 1 -or [int]$env:MEDIUM_ISSUES -gt 1) {
              Write-Host "Security thresholds exceeded"
              exit 1
            }
        artifacts:
          - reports/**
```

## Ways to Consume Results

You can consume variables in 3 patterns:
- Same `script:` block, immediately after `pipe:` or `docker run`
- `after-script:` block
- Separate step (requires `reports/**` artifacts)

If you do not want shell sourcing, parse `reports/scan_output.json` instead.

## Build and Push Your Own Image

Run from repository root.

```bash
# Linux image
docker build -f linux/Dockerfile -t <YOUR_DOCKERHUB>/bitbucket_asoc_sast:linux .
docker push <YOUR_DOCKERHUB>/bitbucket_asoc_sast:linux

# Windows image
docker build -f windows/Dockerfile -t <YOUR_DOCKERHUB>/bitbucket_asoc_sast:windows .
docker push <YOUR_DOCKERHUB>/bitbucket_asoc_sast:windows
```

Use custom image:

```yaml
- pipe: docker://<YOUR_DOCKERHUB>/bitbucket_asoc_sast:linux
```

## Platform-Specific Guides

- Linux details: `linux/README.md`
- Windows details: `windows/README.md`

## Contributing and Customization

Common customization entry points:
- `common/ASoC.py`: AppScan API handling
- `common/RunSASTBase.py`: shared scan orchestration and output export
- `linux/pipe/RunSAST.py`: Linux-specific behavior
- `windows/pipe/RunSAST.py`: Windows-specific behavior
- `linux/pipe/platform_config.py` and `windows/pipe/platform_config.py`: platform constants

If you find issues or want enhancements, open an issue or PR.
