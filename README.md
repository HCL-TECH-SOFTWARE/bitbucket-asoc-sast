# Bitbucket Pipe for HCL AppScan on Cloud SAST

This repository provides Docker-based Bitbucket pipeline integrations for HCL AppScan on Cloud and AppScan 360° SAST/SCA scanning.

Supported runner models:
- Linux image on Bitbucket Cloud hosted Linux runners (`pipe:` syntax)
- Linux image on self-hosted Linux runners (`docker run`)
- Windows image on self-hosted Windows runners (`docker run` in Windows container mode)

## Repository Layout

- `common/`: shared Python implementation used by Linux and Windows images
- `linux/`: Linux Dockerfile, pipe metadata, and Linux-specific thin wrapper
- `windows/`: Windows Dockerfile, pipe metadata, and Windows-specific thin wrapper
- `appscan-config.xml`: sample AppScan configuration file

## Runtime Flow

The pipe executes these stages:
1. Validate inputs and prepare working folders
2. Download and extract SAClientUtil
3. Generate IRX from `TARGET_DIR`
4. Submit scan(s) (SAST, SCA, or both depending on flags)
5. Optionally wait for completion (`WAIT_FOR_ANALYSIS=true`)
6. Export results and download HTML reports (only when waiting for completion)

If `WAIT_FOR_ANALYSIS=false`, the pipe exits after scan submission and does not generate summary/report files.

## Variables

Schema-defined variables in current code:

| Variable | Required | Default | Description |
|---|---|---|---|
| `API_KEY_ID` | Yes | - | AppScan API key ID |
| `API_KEY_SECRET` | Yes | - | AppScan API key secret |
| `APP_ID` | Yes | - | Target App ID in AppScan |
| `TARGET_DIR` | Yes | `./` | Directory to package and scan |
| `SCAN_NAME` | No | empty | Scan name. If empty, auto-generated from repo/app id + timestamp |
| `DATACENTER` | No | `NA` | `NA`, `EU`, or full custom base URL |
| `CONFIG_FILE_PATH` | No | empty | AppScan config file path (absolute or relative to container working dir) |
| `SECRET_SCANNING` | No | `None` | Enables/disables secrets scan mode when supported by SAClient |
| `STATIC_ANALYSIS_ONLY` | No | `false` | Run SAST only |
| `OPEN_SOURCE_ONLY` | No | `false` | Run SCA only |
| `SCAN_SPEED` | No | empty | Optional SAClient scan speed value |
| `PERSONAL_SCAN` | No | `false` | Create personal scan |
| `WAIT_FOR_ANALYSIS` | No | `true` | Wait for completion and export results |
| `FAIL_FOR_NONCOMPLIANCE` | No | `false` | Fail step when issues at/above threshold exist |
| `FAILURE_THRESHOLD` | No | `Low` | `Critical`, `High`, `Medium`, `Low`, `Informational` |
| `ALLOW_UNTRUSTED` | No | `false` | Disable TLS cert validation for API calls |
| `DEBUG` | No | `false` | Enable debug logging |
| `BUILD_NUM` | No | `0` | Optional build metadata used in report notes |
| `OUTPUT_DIR` | No | empty | Additional location to copy generated output files |
| `REPO` | No | empty | Present in schema (legacy/reserved) |

Notes:
- `STATIC_ANALYSIS_ONLY=true` and `OPEN_SOURCE_ONLY=true` cannot be used together.
- `OUTPUT_DIR` is most useful with self-hosted `docker run` so outputs land on a mounted host path.
- Avoid `ALLOW_UNTRUSTED=true` outside controlled test environments.

## Generated Output

When `WAIT_FOR_ANALYSIS=true`, the pipe writes outputs under `reports/` and optionally mirrors files to `OUTPUT_DIR`.

| File | Description |
|---|---|
| `scan_results.txt` | Flat `KEY=VALUE` summary values |
| `scan_env.sh` | Shell exports (`source reports/scan_env.sh`) |
| `report_paths.txt` | Full paths to generated report/summary files |
| `{scanName}_sast.html` | SAST HTML report (if SAST ran) |
| `{scanName}_sca.html` | SCA HTML report (if SCA ran) |
| `{scanName}_sast.json` | Raw SAST execution JSON (if SAST ran) |
| `{scanName}_sca.json` | Raw SCA execution JSON (if SCA ran) |
| `{scanName}_stdout.txt` | IRX generation stdout capture |
| `{scanName}_logs.zip` | SAClient logs zip when generated |

Common exported values include:
- `SAST_SCAN_ID`, `SAST_SCAN_URL` (if SAST ran)
- `SCA_SCAN_ID`, `SCA_SCAN_URL` (if SCA ran)
- `SCAN_NAME`
- `TOTAL_ISSUES`
- `CRITICAL_ISSUES`, `HIGH_ISSUES`, `MEDIUM_ISSUES`, `LOW_ISSUES`, `INFO_ISSUES`
- `SCAN_DURATION_SECONDS`

## Viewing Reports in Bitbucket Pipelines

When `WAIT_FOR_ANALYSIS=true`, the pipe generates HTML reports, JSON results, and a summary file under `reports/`. To make these accessible in the Bitbucket UI:

1. Declare `artifacts` in the pipeline step that runs the scan (see examples below).
2. After the pipeline runs, open the step in the Bitbucket Pipelines UI and click the **Artifacts** tab.
3. All files matching `reports/**` will be listed and available for download directly from the browser — no need to access the runner or AppScan portal.

Typical files you will find in the Artifacts tab:

| Artifact | Contents |
|---|---|
| `reports/{scanName}_sast.html` | SAST findings as a browsable HTML report |
| `reports/{scanName}_sca.html` | SCA/open-source findings as a browsable HTML report |
| `reports/scan_results.txt` | Key=Value summary (issue counts, scan IDs, URLs) |
| `reports/scan_env.sh` | Shell-sourceable exports for use in downstream steps |
| `reports/report_paths.txt` | Full paths to every generated file |

> **Note:** Artifacts are only produced when `WAIT_FOR_ANALYSIS=true`. If set to `false`, the step exits after submission and no report files are written.

## Bitbucket Cloud Example (Linux Hosted)

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
        name: Enforce Policy
        script:
          - source reports/scan_env.sh
          - echo "Critical=$CRITICAL_ISSUES High=$HIGH_ISSUES Medium=$MEDIUM_ISSUES"
          - |
            if [ "$CRITICAL_ISSUES" -gt 0 ] || [ "$HIGH_ISSUES" -gt 0 ]; then
              echo "Security thresholds exceeded"
              exit 1
            fi
```

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
          cwtravis1/bitbucket_asoc_sast:linux
      - source "$BITBUCKET_CLONE_DIR/reports/scan_env.sh"
      - echo "Total issues: $TOTAL_ISSUES"
    artifacts:
      - reports/**
```

## Self-Hosted Windows Example (`docker run`)

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
                  -e OUTPUT_DIR="C:\src\reports" `
                  -v "${localPath}:C:\src" `
                  cwtravis1/bitbucket_asoc_sast:windows

          - $result = @{}
          - Get-Content "$env:BITBUCKET_CLONE_DIR\reports\scan_results.txt" | ForEach-Object {
              if ($_ -match '^(?<k>[^=]+)=(?<v>.*)$') {
                $result[$Matches.k] = $Matches.v
              }
            }
          - Write-Host "Critical=$($result.CRITICAL_ISSUES) High=$($result.HIGH_ISSUES)"
        artifacts:
          - reports/**
```

> **Windows note:** Because the scan runs inside a Windows container, the `OUTPUT_DIR` variable is used to copy reports from inside the container to the host-mounted volume path (`C:\src\reports` → `$BITBUCKET_CLONE_DIR\reports`). The `artifacts` declaration then picks them up for the Artifacts tab.

## Build and Push Images

Run from repository root. Replace `<YOUR_REGISTRY>` with your Docker Hub username or registry hostname (e.g. `cwtravis1`).

**Linux image** (build on a Linux host or with Linux containers mode):
```bash
docker build -f linux/Dockerfile -t <YOUR_REGISTRY>/bitbucket_asoc_sast:linux .

docker push <YOUR_REGISTRY>/bitbucket_asoc_sast:linux
```

**Windows image** (build on a Windows host with Windows containers mode):
```powershell
docker build -f windows/Dockerfile -t <YOUR_REGISTRY>/bitbucket_asoc_sast:windows .

docker push <YOUR_REGISTRY>/bitbucket_asoc_sast:windows
```

If not already logged in to Docker Hub, authenticate first:
```bash
docker login
```
For other registries (e.g. Azure Container Registry, AWS ECR), use the relevant `docker login` command for that registry before pushing.

## Platform Guides

- Linux details: `linux/README.md`
- Windows details: `windows/README.md`

## Key Implementation Files

- `common/RunSASTBase.py`: shared pipeline orchestration and output export
- `common/ASoC.py`: AppScan API client wrapper
- `linux/pipe/RunSAST.py`: Linux platform overrides
- `windows/pipe/RunSAST.py`: Windows platform overrides
