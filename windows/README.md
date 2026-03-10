# Windows Pipe Guide

This image runs HCL AppScan on Cloud SAST scanning in Windows container environments.

Use this guide when:
- You run self-hosted Windows Bitbucket runners
- Docker is configured for Windows containers

For full project docs, see `README.md` at repo root.

## Scope and Limitation

- Bitbucket Cloud hosted runners do not support Windows containers.
- This image is intended for self-hosted Windows runners.

## Minimal Self-Hosted Windows Example

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

          # Load exported variables
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

## Required Variables

- `API_KEY_ID`
- `API_KEY_SECRET`
- `APP_ID`
- `TARGET_DIR`

## Common Optional Variables

- `DATACENTER` (`NA`, `EU`, or custom URL)
- `WAIT_FOR_ANALYSIS`
- `FAIL_FOR_NONCOMPLIANCE`
- `FAILURE_THRESHOLD`
- `STATIC_ANALYSIS_ONLY`
- `OPEN_SOURCE_ONLY`
- `SCAN_SPEED`
- `DEBUG`

## Output Files and Variables

The scan writes outputs to `reports/`:
- `scan_env.ps1` for PowerShell environment loading
- `scan_output.json` for programmatic use
- `scan_results.txt` for text-based parsing
- SAST and optional SCA report/summary files

Common exported variables:
- `SAST_SCAN_ID`, `SAST_SCAN_URL`
- `SCA_SCAN_ID`, `SCA_SCAN_URL` (if SCA ran)
- `CRITICAL_ISSUES`, `HIGH_ISSUES`, `MEDIUM_ISSUES`, `LOW_ISSUES`, `INFO_ISSUES`
- `TOTAL_ISSUES`, `SCAN_NAME`, `SCAN_DURATION_SECONDS`

## Alternate: JSON Parsing (No Dot-Sourcing)

```powershell
$r = Get-Content reports\scan_output.json | ConvertFrom-Json
if ([int]$r.CRITICAL_ISSUES -gt 10 -or [int]$r.HIGH_ISSUES -gt 1) {
  Write-Host "Security thresholds exceeded"
  exit 1
}
```

## Troubleshooting

- Confirm Docker is reachable: `docker version`
- Confirm runner path mount: `Resolve-Path $env:BITBUCKET_CLONE_DIR`
- If output files are missing, check container logs and ensure `TARGET_DIR` exists inside mounted path
