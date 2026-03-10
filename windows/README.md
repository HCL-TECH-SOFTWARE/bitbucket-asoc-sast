# Windows Pipe Guide

This image runs the AppScan Bitbucket pipe in Windows container environments.

Use this guide when:
- You run self-hosted Windows Bitbucket runners
- Docker is configured for Windows containers

For repository-wide documentation, see the root `README.md`.

## Scope and Limitation

- Bitbucket Cloud hosted runners do not support Windows containers.
- This image is intended for self-hosted Windows runners.

## Runtime Behavior

- The container downloads SAClientUtil for Windows (`appscan.bat`)
- It packages `TARGET_DIR` into IRX and submits scan(s)
- It runs SAST, SCA, or both depending on flags
- If `WAIT_FOR_ANALYSIS=true` (default), it waits for completion and writes reports/results
- If `WAIT_FOR_ANALYSIS=false`, it exits after submission with no summary/report export files

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

          # Parse KEY=VALUE output from scan_results.txt
          - $result = @{}
          - Get-Content "$env:BITBUCKET_CLONE_DIR\reports\scan_results.txt" | ForEach-Object {
              if ($_ -match '^(?<k>[^=]+)=(?<v>.*)$') {
                $result[$Matches.k] = $Matches.v
              }
            }
          - Write-Host "Critical=$($result.CRITICAL_ISSUES) High=$($result.HIGH_ISSUES) Medium=$($result.MEDIUM_ISSUES)"
          - |
            if ([int]$result.CRITICAL_ISSUES -gt 10 -or [int]$result.HIGH_ISSUES -gt 1 -or [int]$result.MEDIUM_ISSUES -gt 1) {
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
- `STATIC_ANALYSIS_ONLY`
- `OPEN_SOURCE_ONLY`
- `SCAN_SPEED`
- `PERSONAL_SCAN`
- `FAIL_FOR_NONCOMPLIANCE`
- `FAILURE_THRESHOLD`
- `CONFIG_FILE_PATH`
- `SECRET_SCANNING`
- `ALLOW_UNTRUSTED`
- `DEBUG`

## Output Files

When waiting for analysis, outputs are written to `reports/`:
- `scan_results.txt`
- `scan_env.sh` (shell export format, useful mainly in Bash environments)
- `report_paths.txt`
- `{scanName}_sast.html` and `{scanName}_sast.json` (if SAST ran)
- `{scanName}_sca.html` and `{scanName}_sca.json` (if SCA ran)
- `{scanName}_stdout.txt`
- `{scanName}_logs.zip` (if generated)

Current implementation does not generate `scan_env.ps1` or `scan_output.json`.

## Troubleshooting

- Confirm Docker is reachable: `docker version`
- Confirm runner mount path resolves: `Resolve-Path $env:BITBUCKET_CLONE_DIR`
- If output files are missing, verify `WAIT_FOR_ANALYSIS=true` and that `TARGET_DIR` exists inside the mounted path
