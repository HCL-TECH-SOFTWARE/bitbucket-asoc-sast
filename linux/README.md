# Linux Pipe Guide

This image runs the AppScan Bitbucket pipe in Linux environments.

Use this guide for:
- Bitbucket Cloud hosted Linux runners (`pipe:` syntax)
- Self-hosted Linux runners (`docker run`)

For repository-wide documentation, see the root `README.md`.

## Runtime Behavior

- The container downloads SAClientUtil for Linux (`appscan.sh`)
- It packages `TARGET_DIR` into IRX and submits scan(s)
- It runs SAST, SCA, or both depending on flags
- If `WAIT_FOR_ANALYSIS=true` (default), it waits for completion and generates reports
- If `WAIT_FOR_ANALYSIS=false`, it exits after submission with no summary/report export files

## Example: Bitbucket Cloud Hosted Linux

```yaml
- step:
    name: ASoC Scan
    script:
      - pipe: docker://cwtravis1/bitbucket_asoc_sast:linux
        variables:
          API_KEY_ID: $API_KEY_ID
          API_KEY_SECRET: $API_KEY_SECRET
          APP_ID: $APP_ID
          TARGET_DIR: $BITBUCKET_CLONE_DIR/build
          DATACENTER: "NA"
          WAIT_FOR_ANALYSIS: "true"
    artifacts:
      - reports/**
```

Consume results in same step or next step:

```bash
source reports/scan_env.sh
echo "Critical=$CRITICAL_ISSUES High=$HIGH_ISSUES Medium=$MEDIUM_ISSUES"
```

## Example: Self-Hosted Linux with `docker run`

Set `OUTPUT_DIR` to a mounted host path so outputs are directly available on the runner host.

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
          -e TARGET_DIR="$BITBUCKET_CLONE_DIR/build" \
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

## Variables

Required:
- `API_KEY_ID`
- `API_KEY_SECRET`
- `APP_ID`
- `TARGET_DIR`

Frequently used optional:
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
- `OUTPUT_DIR`
- `ALLOW_UNTRUSTED`
- `DEBUG`

## Output Files

When waiting for analysis, outputs are written to `reports/`:
- `scan_results.txt`
- `scan_env.sh`
- `report_paths.txt`
- `{scanName}_sast.html` and `{scanName}_sast.json` (if SAST ran)
- `{scanName}_sca.html` and `{scanName}_sca.json` (if SCA ran)
- `{scanName}_stdout.txt`
- `{scanName}_logs.zip` (if generated)

There is no `scan_output.json` output in the current implementation.

## Enforcing Policy in Pipeline Code

```bash
source reports/scan_env.sh
if [ "$CRITICAL_ISSUES" -gt 0 ] || [ "$HIGH_ISSUES" -gt 0 ]; then
  echo "Security thresholds exceeded"
  exit 1
fi
```
