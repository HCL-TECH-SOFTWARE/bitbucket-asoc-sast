# Linux Pipe Guide

This image runs HCL AppScan on Cloud SAST scanning in Linux environments.

Use this guide when:
- You run Bitbucket Cloud hosted Linux runners with `pipe:` syntax
- You run self-hosted Linux runners with `docker run`

For full project docs, see `README.md` at repo root.

## Recommended Usage Modes

## 1. Bitbucket Cloud (hosted Linux)

Use `pipe:` syntax:

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
          WAIT_FOR_ANALYSIS: "true"
    artifacts:
      - reports/**
```

Then evaluate in same step or next step:

```yaml
- source reports/scan_env.sh
- echo "Critical=$CRITICAL_ISSUES High=$HIGH_ISSUES Medium=$MEDIUM_ISSUES"
```

## 2. Self-hosted Linux (`docker run`)

Set `OUTPUT_DIR` to a mounted host path to make output files directly available without `docker cp`.

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
          -e OUTPUT_DIR="$BITBUCKET_CLONE_DIR/reports" \
          -e WAIT_FOR_ANALYSIS="true" \
          -v "$BITBUCKET_CLONE_DIR:$BITBUCKET_CLONE_DIR" \
          cwtravis1/bitbucket_asoc_sast:linux
      - source "$BITBUCKET_CLONE_DIR/reports/scan_env.sh"
      - echo "Critical=$CRITICAL_ISSUES High=$HIGH_ISSUES Medium=$MEDIUM_ISSUES"
    artifacts:
      - reports/**
```

## Important Variables

Required:
- `API_KEY_ID`
- `API_KEY_SECRET`
- `APP_ID`
- `TARGET_DIR`

Common optional:
- `DATACENTER` (`NA`, `EU`, or custom URL)
- `WAIT_FOR_ANALYSIS`
- `FAIL_FOR_NONCOMPLIANCE`
- `FAILURE_THRESHOLD`
- `STATIC_ANALYSIS_ONLY`
- `OPEN_SOURCE_ONLY`
- `SCAN_SPEED`
- `OUTPUT_DIR` (primarily for self-hosted `docker run`)

## Output Files

The pipe writes scan results to `reports/`:
- `scan_env.sh`
- `scan_output.json`
- `scan_results.txt`
- `report_paths.txt`
- `*_sast.html`, `*_sast.json`
- `*_sca.html`, `*_sca.json` (if SCA ran)

## Applying Your Own Security Policy

Example:

```bash
source reports/scan_env.sh
if [ "$CRITICAL_ISSUES" -gt 10 ] || [ "$HIGH_ISSUES" -gt 1 ] || [ "$MEDIUM_ISSUES" -gt 1 ]; then
  echo "Security thresholds exceeded"
  exit 1
fi
```

You can also parse `reports/scan_output.json` if you prefer not to source shell files.
