# Linux AppScan Pipe

[![Docker](https://img.shields.io/badge/docker-linux-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../LICENSE)

> Linux image for HCL AppScan scans in Bitbucket Cloud hosted and self-hosted runners.

For complete documentation, variables, and troubleshooting, see [README.md](../README.md).

---

## Bitbucket Cloud (pipe: syntax)

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

Access results:

```bash
source reports/scan_env.sh
echo "Critical: $CRITICAL_ISSUES, High: $HIGH_ISSUES"
```

---

## Self-Hosted Linux (docker run)

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
          -e WAIT_FOR_ANALYSIS="true" \
          -e OUTPUT_DIR="$BITBUCKET_CLONE_DIR/reports" \
          -v "$BITBUCKET_CLONE_DIR:$BITBUCKET_CLONE_DIR" \
          cwtravis1/bitbucket_asoc_sast:linux
      - source "$BITBUCKET_CLONE_DIR/reports/scan_env.sh"
      - echo "Total issues: $TOTAL_ISSUES"
    artifacts:
      - reports/**
```

**Setup notes:**
- `OUTPUT_DIR` copies reports from container to host path
- Volume mounts (`-v`) allow container to access source code
- Results are available on the host after container exits

---

## Linux-Specific Usage

### Using scan_env.sh for Policy Enforcement

```bash
source reports/scan_env.sh
if [ "$CRITICAL_ISSUES" -gt 0 ]; then
  echo "Critical issues found - failing build"
  exit 1
fi
```

### Available Environment Variables

After sourcing `scan_env.sh`:

```bash
$SAST_SCAN_ID          # Scan identifier
$TOTAL_ISSUES          # Total issues found
$CRITICAL_ISSUES       # Critical severity count
$HIGH_ISSUES           # High severity count
$MEDIUM_ISSUES         # Medium severity count
$LOW_ISSUES            # Low severity count
$INFO_ISSUES           # Informational severity count
```

---

## Linux Troubleshooting

| Issue | Solution |
|-------|----------|
| **Docker not found** | Verify `docker version` works on self-hosted runner |
| **Volume mount fails** | Check path exists: `ls -la $BITBUCKET_CLONE_DIR` |
| **Reports missing** | Ensure `WAIT_FOR_ANALYSIS=true` and check container logs |
| **Permission denied** | Verify Docker daemon can access mounted host paths |
| **API connection error** | Enable `DEBUG=true` and verify `DATACENTER` setting |

---

## Quick Links

- **Full Documentation:** [README.md](../README.md)
- **Configuration Variables:** [README.md#configuration-variables](../README.md#configuration-variables)
- **Windows Guide:** [windows/README.md](../windows/README.md)


