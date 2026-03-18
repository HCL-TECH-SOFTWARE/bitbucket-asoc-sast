# Windows AppScan Pipe

[![Docker](https://img.shields.io/badge/docker-windows-0078d4.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../LICENSE)

> Windows image for HCL AppScan scans on self-hosted runners only.

**⚠️ Windows containers are not supported on Bitbucket Cloud.** Use the [Linux image](../linux/README.md) for cloud-hosted scans.

For complete documentation, variables, and troubleshooting, see [README.md](../README.md).

---

## Setup Requirements

- Self-hosted Bitbucket Pipelines runner on Windows
- Docker configured for **Windows container mode**
- Windows Server 2016 or later recommended

---

## Self-Hosted Windows (docker run)

```yaml
- step:
    name: ASoC SAST Scan
    runs-on:
      - self.hosted
      - windows
    script:
      - $env:DOCKER_HOST = "npipe:////./pipe/docker_engine"
      - $localPath = (Resolve-Path "$env:BITBUCKET_CLONE_DIR").Path
      - New-Item -ItemType Directory -Force -Path "$localPath\reports" | Out-Null
      - docker run --rm `
          -v "$($localPath):C:\src" `
          -v "$($localPath)\reports:C:\reports" `
          -e API_KEY_ID=$env:API_KEY_ID `
          -e API_KEY_SECRET=$env:API_KEY_SECRET `
          -e APP_ID=$env:APP_ID `
          -e TARGET_DIR="C:\src\bin\Release" `
          -e WAIT_FOR_ANALYSIS="true" `
          vndpal/bitbucket_asoc_sast:windows
      - if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    artifacts:
      - reports/*
```

**Windows-specific setup:**
- Set `DOCKER_HOST` to direct Docker to Windows container daemon
- Map source path to `C:\src` inside container
- Map reports to `C:\reports` to copy results to host
- Resolve paths explicitly: `(Resolve-Path $path).Path`

---

## Windows-Specific Usage

### Parsing Results in PowerShell

```powershell
$result = @{}
Get-Content "$env:BITBUCKET_CLONE_DIR\reports\scan_results.txt" | ForEach-Object {
  if ($_ -match '^(?<k>[^=]+)=(?<v>.*)$') {
    $result[$Matches.k] = $Matches.v
  }
}

Write-Host "Total Issues: $($result.TOTAL_ISSUES)"
Write-Host "Critical: $($result.CRITICAL_ISSUES)"
```

### Policy Enforcement in PowerShell

```powershell
$r = Get-Content "$env:BITBUCKET_CLONE_DIR\reports\scan_results.txt" | ConvertFrom-StringData
$critical = [int]$r.CRITICAL_ISSUES
$high = [int]$r.HIGH_ISSUES

if ($critical -gt 10 -or $high -gt 0) {
  Write-Host "Security thresholds exceeded"
  exit 1
}
```

---

## Windows-Specific Configuration

| Variable | Windows Note |
|----------|---|
| `TARGET_DIR` | Use container path like `C:\src\bin\Release` |
| `CONFIG_FILE_PATH` | Use container path like `C:\src\appscan-config.xml` |
| `OUTPUT_DIR` | Not needed; use volume mounts instead |
| `scan_env.sh` | Not available on Windows; parse `scan_results.txt` directly |

---

## Windows Troubleshooting

| Issue | Solution |
|-------|----------|
| **Docker uses Linux containers** | Run: `docker info \| findstr "OSType"` — should show `windows` |
| **Cannot switch to Windows containers** | Right-click Docker icon → Switch to Windows containers → Wait for restart |
| **Volume mount fails** | Verify path exists: `Test-Path C:\your\path` |
| **Permission denied** | Check NTFS permissions and Docker process access |
| **Path resolution errors** | Use explicit resolution: `(Resolve-Path $path).Path` |
| **Reports missing** | Ensure mounted `reports` directory exists and is writable |

### Verify Windows Container Setup

```powershell
# Check if using Windows containers
docker info | findstr "OSType"

# Test volume mount
docker run -it -v "C:\windows:C:\test" windows:latest cmd
# Inside container: dir C:\test
```

---

## Quick Links

- **Full Documentation:** [README.md](../README.md)
- **Configuration Variables:** [README.md#configuration-variables](../README.md#configuration-variables)
- **Linux Guide:** [linux/README.md](../linux/README.md)