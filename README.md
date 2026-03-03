# Bitbucket Pipe for HCL AppScan on Cloud Static Analysis
This repo contains windows/linux docker image that uses python to download the SAClientUtil from HCL AppScan on Cloud and run static analysis against an application in Bitbucket pipelines. The script also will wait for the scan to complete and download a scan summary json file and a scan report. These files are all placed in a directory "reports" so they can be saved as artifacts of the pipeline. See the bitbucket-pipelines.yml example below. Most builds can happen on the linux image, but some projects, like .NET projects must be built on windows.

### Variables

The pipe has 19 variables.

| Variable |  Required | Description |
|---|---|---|
| API_KEY_ID | Required | The HCL AppScan on Cloud API Key ID |
| API_KEY_SECRET | Required | The HCL AppScan on Cloud API Key Secret |
| APP_ID | Required | The application Id of the app in AppScan on Cloud |
| TARGET_DIR | Required | The directory to be scanned. Place scan targets here. |
| CONFIG_FILE_PATH | Optional | Relative path from the repo root to an appscan config xml file. |
| SECRET_SCANNING | Optional | True or False. Enables or disables the secret scanning feature. |
| REPO | Optional | The Repository name. Only really used to make filenames and comments relevant. |
| BUILD_NUM | Optional | The Bitbucket build number. Used to make filenames and comments relevant. |
| SCAN_NAME | Optional | The name of the scan in AppScan on Cloud. Default: "HCL_ASoC_SAST" |
| DATACENTER | Optional | ASoC Datacenter to connect to: "NA" (default) or "EU", or an AppScan 360 url |
| DEBUG | Optional | If true, prints additional debug info to the log. Default: false |
| STATIC_ANALYSIS_ONLY | Optional | If true, only prepare for static analysis during IRX generation. Default: false |
| OPEN_SOURCE_ONLY | Optional | If true, only gather opensource information during IRX generation. Default: false |
| ALLOW_UNTRUSTED | Optional | If true, disables SSL certificate verification for HTTPS requests. Default: false (SSL verification enabled) |
| SCAN_SPEED | Optional | Scan depth/speed: "simple" (quick checks), "balanced" (CI/CD), "deep" (default, thorough analysis), "thorough" (most comprehensive). Default: None (uses AppScan default) |
| PERSONAL_SCAN | Optional | If true, creates a personal scan in AppScan on Cloud. Default: false |
| WAIT_FOR_ANALYSIS | Optional | If true, waits for the scan to complete before finishing. Default: true |
| FAIL_FOR_NONCOMPLIANCE | Optional | If WAIT_FOR_ANALYSIS is true, fail the job if any non-compliant issues are found at or above the FAILURE_THRESHOLD severity. Default: false |
| FAILURE_THRESHOLD | Optional | If FAIL_FOR_NONCOMPLIANCE is enabled, the severity that indicates a failure. Lesser severities will not cause a failure. Valid values: "Critical", "High", "Medium", "Low", "Informational". Default: "Low" |

**Note:** Providing a config file can override other settings like `TARGET_DIR` or `SECRET_SCANNING`.

**Security Note:** Only set `ALLOW_UNTRUSTED` to true in development/testing environments with self-signed certificates. In production, keep SSL verification enabled (default).

### Fail Build on Security Issues

You can configure the pipeline to fail automatically when security issues are found at or above a certain severity threshold. This is useful for enforcing security policies in your CI/CD pipeline.

**How it works:**
- Set `FAIL_FOR_NONCOMPLIANCE` to `"true"` to enable the fail build feature
- Set `FAILURE_THRESHOLD` to the minimum severity that should cause a failure
- The pipeline will fail if any issues are found at or above the threshold

**Threshold Examples:**
| FAILURE_THRESHOLD | Fails on |
|---|---|
| Critical | Critical issues only |
| High | Critical + High issues |
| Medium | Critical + High + Medium issues |
| Low | Critical + High + Medium + Low issues (default) |
| Informational | Any issues |

### Example bitbucket-pipelines.yml step

The following is the bitbucket-pipelines.yml file from my demo repository that makes use of this custom pipe.

```yaml
image: gradle:6.6.0

pipelines:
  default:
    - step:
        name: Build and Test
        caches:
          - gradle
        script:
          - cd "AltoroJ 3.1.1"
          - gradle build
          - ls -la build/libs
        artifacts:
          - AltoroJ 3.1.1/build/libs/altoromutual.war
        after-script:
          - pipe: atlassian/checkstyle-report:0.3.0
    - step:
        name: ASoC SAST Scan
        script:
          # Custom Pipe to run Static Analysis via HCL AppScan on Cloud
          # View README: https://github.com/cwtravis/bitbucket-asoc-sast
          - pipe: docker://cwtravis1/bitbucket_asoc_sast:test
            variables:
              # Required Variables
              API_KEY_ID: $API_KEY_ID
              API_KEY_SECRET: $API_KEY_SECRET
              APP_ID: $APP_ID
              TARGET_DIR: $BITBUCKET_CLONE_DIR/AltoroJ 3.1.1/build/libs
              # Optional Variables
              DATACENTER: "NA"
              SECRET_SCANNING: "true"
              CONFIG_FILE_PATH: "appscan-config.xml"
              REPO: $BITBUCKET_REPO_FULL_NAME
              BUILD_NUM: $BITBUCKET_BUILD_NUMBER
              SCAN_NAME: "ASoC_SAST_BitBucket"
              DEBUG: "true"
              STATIC_ANALYSIS_ONLY: "false"
              OPEN_SOURCE_ONLY: "false"
              SCAN_SPEED: "balanced"
              PERSONAL_SCAN: "false"
              # Fail Build Variables
              WAIT_FOR_ANALYSIS: "true"
              FAIL_FOR_NONCOMPLIANCE: "true"
              FAILURE_THRESHOLD: "High"
        artifacts:
          - reports/*
```

### Using Scan Results in Subsequent Pipeline Steps

The pipe now exports scan results that can be used in subsequent pipeline steps. After the scan completes, the following files are generated in the `reports/` directory:

**Output Files:**
- `scan_results.txt` - Key-value pairs of scan metrics
- `scan_env.sh` - Sourceable shell script with environment variables
- `report_paths.txt` - Paths to generated reports
- `{scanName}.html` - Full HTML security report
- `{scanName}.json` - Complete JSON scan summary

**Exported Variables:**
- `ASOC_SCAN_ID` - The scan ID in AppScan on Cloud
- `ASOC_SCAN_NAME` - Name of the scan
- `ASOC_TOTAL_ISSUES` - Total number of issues found
- `ASOC_CRITICAL_ISSUES` - Number of critical severity issues
- `ASOC_HIGH_ISSUES` - Number of high severity issues
- `ASOC_MEDIUM_ISSUES` - Number of medium severity issues
- `ASOC_LOW_ISSUES` - Number of low severity issues
- `ASOC_INFO_ISSUES` - Number of informational issues
- `ASOC_SCAN_DURATION_SECONDS` - Scan duration in seconds
- `ASOC_SCAN_URL` - Direct URL to view scan results in AppScan on Cloud

#### Example: Using Outputs in Next Steps

```yaml
pipelines:
  default:
    - step:
        name: Build and Test
        script:
          - gradle build
        artifacts:
          - build/libs/*.war
          
    - step:
        name: ASoC SAST Scan
        script:
          - pipe: docker://cwtravis1/bitbucket_asoc_sast:linux
            variables:
              API_KEY_ID: $API_KEY_ID
              API_KEY_SECRET: $API_KEY_SECRET
              APP_ID: $APP_ID
              TARGET_DIR: $BITBUCKET_CLONE_DIR/build/libs
        artifacts:
          - reports/*
          
    - step:
        name: Evaluate Security Results
        script:
          # Source the environment variables from the scan
          - source reports/scan_env.sh
          
          # Display scan results
          - echo "Scan ID: $ASOC_SCAN_ID"
          - echo "Total Issues: $ASOC_TOTAL_ISSUES"
          - echo "Critical Issues: $ASOC_CRITICAL_ISSUES"
          - echo "High Issues: $ASOC_HIGH_ISSUES"
          - echo "View Report: $ASOC_SCAN_URL"
          
          # Fail the pipeline if critical or high issues found
          - |
            if [ "$ASOC_CRITICAL_ISSUES" -gt 0 ]; then
              echo "❌ Build failed: $ASOC_CRITICAL_ISSUES critical security issues found!"
              exit 1
            fi
          - |
            if [ "$ASOC_HIGH_ISSUES" -gt 5 ]; then
              echo "❌ Build failed: Too many high severity issues ($ASOC_HIGH_ISSUES > 5)!"
              exit 1
            fi
          
          # Upload report to external system (example)
          - curl -F "report=@reports/*.html" https://your-report-server.com/upload
          
          # Parse JSON for detailed analysis
          - cat reports/*.json | jq '.LatestExecution'
        artifacts:
          - reports/*
```

#### Example: Conditional Deployment Based on Scan Results

```yaml
    - step:
        name: Deploy to Production
        deployment: production
        script:
          # Only deploy if security scan passed
          - source reports/scan_env.sh
          
          # Check security threshold
          - |
            if [ "$ASOC_CRITICAL_ISSUES" -eq 0 ] && [ "$ASOC_HIGH_ISSUES" -lt 3 ]; then
              echo "✅ Security scan passed. Deploying to production..."
              ./deploy.sh production
            else
              echo "⚠️ Security issues found. Manual review required."
              echo "Critical: $ASOC_CRITICAL_ISSUES, High: $ASOC_HIGH_ISSUES"
              exit 1
            fi
```

### Building The Image

Feel free to use my docker images just as shown in the example pipeline above. You can also use the following commands to build your own images and push to your dockerhub. Replace `<YOUR_DOCKERHUB>` with your dockerhub username.

Build and Push the Linux Image:
```shell
git clone https://github.com/cwtravis/bitbucket-asoc-sast.git
cd bitbucket-asoc-sast
docker build -f linux/Dockerfile -t asoc_sast_linux .
docker tag asoc_sast_linux <YOUR_DOCKERHUB>/bitbucket_asoc_sast:linux
docker push <YOUR_DOCKERHUB>/bitbucket_asoc_sast:linux
```

Once your image is built, you can use them as in the example pipeline above.

```yaml
...
    - step:
        name: ASoC SAST Scan
        script:
          - pipe: docker://<YOUR_DOCKERHUB>/bitbucket_asoc_sast:linux
            variables:
              # Required Variables
              API_KEY_ID: $API_KEY_ID
              API_KEY_SECRET: $API_KEY_SECRET
              APP_ID: $ASOC_APP_ID
              DATACENTER: "NA"
              SECRET_SCANNING: "true"
              CONFIG_FILE_PATH: "appscan-config.xml"
              TARGET_DIR: $BITBUCKET_CLONE_DIR/AltoroJ 3.1.1/build/libs
              # Optional Variables
              REPO: $BITBUCKET_REPO_FULL_NAME
              BUILD_NUM: $BITBUCKET_BUILD_NUMBER
              SCAN_NAME: "HCL_ASoC_SAST"
              DEBUG: "false"
        artifacts:
          - reports/*
```

### Windows image

```yaml
# Bitbucket pipeline for .NET project running on a Windows self-hosted runner
# Includes ASoC SAST scanning via Docker (Windows container mode)

pipelines:
  default:
    - step:
        name: Build and Test (.NET on Windows)
        runs-on:
          - self.hosted
          - windows     # make sure your runner has this tag
        script:
          # Restore .NET dependencies
          - dotnet restore

          # Build project
          - dotnet build --configuration Release

          # Run tests (if applicable)
          - dotnet test --no-build --verbosity normal --logger:"trx;LogFileName=TestResults.trx"

        artifacts:
          - bin/**
          - obj/**
          - TestResults/**
        after-script:
          - echo "✅ Build and tests completed successfully."

    - step:
        name: ASoC SAST Scan (Windows)
        runs-on:
          - self.hosted
          - windows
        script:
          # Tell Docker CLI to use the Windows named pipe
          - $env:DOCKER_HOST = "npipe:////./pipe/docker_engine"

          # Confirm Docker connectivity
          - docker version

          # Get absolute path to the repo directory
          - $localPath = (Resolve-Path "$env:BITBUCKET_CLONE_DIR").Path
          - Write-Host "Resolved localPath = $localPath"

          # Verify that the path actually exists
          - |
            if (-not (Test-Path $localPath)) {
              Write-Host "Path not found: $localPath"
              exit 1
            } else {
              Write-Host "Path exists: $localPath"
            }

          # Run the Windows-based ASoC SAST scan container
          - docker run --rm `
                  -e API_KEY_ID=$env:API_KEY_ID `
                  -e API_KEY_SECRET=$env:API_KEY_SECRET `
                  -e APP_ID=$env:APP_ID `
                  -e TARGET_DIR="C:\src\bin" `
                  -e DATACENTER="NA" `
                  -e SECRET_SCANNING="true" `
                  -e CONFIG_FILE_PATH="C:\src\appscan-config.xml" `
                  -e SCAN_NAME="ASoC_SAST_BitBucket" `
                  -e DEBUG="true" `
                  -e STATIC_ANALYSIS_ONLY="false" `
                  -e OPEN_SOURCE_ONLY="false" `
                  -e ALLOW_UNTRUSTED="false" `
                  -e SCAN_SPEED="balanced" `
                  -e PERSONAL_SCAN="false" `
                  -e BITBUCKET_REPO_SLUG=$env:BITBUCKET_REPO_SLUG `
                  -e BITBUCKET_REPO_FULL_NAME=$env:BITBUCKET_REPO_FULL_NAME `
                  -e BITBUCKET_BRANCH=$env:BITBUCKET_BRANCH `
                  -e BITBUCKET_COMMIT=$env:BITBUCKET_COMMIT `
                  -e BITBUCKET_PROJECT_KEY=$env:BITBUCKET_PROJECT_KEY `
                  -e BITBUCKET_REPO_OWNER=$env:BITBUCKET_REPO_OWNER `
                  -v "${localPath}:C:\src" `
                  vndpal/bitbucket_asoc_sast:windows17

        artifacts:
          - reports/*

```

### Customization and Custom Implementation

This repository is fully customizable. You can modify the files to create your own custom implementation according to your specific needs.

#### Getting Started with Customization

1. **Fork or Clone the Repository**
   ```shell
   git clone https://github.com/cwtravis/bitbucket-asoc-sast.git
   cd bitbucket-asoc-sast
   ```

2. **Modify Python Scripts**
   - Edit `common/ASoC.py` to customize API interactions or error handling (shared by both platforms)
   - Edit `common/RunSASTBase.py` to modify shared scan execution logic, reporting, or workflow
   - Edit `common/constants.py` to change shared constants
   - Edit `linux/pipe/RunSAST.py` or `windows/pipe/RunSAST.py` to modify platform-specific behavior
   - Edit `linux/pipe/platform_config.py` or `windows/pipe/platform_config.py` to change platform-specific constants

3. **Update Docker Configuration**
   - Modify `linux/Dockerfile` or `windows/Dockerfile` to change base images or configure the environment
   - Update `requirements.txt` if you add new Python packages

4. **Customize Pipeline Variables**
   - Edit `linux/pipe.yml` or `windows/pipe.yml` to add new variables or change pipe metadata
   - Adapt the docker run commands and environment variables in your `bitbucket-pipelines.yml` to fit your project's requirements

5. **Build and Push Your Custom Image**

   **Important:** Docker builds must be run from the repository root so that the shared `common/` directory is included in the build context.

   ```shell
   # For Linux (from repo root)
   docker build -f linux/Dockerfile -t <YOUR_DOCKERHUB>/bitbucket_asoc_sast:custom .
   docker push <YOUR_DOCKERHUB>/bitbucket_asoc_sast:custom
   
   # For Windows (from repo root)
   docker build -f windows/Dockerfile -t <YOUR_DOCKERHUB>/bitbucket_asoc_sast:windows-custom .
   docker push <YOUR_DOCKERHUB>/bitbucket_asoc_sast:windows-custom
   ```

6. **Use Your Custom Image in Pipeline**
   Update your `bitbucket-pipelines.yml` to reference your custom image:
   ```yaml
   - pipe: docker://<YOUR_DOCKERHUB>/bitbucket_asoc_sast:custom
   ```

If you have any questions raise an issue in this repo.

