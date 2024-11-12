# Bitbucket Pipe for HCL AppScan on Cloud Static Analysis
This is a linux docker image that uses python to download the SAClientUtil from HCL AppScan on Cloud and run static analysis against an application in Bitbucket pipelines. The script also will wait for the scan to complete and download a scan summary json file and a scan report. These files are all placed in a directory "reports" so they can be saved as artifacts of the pipeline. See the bitbucket-pipelines.yml example below.

### Variables

The pipe has 13 variables.

| Variable |  Required | Description |
|---|---|---|
| API_KEY_ID | Required | The HCL AppScan on Cloud API Key ID |
| API_KEY_SECRET | Required | The HCL AppScan on Cloud API Key Secret |
| APP_ID | Required | The application Id of the app in AppScan on Cloud |
| TARGET_DIR | Required | The directory to be scanned. Place scan targets here. |
| CONFIG_FILE_PATH | Optional | Relative path from the repo root to an appscan config xml file. |
| SECRET_SCANNING | Optional | True or False (default). Enables the secret scanning feature of ASoC SAST. |
| BUILD_NUM | Optional | The Bitbucket build number. Used to make filenames and comments relevant. |
| REPO | Optional | The Repository name. Only really used to make filenames and comments relevant. |
| SCAN_NAME | Optional | The name of the scan in AppScan on Cloud |
| DATACENTER | Optional | ASoC Datacenter to connect to: "NA" (default) or "EU" |
| DEBUG | Optional | If true, prints additional debug info to the log. |
| STATIC_ANALYSIS_ONLY | Optional | If true, only prepare for static analysis during IRX generation. |
| OPEN_SOURCE_ONLY | Optional | If true, only gather opensource information during IRX generation. |

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
          - echo "$BITBUCKET_CLONE_DIR"
          - cd "AltoroJ 3.1.1"
          - pwd
          - ls -la
          - gradle build
        artifacts:
          - AltoroJ 3.1.1/build/libs/altoromutual.war
        after-script:
          - pipe: atlassian/checkstyle-report:0.2.0
    - step:
        name: ASoC SAST Scan
        script:
          # Custom Pipe to run Static Analysis via HCL AppScan on Cloud
          # View README: https://github.com/cwtravis/bitbucket-asoc-sast-linux
          - pipe: docker://cwtravis1/bitbucket_asoc_sast:1.0.1
            variables:
              # Required Variables
              API_KEY_ID: $API_KEY_ID
              API_KEY_SECRET: $API_KEY_SECRET
              APP_ID: a4696e4a-a3c4-449b-b5e3-327fe05c02c3
              TARGET_DIR: $BITBUCKET_CLONE_DIR/AltoroJ 3.1.1/build/libs
              # Optional Variables
              REPO: $BITBUCKET_REPO_FULL_NAME
              BUILD_NUM: $BITBUCKET_BUILD_NUMBER
              SCAN_NAME: "HCL_ASoC_SAST"
              DEBUG: "false"
        artifacts:
          - reports/*
```
