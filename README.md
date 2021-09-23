# Bitbucket Pipe for HCL AppScan on Cloud Static Analysis
This repo contains windows/linux docker image that uses python to download the SAClientUtil from HCL AppScan on Cloud and run static analysis against an application in Bitbucket pipelines. The script also will wait for the scan to complete and download a scan summary json file and a scan report. These files are all placed in a directory "reports" so they can be saved as artifacts of the pipeline. See the bitbucket-pipelines.yml example below. Most builds can happen on the linux image, but some projects, like .NET projects must be built on windows.

### Variables

The pipe has 8 variables.

| Variable |  Required | Description |
|---|---|---|
| API_KEY_ID | Required | The HCL AppScan on Cloud API Key ID |
| API_KEY_SECRET | Required | The HCL AppScan on Cloud API Key Secret |
| APP_ID | Required | The application Id of the app in AppScan on Cloud |
| TARGET_DIR | Required | The directory to be scanned. Place scan targets here. |
| REPO | Optional | The Repository name. Only really used to make filenames and comments relevant. |
| BUILD_NUM | Optional | The Bitbucket build number. Used to make filenames and comments relevant. |
| SCAN_NAME | Optional | The name of the scan in AppScan on Cloud |
| DEBUG | Optional | If true, prints additional debug info to the log. |

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
          # View README: https://github.com/cwtravis/bitbucket-asoc-sast
          - pipe: docker://cwtravis1/bitbucket_asoc_sast:linux
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

### Building The Images

Feel free to use my docker images just as shown in the example pipeline above. You can also use the following commands to build your own images and push to your dockerhub. Replace <YOUR_DOCKERHUB> with your dockerhub username.

Build and Push the Linux Image:
```shell
git clone https://github.com/cwtravis/bitbucket-asoc-sast.git
cd bitbucket-asoc-sast/linux
docker build -t asoc_sast_linux .
docker tag asoc_sast_linux <YOUR_DOCKERHUB>/bitbucket_asoc_sast:linux
docker push <YOUR_DOCKERHUB>/bitbucket_asoc_sast:linux
```

Build and Push the Windows Image:
```shell
git clone https://github.com/cwtravis/bitbucket-asoc-sast.git
cd bitbucket-asoc-sast/windows
docker build -t asoc_sast_win .
docker tag asoc_sast_win <YOUR_DOCKERHUB>/bitbucket_asoc_sast:windows
docker push <YOUR_DOCKERHUB>/bitbucket_asoc_sast:windows
```

Once your images are built, you can use them as in the example pipeline above.

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
              TARGET_DIR: $BITBUCKET_CLONE_DIR/AltoroJ 3.1.1/build/libs
              # Optional Variables
              REPO: $BITBUCKET_REPO_FULL_NAME
              BUILD_NUM: $BITBUCKET_BUILD_NUMBER
              SCAN_NAME: "HCL_ASoC_SAST"
              DEBUG: "false"
        artifacts:
          - reports/*
```

### Windows image is still under construction and does not work. 

If you have any questions raise an issue in this repo.

