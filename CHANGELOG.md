# Changelog

All notable changes to this project will be documented in this file.

## Version 1.1.2 - 2024-11-12

- Updated linux pipe to work with ASoC v4 APIs.
- Added initial support for OSO and SAO scanning.
- Added support for AppScan 360 url

## Version 1.1.1 - 2023-10-11

- Added optional pipeline variable `CONFIG_FILE_PATH` to the docs. It was added previously but not in the example or help docs.
  - Providing a config file may override other pipeline variables (e.g. `SECRET_SCANNING`)
- Added optional pipeline variable `SECRET_SCANNING`
  - False is the default. Setting this to True will enable the secret scanner, which could impact scan time.

## Version 1.1.0 - 2023-10-11

- Added optional pipeline variable `DATACENTER` to specify which ASOC datacenter to connect to.
  - "NA" (default) or "EU"

- Fixed an scan summary misreporting issue counts.

## Version 1.0.1 - 2023-07-19

- Updated Python to ver 3.11.4
- Updated Bitbucket Pipes Toolkit to ver 3.3.0
- Removed the optional environment variable `REPO` as it is already provided by BitBucket
- Added optional environment variable `CONFIG_FILE_PATH` to specify the location of a config file to use in the IRX generation process.
- Changed version semantic to a number instead of platform. Docker containers will specify a version number i.e. docker://cwtravis1/bitbucket_asoc_sast:1.0.1