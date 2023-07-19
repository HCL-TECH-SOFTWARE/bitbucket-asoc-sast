# Changelog

All notable changes to this project will be documented in this file.

## Version 1.0.1 - 2023-07-19

- Updated Python to ver 3.11.4
- Updated Bitbucket Pipes Toolkit to ver 3.3.0
- Removed the optional environment variable `REPO` as it is already provided by BitBucket
- Added optional environment variable `CONFIG_FILE_PATH` to specify the location of a config file to use in the IRX generation process.
- Changed version semantic to a number instead of platform. Docker containers will specify a version number i.e. docker://cwtravis1/bitbucket_asoc_sast:1.0.1