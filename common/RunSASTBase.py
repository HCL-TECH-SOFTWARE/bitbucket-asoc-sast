#
# Copyright 2026 HCL America, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Base class for the AppScan on Cloud SAST Bitbucket Pipe.

Contains all shared pipeline logic.  Platform-specific behaviour is
provided by overriding two hook methods in a thin subclass:

    _get_reports_dir()          – where to write reports
    _resolve_appscan_path()     – how to locate the appscan binary
"""

from bitbucket_pipes_toolkit import Pipe, get_logger
from ASoC import ASoC
import requests
import urllib3
import socket
import os
import json
import time
import zipfile
import re
import datetime
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from constants import (
    VERSION,
    CONTENT_TYPE_ZIP,
    SCAN_FLAG_SAO, SCAN_FLAG_OSO,
    SCAN_STATUS_READY, SCAN_STATUS_ABORT,
    SCAN_POLL_INTERVAL_SECS, SCAN_LOG_INTERVAL_SECS, SCAN_MAX_WAIT_SECS,
    REPORT_POLL_INTERVAL_SECS, DOWNLOAD_LOG_INTERVAL_SECS,
    DOWNLOAD_CHUNK_SIZE, BYTES_PER_MB, FILE_PERMISSION_MODE, SECONDS_PER_DAY,
    SACLIENT_DIR, TARGET_DIR, REPORTS_DIR,
    SACLIENT_ZIP_FILENAME, SCAN_RESULTS_FILENAME, SCAN_ENV_FILENAME, REPORT_PATHS_FILENAME,
    SCAN_NAME_VALID_CHARS_REGEX, SCAN_NAME_REPLACEMENT_CHAR,
    DEFAULT_REPORT_TITLE, DEFAULT_REPORT_FILE_TYPE,
    MSG_PIPE_NAME, MSG_PIPELINE_ERROR, MSG_PIPELINE_SUCCESS,
    MSG_BOTH_OSO_SAO, MSG_SCAN_COMMENT,
    TIMESTAMP_FORMAT,
)
from platform_config import SACLIENT_DOWNLOAD_ENDPOINT, APPSCAN_BIN_NAME

# Disable SSL warnings when bypassing certificate verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger()

schema = {
    'SCAN_NAME': {'type': 'string', 'required': False, 'default': ""},
    'DATACENTER': {'type': 'string', 'required': False, 'default': "NA"},
    'SECRET_SCANNING': {'type': 'boolean', 'required': False, 'default': None},
    'CONFIG_FILE_PATH': {'type': 'string', 'required': False, 'default': ""},
    'REPO': {'type': 'string', 'required': False, 'default': ""},
    'BUILD_NUM': {'type': 'number', 'required': False, 'default': 0},
    'API_KEY_ID': {'type': 'string', 'required': True},
    'API_KEY_SECRET': {'type': 'string', 'required': True},
    'APP_ID': {'type': 'string', 'required': True},
    'TARGET_DIR': {'type': 'string', 'required': True, 'default': './'},
    'DEBUG': {'type': 'boolean', 'required': False, 'default': False},
    'STATIC_ANALYSIS_ONLY': {'type': 'boolean', 'required': False, 'default': False},
    'OPEN_SOURCE_ONLY': {'type': 'boolean', 'required': False, 'default': False},
    'ALLOW_UNTRUSTED': {'type': 'boolean', 'required': False, 'default': False},
    'SCAN_SPEED': {'type': 'string', 'required': False, 'default': ""},
    'PERSONAL_SCAN': {'type': 'boolean', 'required': False, 'default': False},
    'WAIT_FOR_ANALYSIS': {'type': 'boolean', 'required': False, 'default': True},
    'FAIL_FOR_NONCOMPLIANCE': {'type': 'boolean', 'required': False, 'default': False},
    'FAILURE_THRESHOLD': {'type': 'string', 'required': False, 'default': 'Low'},
    'OUTPUT_DIR': {'type': 'string', 'required': False, 'default': ''}
}


class AppScanOnCloudSASTBase(Pipe):
    """Base class containing all shared SAST pipeline logic.

    Subclasses **must** override:
        _get_reports_dir()          – platform-specific reports directory
        _resolve_appscan_path()     – platform-specific appscan binary path
    """

    asoc = None

    # ------------------------------------------------------------------
    # Platform hooks – override in subclasses
    # ------------------------------------------------------------------

    def _get_reports_dir(self):
        """Return the absolute path to the reports directory.

        Override per platform (e.g. cwd-relative on Linux,
        cloneDir-parent-relative on Windows).
        """
        raise NotImplementedError("Subclass must implement _get_reports_dir()")

    def _resolve_appscan_path(self, saclientPath, dirEntry):
        """Return the absolute path to the appscan binary.

        Args:
            saclientPath: The extracted SAClient directory.
            dirEntry: A directory entry inside saclientPath (version folder).
        """
        raise NotImplementedError("Subclass must implement _resolve_appscan_path()")

    # ------------------------------------------------------------------
    # Shared utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _get_repo_name_from_git(cwd=None):
        """Attempt to derive a repo name from the git remote URL.

        Runs ``git remote get-url origin`` in *cwd* (defaults to the
        process working directory) and parses the result, handling both
        SSH (``git@host:owner/repo.git``) and HTTPS
        (``https://host/owner/repo.git``) formats.

        Args:
            cwd: Directory in which to run the git command.  Should be
                 the cloned repository root so git can locate .git.

        Returns:
            A string such as ``owner/repo`` on success, or an empty
            string when the remote cannot be determined.
        """
        try:
            result = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                capture_output=True, text=True, timeout=10,
                cwd=cwd
            )
            url = result.stdout.strip()
            if not url:
                logger.warning("git remote get-url origin returned no output; cannot derive repo name")
                return ""
            # SSH format:  git@github.com:owner/repo.git
            ssh_match = re.match(r"git@[^:]+:(.+?)(?:\.git)?$", url)
            if ssh_match:
                return ssh_match.group(1)
            # HTTPS format: https://github.com/owner/repo.git
            https_match = re.match(r"https?://[^/]+/(.+?)(?:\.git)?$", url)
            if https_match:
                return https_match.group(1)
            logger.warning(f"Could not parse repo name from git remote URL: {url}")
        except FileNotFoundError:
            logger.warning("'git' binary not found in PATH; cannot derive repo name from remote URL")
        except Exception as e:
            logger.warning(f"Unexpected error running git to derive repo name: {e}")
        return ""

    @staticmethod
    def _safe_path_join(base_dir, *paths):
        """Safely join paths, ensuring result stays within base_dir to prevent path traversal.

        Resolves the final path to its canonical form and verifies it resides
        within the expected base directory.  Raises ValueError if a traversal
        is detected (e.g. via ``..`` components or symlinks).
        """
        sanitized_paths = tuple(p.lstrip(os.sep) for p in paths)
        joined = os.path.join(base_dir, *sanitized_paths)
        resolved = os.path.realpath(joined)
        base_resolved = os.path.realpath(base_dir)
        base_prefix = base_resolved if base_resolved.endswith(os.sep) else base_resolved + os.sep
        if not (resolved == base_resolved or resolved.startswith(base_prefix)):
            raise ValueError(
                f"Path traversal detected: '{joined}' resolves outside base directory '{base_dir}'"
            )
        return resolved

    # ------------------------------------------------------------------
    # Main pipeline entry point
    # ------------------------------------------------------------------

    def run(self):
        super().run()

        # Read Environment Vars
        env = dict(os.environ)

        # Read Provided Variables from BitBucket Pipeline
        scanName = self.get_variable('SCAN_NAME')
        apikeyid = self.get_variable('API_KEY_ID')
        apikeysecret = self.get_variable('API_KEY_SECRET')
        self.appID = self.get_variable('APP_ID')
        self.datacenter = self.get_variable('DATACENTER')
        self.debug = self.get_variable('DEBUG')
        self.cloneDir = self.get_variable('TARGET_DIR')
        self.secret_scanning = self.get_variable('SECRET_SCANNING')
        buildNum = self.get_variable('BUILD_NUM')
        self.static_analysis_only = self.get_variable('STATIC_ANALYSIS_ONLY')
        self.open_source_only = self.get_variable('OPEN_SOURCE_ONLY')
        self.scan_speed = self.get_variable('SCAN_SPEED')
        self.personal_scan = self.get_variable('PERSONAL_SCAN')
        self.wait_for_analysis = self.get_variable('WAIT_FOR_ANALYSIS')
        self.fail_for_noncompliance = self.get_variable('FAIL_FOR_NONCOMPLIANCE')
        self.failure_threshold = self.get_variable('FAILURE_THRESHOLD')
        self.output_dir = self.get_variable('OUTPUT_DIR')

        # Read Variables from the Environment
        self.repo = env.get('BITBUCKET_REPO_SLUG', "")
        self.repo_full_name = env.get('BITBUCKET_REPO_FULL_NAME', "")
        branch = env.get('BITBUCKET_BRANCH', "")
        self.commit = env.get('BITBUCKET_COMMIT', "")
        projectKey = env.get('BITBUCKET_PROJECT_KEY', "")
        self.repoOwner = env.get('BITBUCKET_REPO_OWNER', "")
        self.cwd = os.getcwd()

        # Ensure both SAO and OSO are not both selected
        if(self.static_analysis_only and self.open_source_only):
            logger.error("Cannot run IRGen with both 'Open Source Only' and 'Static Analysis Only' options")
            self.fail(message=MSG_BOTH_OSO_SAO)
            return False

        # Set SAO or OSO scan flags
        scan_flag = None
        if(self.static_analysis_only):
            logger.info("Setting scan mode to SAO")
            scan_flag = SCAN_FLAG_SAO
        if(self.open_source_only):
            logger.info("Setting scan mode to OSO")
            scan_flag = SCAN_FLAG_OSO

        configFile = None
        if len(self.get_variable('CONFIG_FILE_PATH')) > 0:
            config_path = self.get_variable('CONFIG_FILE_PATH')
            if os.path.isabs(config_path):
                configFile = os.path.realpath(config_path)
            else:
                configFile = self._safe_path_join(self.cwd, config_path)

        allow_untrusted = self.get_variable('ALLOW_UNTRUSTED')

        apikey = {
            "KeyId": apikeyid,
            "KeySecret": apikeysecret,
        }
        self.asoc = ASoC(apikey, logger, self.datacenter, allow_untrusted)
        client_type = self.asoc.getClientType()
        self.asoc.apikey["ClientType"] = client_type
        logger.info(f"Client Type for scan: {client_type}")
        logger.info(MSG_PIPE_NAME)
        logger.info(f"\tVersion: {VERSION}")
        if(self.debug):
            logger.setLevel('DEBUG')
            logger.info("Debug logging enabled")

        # Use Bitbucket repo name if scan name not provided;
        # fall back to git remote URL if the Bitbucket repo name is also absent.
        # fall back to APP_ID if neither is available.
        # Append a timestamp so derived names are unique per run.
        if not scanName:
            if self.repo:
                repo_name = self.repo
            else:
                logger.warning("BITBUCKET_REPO not set; attempting to derive repo name from git remote")
                repo_name = self._get_repo_name_from_git(cwd=self.cloneDir)
                if repo_name:
                    logger.warning(f"Derived repo name from git remote: {repo_name}")
                else:
                    logger.warning(f"Could not determine repo name from git remote; falling back to APP_ID: {self.appID}")
                    repo_name = self.appID
            timestamp = self.getTimeStamp()
            scanName = f"{repo_name}_{timestamp}" if repo_name else timestamp

        # Valid chars for a scan name: alphanumeric + [.-_ ]
        scanName = re.sub(SCAN_NAME_VALID_CHARS_REGEX, SCAN_NAME_REPLACEMENT_CHAR, scanName)
        comment = MSG_SCAN_COMMENT

        logger.info("========== Step 0: Preparation ====================")
        logger.info(f"SCAN_NAME: {scanName}")
        logger.info(f"APP_ID: {self.appID}")
        logger.info(f"BUILD_NUM: {buildNum}")
        logger.info(f"TARGET_DIR: {self.cloneDir}")
        if configFile is not None:
            logger.info(f"CONFIG_FILE_PATH: {configFile}")
        else:
            logger.info(f"CONFIG_FILE_PATH: Not Specified")
        logger.info(f"DATACENTER: {self.datacenter}")
        logger.info(f"SECRET_SCANNING: {self.secret_scanning}")
        logger.info(f"SCAN_SPEED: {self.scan_speed}")
        logger.info(f"DEBUG: {self.debug}")
        logger.debug(f"REPO: {self.repo}")
        logger.debug(f"REPO_FULL: {self.repo_full_name}")
        logger.debug(f"BRANCH: {branch}")
        logger.debug(f"COMMIT: {self.commit}")
        logger.debug(f"PROJECT_KEY: {projectKey}")
        logger.debug(f"REPO_OWNER: {self.repoOwner}")
        logger.debug(f"Current Working Dir: {self.cwd}")
        targetDir = self._safe_path_join(self.cwd, TARGET_DIR)
        logger.debug(f"SCAN TARGET: {targetDir}")

        cwd_dir_list = os.listdir(self.cwd)
        logger.debug(cwd_dir_list)
        clone_dir_list = os.listdir(self.cloneDir)
        logger.debug(clone_dir_list)

        # Check if config file actually exists
        if configFile is not None:
            if not os.path.exists(configFile):
                logger.error(f"Config Path Does Not Exist: {configFile}")
                logger.error(f"Using Defaults")
                configFile = None

        # Validate cloneDir to prevent path traversal
        safe_cloneDir = os.path.realpath(self.cloneDir)
        logger.info(f"Copying [{safe_cloneDir}] to [{targetDir}]")
        if(shutil.copytree(safe_cloneDir, targetDir) is None):
            logger.error("Cannot copy build clone dir into target dir")
            self.fail(message=MSG_PIPELINE_ERROR)
            return False

        # Create the saclient dir if it doesn't exist
        saclientPath = self._safe_path_join(self.cwd, SACLIENT_DIR)
        if(not os.path.isdir(saclientPath)):
            logger.debug(f"SAClient Path [{saclientPath}] does not exist")
            try:
                os.mkdir(saclientPath)
                logger.info(f"Created dir [{saclientPath}]")
            except:
                logger.error(f"Error creating saclient path [{saclientPath}]")
                self.fail(message=MSG_PIPELINE_ERROR)
                return False
            if(not os.path.isdir(saclientPath)):
                logger.error(f"Error creating saclient path [{saclientPath}]")
                self.fail(message=MSG_PIPELINE_ERROR)
                return False

        # Create Reports Dir if it does not exist (platform-specific location)
        reportsDir = self._get_reports_dir()

        # If OUTPUT_DIR is set, use it as an additional output location.
        # This allows self-hosted runners to point to a mounted volume path
        # so output files are directly accessible on the host without docker cp.
        if self.output_dir:
            self.output_dir = os.path.realpath(self.output_dir)
            logger.info(f"OUTPUT_DIR set: output files will also be written to [{self.output_dir}]")
            os.makedirs(self.output_dir, exist_ok=True)

        logger.info(f"Reports directory: {reportsDir}")
        if(not os.path.isdir(reportsDir)):
            logger.debug(f"Reports dir doesn't exist [{reportsDir}]")
            os.mkdir(reportsDir)
            if(not os.path.isdir(reportsDir)):
                logger.error(f"Cannot create reports dir! [{reportsDir}]")
                self.fail(message=MSG_PIPELINE_ERROR)
                return False
            else:
                logger.info(f"Created dir [{reportsDir}]")

        # Make sure we have write permission on the reports dir
        logger.info("Setting permissions on reports dir")
        os.chmod(reportsDir, FILE_PERMISSION_MODE)
        logger.info("========== Step 0: Complete =======================\n")

        # Step 1: Download the SAClientUtil
        logger.info("========== Step 1: Download SAClientUtil ==========")
        appscanPath = self.getSAClient(saclientPath)
        if(appscanPath is None):
            logger.error("AppScan Path not found, something went wrong with SAClientUtil Download?")
            self.fail(message=MSG_PIPELINE_ERROR)
            return False
        logger.info("========== Step 1: Complete =======================\n")

        # Step 2: Generate the IRX
        logger.info("========== Step 2: Generate IRX File ==============")
        if configFile is None:
            logger.info("Config file not specified. Using defaults.")

        irxPath = self.genIrx(scanName, appscanPath, targetDir, reportsDir, scan_flag, configFile, self.secret_scanning, self.scan_speed)
        if(irxPath is None):
            logger.error("IRX File Not Generated.")
            self.fail(message=MSG_PIPELINE_ERROR)
            return False
        logger.info("========== Step 2: Complete =======================\n")

        # Step 3: Run the Scan(s)
        logger.info("========== Step 3: Run the Scan on ASoC/A360° =========")
        scan_result = self.runScan(scanName, self.appID, irxPath, comment, self.wait_for_analysis, self.personal_scan)
        if(scan_result is None):
            logger.error("Error creating scan(s)")
            self.fail(message=MSG_PIPELINE_ERROR)
            return False
        sast_scan_id = scan_result.get('sast_scan_id')
        sca_scan_id = scan_result.get('sca_scan_id')
        self.scanID = sast_scan_id or sca_scan_id
        logger.info("========== Step 3: Complete =======================\n")

        # If WAIT_FOR_ANALYSIS is False, pipeline completes immediately after scan initiation
        if not self.wait_for_analysis:
            logger.info("WAIT_FOR_ANALYSIS=False: pipeline completing after scan submission")
            if sast_scan_id:
                logger.info(f"SAST Scan submitted: [{sast_scan_id}]")
            if sca_scan_id:
                logger.info(f"SCA Scan submitted: [{sca_scan_id}]")
            self.success(message=MSG_PIPELINE_SUCCESS)
            return

        # Step 4: Get the Scan Summary
        logger.info("========== Step 4: Fetch Scan Summary =============")
        summaries = {}
        summary_paths = {}
        for scan_type, scan_id in [('SAST', sast_scan_id), ('SCA', sca_scan_id)]:
            if scan_id is None:
                continue
            summaryFileName = scanName + f"_{scan_type.lower()}.json"
            sSummaryPath = self._safe_path_join(reportsDir, summaryFileName)
            summary_paths[scan_type] = sSummaryPath
            logger.debug(f"Fetching {scan_type} Scan Summary")
            scan_summary = self.getScanSummary(scan_id, sSummaryPath)
            if scan_summary is None:
                logger.error(f"Error getting {scan_type} scan summary")
            else:
                summaries[scan_type] = scan_summary
                self._logScanSummary(scan_type, scan_summary)

        combined_summary = self._combineSummaries(summaries) if summaries else None
        if combined_summary:
            if len(summaries) > 1:
                logger.info("Combined Summary (SAST + SCA):")
                self._logScanSummary("Combined", combined_summary)
            self.exportScanResults(combined_summary, scan_result, reportsDir)
        else:
            logger.error("No scan summaries available")
        logger.info("========== Step 4: Complete =======================\n")

        # Step 5: Download the Scan Report
        logger.info("========== Step 5: Download Scan Report ===========")
        notes = ""
        if(len(self.repo_full_name) > 0):
            notes += f"Bitbucket Repo: {self.repo_full_name} "
        if(buildNum != 0):
            notes += f"Build: {buildNum}"
        report_paths = {}
        for scan_type, scan_id in [('SAST', sast_scan_id), ('SCA', sca_scan_id)]:
            if scan_id is None:
                continue
            reportFileName = scanName + f"_{scan_type.lower()}.html"
            reportPath = self._safe_path_join(reportsDir, reportFileName)
            logger.info(f"Downloading {scan_type} report...")
            report = self.getReport(scan_id, reportPath, notes)
            if(report is None):
                logger.error(f"Error downloading {scan_type} report")
                self.fail(message=MSG_PIPELINE_ERROR)
                return False
            logger.info(f"{scan_type} Report Downloaded [{reportPath}]")
            report_paths[scan_type] = reportPath

        self.exportReportPaths(report_paths, summary_paths, reportsDir)
        logger.info("========== Step 5: Complete =======================\n")

        # Copy all output files to OUTPUT_DIR if specified (self-hosted Docker support)
        self._copyToOutputDir(reportsDir)

        # Step 6: Check for Non-Compliance (if enabled)
        if self.wait_for_analysis and self.fail_for_noncompliance and combined_summary is not None:
            logger.info("========== Step 6: Compliance Check ===============")
            issues_at_threshold = self.getIssuesAtOrAboveThreshold(combined_summary, self.failure_threshold)
            if issues_at_threshold > 0:
                logger.error(f"Non-compliance detected: {issues_at_threshold} issue(s) found at or above '{self.failure_threshold}' severity threshold")
                logger.error(f"  Threshold: {self.failure_threshold}")
                logger.error(f"  Critical Issues: {combined_summary['critical_issues']}")
                logger.error(f"  High Issues: {combined_summary['high_issues']}")
                logger.error(f"  Medium Issues: {combined_summary['medium_issues']}")
                logger.error(f"  Low Issues: {combined_summary['low_issues']}")
                logger.error(f"  Informational Issues: {combined_summary['info_issues']}")
                logger.info("========== Step 6: FAILED =========================\n")
                self.fail(message=f"Security scan failed: {issues_at_threshold} issue(s) at or above {self.failure_threshold} severity")
                return False
            else:
                logger.info(f"No issues found at or above '{self.failure_threshold}' severity threshold")
                logger.info("========== Step 6: Complete =======================\n")

        self.success(message=MSG_PIPELINE_SUCCESS)

    # ------------------------------------------------------------------
    # Output directory support (self-hosted Docker runners)
    # ------------------------------------------------------------------

    def _copyToOutputDir(self, reportsDir):
        """Copy all output files from reportsDir to OUTPUT_DIR when configured.

        For self-hosted runners executing the pipe via ``docker run``,
        OUTPUT_DIR should point to a path on a mounted volume so that
        output files (scan_env.sh, scan_output.json, HTML reports, etc.)
        are directly accessible on the host without ``docker cp``.

        When OUTPUT_DIR is not set (the default, and always the case on
        Bitbucket Cloud), this method returns immediately without doing
        anything.
        """
        if not self.output_dir:
            return
        if os.path.realpath(reportsDir) == self.output_dir:
            logger.debug("OUTPUT_DIR is the same as reportsDir; skipping copy")
            return
        logger.info(f"Copying output files to OUTPUT_DIR: [{self.output_dir}]")
        for entry in os.scandir(reportsDir):
            if entry.is_file():
                dest = os.path.join(self.output_dir, entry.name)
                shutil.copy2(entry.path, dest)
                logger.debug(f"Copied [{entry.name}] to [{self.output_dir}]")
        logger.info("Output files copied to OUTPUT_DIR successfully")

    # ------------------------------------------------------------------
    # Scan summary helpers
    # ------------------------------------------------------------------

    def createSummaryReport(self, scanSummaryJson):
        """ToDo: Create CodeInsights Report"""

    def _logScanSummary(self, label, summary):
        """Log a scan summary with a label."""
        seconds = summary["duration_seconds"] % SECONDS_PER_DAY
        hour = seconds // 3600
        seconds %= 3600
        minutes = seconds // 60
        seconds %= 60
        durationStr = "%d:%02d:%02d" % (hour, minutes, seconds)
        logger.info(f"{label} Scan Summary:")
        logger.info(f"\tDuration: {durationStr}")
        logger.info(f'\tTotal Issues: {summary["total_issues"]}')
        logger.info(f'\t\tCritical Issues: {summary["critical_issues"]}')
        logger.info(f'\t\tHigh Issues: {summary["high_issues"]}')
        logger.info(f'\t\tMed Issues: {summary["medium_issues"]}')
        logger.info(f'\t\tLow Issues: {summary["low_issues"]}')
        logger.info(f'\t\tInfo Issues: {summary["info_issues"]}')
        logger.debug(f"{label} Scan Summary:\n" + json.dumps(summary, indent=2))

    def _combineSummaries(self, summaries):
        """Combine multiple scan summaries into a single aggregated summary.

        Args:
            summaries: dict keyed by scan type ('SAST', 'SCA') with summary dicts as values

        Returns:
            Combined summary dict with aggregated issue counts
        """
        if not summaries:
            return None
        if len(summaries) == 1:
            return list(summaries.values())[0]

        combined = {
            "scan_name": " + ".join(s.get("scan_name", "Unknown") for s in summaries.values()),
            "scan_ids": {k: v.get("scan_id") for k, v in summaries.items()},
            "duration_seconds": max(s.get("duration_seconds", 0) for s in summaries.values()),
            "critical_issues": sum(s.get("critical_issues", 0) for s in summaries.values()),
            "high_issues": sum(s.get("high_issues", 0) for s in summaries.values()),
            "medium_issues": sum(s.get("medium_issues", 0) for s in summaries.values()),
            "low_issues": sum(s.get("low_issues", 0) for s in summaries.values()),
            "info_issues": sum(s.get("info_issues", 0) for s in summaries.values()),
            "total_issues": sum(s.get("total_issues", 0) for s in summaries.values()),
        }
        return combined

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------

    def exportScanResults(self, summary, scan_result, reportsDir):
        """Export scan results as environment variables and output files
        for use in subsequent Bitbucket Pipeline steps.
        """
        sast_scan_id = scan_result.get('sast_scan_id', '')
        sca_scan_id = scan_result.get('sca_scan_id', '')

        outputFile = self._safe_path_join(reportsDir, SCAN_RESULTS_FILENAME)
        envFile = self._safe_path_join(reportsDir, SCAN_ENV_FILENAME)

        # Write human-readable output
        with open(outputFile, 'w') as f:
            if sast_scan_id:
                f.write(f"SAST_SCAN_ID={sast_scan_id}\n")
            if sca_scan_id:
                f.write(f"SCA_SCAN_ID={sca_scan_id}\n")
            f.write(f"SCAN_NAME={summary['scan_name']}\n")
            f.write(f"TOTAL_ISSUES={summary['total_issues']}\n")
            f.write(f"CRITICAL_ISSUES={summary['critical_issues']}\n")
            f.write(f"HIGH_ISSUES={summary['high_issues']}\n")
            f.write(f"MEDIUM_ISSUES={summary['medium_issues']}\n")
            f.write(f"LOW_ISSUES={summary['low_issues']}\n")
            f.write(f"INFO_ISSUES={summary['info_issues']}\n")
            f.write(f"SCAN_DURATION_SECONDS={summary['duration_seconds']}\n")
            if 'createdAt' in summary:
                f.write(f"CREATED_AT={summary['createdAt']}\n")

        # Write shell-sourceable environment variables
        with open(envFile, 'w') as f:
            if sast_scan_id:
                f.write(f"export SAST_SCAN_ID='{sast_scan_id}'\n")
                f.write(f"export SAST_SCAN_URL='{self.asoc.getDataCenterURL()}/main/myapps/{self.appID}/scans/{sast_scan_id}'\n")
            if sca_scan_id:
                f.write(f"export SCA_SCAN_ID='{sca_scan_id}'\n")
                f.write(f"export SCA_SCAN_URL='{self.asoc.getDataCenterURL()}/main/myapps/{self.appID}/scans/{sca_scan_id}'\n")
            f.write(f"export SCAN_NAME='{summary['scan_name']}'\n")
            f.write(f"export TOTAL_ISSUES={summary['total_issues']}\n")
            f.write(f"export CRITICAL_ISSUES={summary['critical_issues']}\n")
            f.write(f"export HIGH_ISSUES={summary['high_issues']}\n")
            f.write(f"export MEDIUM_ISSUES={summary['medium_issues']}\n")
            f.write(f"export LOW_ISSUES={summary['low_issues']}\n")
            f.write(f"export INFO_ISSUES={summary['info_issues']}\n")
            f.write(f"export SCAN_DURATION_SECONDS={summary['duration_seconds']}\n")

        logger.info(f"Scan results exported to: {outputFile}")
        logger.info(f"Environment variables exported to: {envFile}")
        logger.info("To use in next pipeline step, add 'source reports/scan_env.sh' or parse scan_results.txt")

    def exportReportPaths(self, report_paths, summary_paths, reportsDir):
        """Export report file paths for artifact collection.

        Args:
            report_paths: dict keyed by scan type ('SAST', 'SCA') with HTML report paths
            summary_paths: dict keyed by scan type ('SAST', 'SCA') with JSON summary paths
            reportsDir: path to reports directory
        """
        pathsFile = self._safe_path_join(reportsDir, REPORT_PATHS_FILENAME)
        with open(pathsFile, 'w') as f:
            for scan_type in ['SAST', 'SCA']:
                if scan_type in report_paths:
                    f.write(f"{scan_type}_HTML_REPORT={report_paths[scan_type]}\n")
                if scan_type in summary_paths:
                    f.write(f"{scan_type}_JSON_SUMMARY={summary_paths[scan_type]}\n")
            f.write(f"REPORTS_DIR={reportsDir}\n")

        logger.info(f"Report paths exported to: {pathsFile}")
        logger.info("")
        logger.info("=" * 55)
        logger.info("PIPELINE OUTPUT SUMMARY")
        logger.info("=" * 55)
        for scan_type in ['SAST', 'SCA']:
            if scan_type in report_paths:
                logger.info(f"{scan_type} HTML Report: {report_paths[scan_type]}")
            if scan_type in summary_paths:
                logger.info(f"{scan_type} JSON Summary: {summary_paths[scan_type]}")
        logger.info(f"Scan Results: {self._safe_path_join(reportsDir, SCAN_RESULTS_FILENAME)}")
        logger.info(f"Environment File: {self._safe_path_join(reportsDir, SCAN_ENV_FILENAME)}")
        logger.info("")
        logger.info("To use these outputs in your bitbucket-pipelines.yml:")
        logger.info("1. Add artifacts section to preserve reports/")
        logger.info("2. Source the environment file: source reports/scan_env.sh")
        logger.info("3. Use variables like $CRITICAL_ISSUES in next steps")
        logger.info("=" * 55)

    # ------------------------------------------------------------------
    # Compliance check
    # ------------------------------------------------------------------

    def getIssuesAtOrAboveThreshold(self, summary, threshold):
        """Calculate the number of issues at or above the specified severity threshold.

        Args:
            summary: The scan summary dictionary containing issue counts
            threshold: Severity threshold string (Critical, High, Medium, Low, Informational)

        Returns:
            int: Total count of issues at or above the threshold
        """
        threshold_lower = threshold.lower() if threshold else 'low'

        critical = summary.get('critical_issues', 0)
        high = summary.get('high_issues', 0)
        medium = summary.get('medium_issues', 0)
        low = summary.get('low_issues', 0)
        info = summary.get('info_issues', 0)

        if threshold_lower == 'critical':
            return critical
        elif threshold_lower == 'high':
            return critical + high
        elif threshold_lower == 'medium':
            return critical + high + medium
        elif threshold_lower == 'low':
            return critical + high + medium + low
        elif threshold_lower in ['informational', 'info']:
            return critical + high + medium + low + info
        else:
            logger.warning(f"Invalid threshold '{threshold}', defaulting to 'Low'")
            return critical + high + medium + low

    # ------------------------------------------------------------------
    # SAClient download & extraction
    # ------------------------------------------------------------------

    def getSAClient(self, saclientPath="saclient"):
        """Download and unzip SAClientUtil to {cwd}/saclient."""
        url = self.asoc.getDataCenterURL() + SACLIENT_DOWNLOAD_ENDPOINT
        logger.info(f"Downloading SAClientUtil Zip from: {url}")

        try:
            if self.asoc.allow_untrusted:
                r = requests.get(url, stream=True, verify=False)
            else:
                r = requests.get(url, stream=True)
        except socket.gaierror as e:
            print(f"DNS resolution failed: {e}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"HTTP request failed: {e}")
            return None

        if(r.status_code != 200):
            logger.error("Invalid HTTP code downloading SAClient Util")
            return None

        file_size = int(r.headers.get("content-length", 0))
        chunk_size = DOWNLOAD_CHUNK_SIZE
        xfered = 0
        start = time.time()
        save_path = self._safe_path_join(self.cwd, SACLIENT_ZIP_FILENAME)
        with open(save_path, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=chunk_size):
                fd.write(chunk)
                xfered += len(chunk)
                mb = round(xfered / BYTES_PER_MB, 2)
                if file_size:
                    percent = round((xfered / file_size) * 100)
                else:
                    percent = 0
                if(time.time() - start > DOWNLOAD_LOG_INTERVAL_SECS):
                    logger.info(f"SAClientUtil Downloading: {mb}MB ({percent}%)...")
                    start = time.time()
        mb = round(xfered / BYTES_PER_MB, 2)
        logger.info(f"SAClientUtil Downloaded: {mb}MB")

        # Check if the downloaded file is a valid zip
        if r.headers.get('content-type', '').lower() != CONTENT_TYPE_ZIP:
            logger.error(f"Unexpected content-type: {r.headers.get('content-type')}")
            with open(save_path, 'rb') as f:
                sample = f.read(20000)
                logger.error(f"First 20000 bytes of file: {sample}")
            logger.error("Downloaded file is not a zip. Aborting extraction.")
            return None

        # Extract the downloaded file
        logger.info("Extracting SAClientUtil Zip")
        try:
            with zipfile.ZipFile(save_path, 'r') as zip_ref:
                zip_ref.extractall(saclientPath)
        except zipfile.BadZipFile:
            logger.error("Downloaded file is not a valid zip file. Aborting.")
            with open(save_path, 'rb') as f:
                sample = f.read(200)
                logger.error(f"First 200 bytes of file: {sample}")
            return None

        # Make sure all SAClientUtil files can be read and executed
        logger.info("Setting permissions on SAClientUtil Files")
        for root, dirs, files in os.walk(saclientPath):
            for d in dirs:
                dir_path = self._safe_path_join(root, d)
                os.chmod(dir_path, FILE_PERMISSION_MODE)
            for f in files:
                file_path = self._safe_path_join(root, f)
                os.chmod(file_path, FILE_PERMISSION_MODE)

        # Find the appscan executable (platform-specific path resolution)
        logger.debug("Finding appscan bin path")
        appscanPath = None
        dirs = os.listdir(saclientPath)
        for file in dirs:
            appscanPath = self._resolve_appscan_path(saclientPath, file)

        if(os.path.exists(appscanPath)):
            logger.debug(f"AppScan Bin Path [{appscanPath}]")
        else:
            logger.error("Something went wrong setting up the SAClientUtil")
            logger.error(f"AppScan Bin [{appscanPath}] not found!")
            return None

        return appscanPath

    # ------------------------------------------------------------------
    # IRX generation
    # ------------------------------------------------------------------

    def genIrx(self, scanName, appscanPath, targetPath, reportsDir, scan_flag, configFile=None, secret_scanning=False, scan_speed=""):
        """Generate IRX file for target directory."""
        logger.debug(f"Changing dir to target: [{targetPath}]")
        os.chdir(targetPath)
        logger.info("IRX Gen stdout will be saved to [reports]")
        logger.info(f"Secret Scanning Enabled: [{secret_scanning}]")

        logger.info("Running AppScan Prepare")
        irxFile = self.asoc.generateIRX(scanName, scan_flag, appscanPath, reportsDir, configFile, secret_scanning, self.debug, scan_speed)
        if(irxFile is None):
            logger.error("IRX Not Generated")
            return None

        irxPath = self._safe_path_join(targetPath, irxFile)
        logPath = self._safe_path_join(targetPath, scanName + "_logs.zip")

        logger.debug(f"Changing dir to previous working dir: [{self.cwd}]")
        os.chdir(self.cwd)

        # Copy logs to reports dir if they exist
        if(os.path.exists(logPath)):
            logger.debug(f"Logs Found [{logPath}]")
            logger.debug("Copying logs to reports dir")
            newLogPath = self._safe_path_join(reportsDir, scanName + "_logs.zip")
            res = shutil.copyfile(logPath, newLogPath)
            if(res):
                logger.info(f"Logs Saved: [{res}]")

        # Verify the IRX File Exists
        if(os.path.exists(irxPath)):
            logger.info(f"IRX Path [{irxPath}]")
            return irxPath

        logger.error(f"IRX File does not exist [{irxPath}]")
        return None

    # ------------------------------------------------------------------
    # Scan execution
    # ------------------------------------------------------------------

    def _waitForScan(self, scanId, label=""):
        """Wait for a single scan to complete. Returns (scanId, execution)."""
        logger.info(f"Waiting for {label} scan [{scanId}] to complete...")
        execution = self.asoc.getScanStatus(scanId)
        status = execution["Status"] if execution else SCAN_STATUS_ABORT
        progress = execution.get("Progress", "N/A") if execution else "N/A"
        scan_start = time.time()
        while(status not in [SCAN_STATUS_READY, SCAN_STATUS_ABORT]):
            elapsed = time.time() - scan_start
            if elapsed >= SCAN_MAX_WAIT_SECS:
                logger.error(f"{label} scan [{scanId}] timed out after {SCAN_MAX_WAIT_SECS}s")
                execution = None
                break
            time.sleep(SCAN_POLL_INTERVAL_SECS)
            execution = self.asoc.getScanStatus(scanId)
            status = execution["Status"] if execution else SCAN_STATUS_ABORT
            progress = execution.get("Progress", "N/A") if execution else "N/A"
            logger.info(f"\t{label} scan [{scanId}] status={status}, progress={progress}")

        if(status == SCAN_STATUS_READY):
            logger.info(f"{label} Scan [{scanId}] Complete")
        elif execution is not None:
            logger.error(f"{label} scan returned invalid status... check login?")
            logger.error("If script continues, the scan might not be complete")
            execution = None
        return (scanId, execution)

    def runScan(self, scanName, appId, irxPath, comment="", wait=True, personal_scan=False):
        """Create and run scan(s) based on scan mode.

        Returns a dict with 'sast_scan_id' and/or 'sca_scan_id' keys,
        or None on error.

        - STATIC_ANALYSIS_ONLY: runs SAST scan only
        - OPEN_SOURCE_ONLY: runs SCA scan only
        - Neither: runs both SAST and SCA scans in parallel
        """
        # Verify that ASoC is logged in, if not then login
        logger.debug("Login to ASoC/A360°")
        if(not self.asoc.checkAuth()):
            if(self.asoc.login()):
                logger.info("Successfully logged into ASoC/A360° API")
            else:
                logger.error("Error logging into ASoC/A360°!")
                return None

        # Verify that appId exists
        logger.debug(f"Checking AppId [{appId}]")
        app = self.asoc.getApplication(appId)
        if(app):
            appName = app["Name"]
            logger.info("App Found:")
            logger.info(f"\t[{appName}] - [{appId}]")
        else:
            logger.error("Invalid AppId: App Not Found!")
            return None

        # Upload the IRX File and get a FileId
        logger.debug("Uploading IRX File")
        fileId = self.asoc.uploadFile(irxPath)
        if(fileId is None):
            logger.error("Error uploading IRX File")
            return None
        logger.debug(f"IRX FileId: [{fileId}]")

        # Create scan(s) based on mode
        scan_result = {}

        if self.static_analysis_only:
            logger.info("Creating SAST scan (Static Analysis Only)")
            sast_id = self.asoc.createSastScan(scanName, appId, fileId, comment, personal_scan)
            if sast_id:
                scan_result['sast_scan_id'] = sast_id
                logger.info(f"SAST ScanId: [{sast_id}]")
            else:
                logger.error("SAST scan not created!")
                return None
        elif self.open_source_only:
            logger.info("Creating SCA scan (Open Source Only)")
            sca_id = self.asoc.createScaScan(scanName, appId, fileId, comment, personal_scan)
            if sca_id:
                scan_result['sca_scan_id'] = sca_id
                logger.info(f"SCA ScanId: [{sca_id}]")
            else:
                logger.error("SCA scan not created!")
                return None
        else:
            logger.info("Creating both SAST and SCA scans")
            sast_id = self.asoc.createSastScan(scanName, appId, fileId, comment, personal_scan)
            sca_id = self.asoc.createScaScan(scanName, appId, fileId, comment, personal_scan)
            if sast_id:
                scan_result['sast_scan_id'] = sast_id
                logger.info(f"SAST ScanId: [{sast_id}]")
            else:
                logger.error("SAST scan not created!")
                return None
            if sca_id:
                scan_result['sca_scan_id'] = sca_id
                logger.info(f"SCA ScanId: [{sca_id}]")
            else:
                logger.error("SCA scan not created!")
                return None

        # If Wait=False, return now with scan_result
        if(wait == False):
            logger.info("Do not wait for scan(s) to complete, return immediately")
            return scan_result

        # Wait for all scans in parallel
        self.lastExecutions = {}
        scans_to_wait = []
        if 'sast_scan_id' in scan_result:
            scans_to_wait.append(('SAST', scan_result['sast_scan_id']))
        if 'sca_scan_id' in scan_result:
            scans_to_wait.append(('SCA', scan_result['sca_scan_id']))

        with ThreadPoolExecutor(max_workers=len(scans_to_wait)) as executor:
            futures = {
                executor.submit(self._waitForScan, scan_id, label): (label, scan_id)
                for label, scan_id in scans_to_wait
            }
            for future in as_completed(futures):
                label, scan_id = futures[future]
                try:
                    _, execution = future.result()
                    self.lastExecutions[scan_id] = execution
                except Exception as e:
                    logger.error(f"Error waiting for {label} scan: {e}")
                    self.lastExecutions[scan_id] = None

        return scan_result

    # ------------------------------------------------------------------
    # Report download
    # ------------------------------------------------------------------

    def getReport(self, scanId, reportPath, note=""):
        """Download a report based on a scan."""
        reportConfig = {
            "Configuration": {
                "Summary": True,
                "Overview": True,
                "TableOfContent": True,
                "Advisories": True,
                "FixRecommendation": True,
                "MinimizeDetails": True,
                "ReportFileType": DEFAULT_REPORT_FILE_TYPE,
                "Title": DEFAULT_REPORT_TITLE,
                "Notes": note
            }
        }
        reportId = self.asoc.startReport(scanId, reportConfig)
        if(reportId is None):
            logger.error("Error starting report")
            return None

        statusMsg = self.asoc.reportStatus(reportId)
        while(statusMsg["Items"][0].get("Status") not in [SCAN_STATUS_READY, SCAN_STATUS_ABORT]):
            time.sleep(REPORT_POLL_INTERVAL_SECS)
            statusMsg = self.asoc.reportStatus(reportId)
            percent = statusMsg["Items"][0].get("Progress")
            logger.info(f"Report Progress: {percent}%")

        if(statusMsg["Items"][0].get("Status") != SCAN_STATUS_READY):
            logger.error("Problem generating report")
            return None
        logger.info("Report Complete, downloading report")

        result = self.asoc.downloadReport(reportId, reportPath)
        if(not result):
            logger.error(f"Error Downloading Report")
        return os.path.exists(reportPath)

    # ------------------------------------------------------------------
    # Scan summary
    # ------------------------------------------------------------------

    def getScanSummary(self, scanId, summaryPath):
        """Get scan summary from the execution data obtained during status polling.

        Uses the execution data already retrieved by getScanStatus to avoid
        an additional API call.
        """
        executions = getattr(self, 'lastExecutions', {})
        execution = executions.get(scanId)
        if execution is None:
            logger.error("No execution data available from scan status")
            return None

        scan_name = execution.get("FileName", "Unknown")
        if scan_name.endswith(".irx"):
            scan_name = scan_name[:-4]

        summaryDict = {
            "scan_name": scan_name,
            "scan_id": execution["ScanId"],
            "execution_id": execution["Id"],
            "createdAt": execution["CreatedAt"],
            "duration_seconds": execution["ExecutionDurationSec"],
            "critical_issues": execution["NCriticalIssues"],
            "high_issues": execution["NHighIssues"],
            "medium_issues": execution["NMediumIssues"],
            "low_issues": execution["NLowIssues"],
            "info_issues": execution["NInfoIssues"],
            "total_issues": execution["NIssuesFound"],
            "opensource_licenses": execution["NOpenSourceLicenses"],
            "opensource_packages": execution["NOpenSourcePackages"]
        }
        logger.info(f"Scan summary saved [{summaryPath}]")
        with open(summaryPath, "w") as summaryFile:
            json.dump(execution, summaryFile, indent=4)
        return summaryDict

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def getTimeStamp(self):
        """Get current system timestamp."""
        ts = time.time()
        return datetime.datetime.fromtimestamp(ts).strftime(TIMESTAMP_FORMAT)
