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
Centralized shared constants for the ASoC SAST Bitbucket Pipe.
Platform-specific values (SACLIENT_TOOL_TYPE, APPSCAN_BIN_NAME,
SACLIENT_DOWNLOAD_ENDPOINT) are defined in each platform's
platform_config.py file.
"""

# =============================================================================
# Version Information
# =============================================================================
VERSION = "2.0.0"

# =============================================================================
# Datacenter Configuration
# =============================================================================
DATACENTER_EU = "EU"
DATACENTER_NA = "NA"
DATACENTER_URL_ASOC_EU = "https://eu.cloud.appscan.com"
DATACENTER_URL_ASOC_US = "https://cloud.appscan.com"

# =============================================================================
# API Endpoints (appended to base_url)
# =============================================================================
API_LOGIN = "/api/v4/Account/ApiKeyLogin"
API_LOGOUT = "/api/v4/Account/Logout"
API_TENANT_INFO = "/api/v4/Account/TenantInfo"
API_FILE_UPLOAD = "/api/v4/FileUpload"
API_SAST_SCAN = "/api/v4/Scans/Sast/"
API_SCA_SCAN = "/api/v4/Scans/Sca/"
API_SCAN_EXECUTIONS = "/api/v4/Scans/{scan_id}/Executions?%24top=1&%24count=false"
API_APPS = "/api/v4/Apps/"
API_SAST_EXECUTION = "/api/v4/Scans/SastExecution/"
API_SCA_EXECUTION = "/api/v4/Scans/ScaExecution/"
API_ISSUES = "/api/v4/Issues/"
API_REPORT_SECURITY_SCAN = "/api/v4/Reports/Security/Scan/"
API_REPORTS_FILTER = "/api/v4/Reports?filter=Id%20eq%20"
API_REPORT_DOWNLOAD = "/api/v4/Reports/{report_id}/Download"

# =============================================================================
# HTTP Headers & Content Types
# =============================================================================
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_OCTET_STREAM = "application/octet-stream"
CONTENT_TYPE_ZIP = "application/zip"

# =============================================================================
# Scan Mode Flags
# =============================================================================
SCAN_FLAG_SAO = "-sao"
SCAN_FLAG_OSO = "-oso"

# =============================================================================
# Scan Statuses
# =============================================================================
SCAN_STATUS_READY = "Ready"
SCAN_STATUS_ABORT = "Abort"

# =============================================================================
# Timing & Polling (seconds)
# =============================================================================
REPORT_WAIT_INTERVAL_SECS = 3
REPORT_WAIT_TIMEOUT_SECS = 60
SCAN_POLL_INTERVAL_SECS = 15
SCAN_LOG_INTERVAL_SECS = 120
SCAN_MAX_WAIT_SECS = 14400
REPORT_POLL_INTERVAL_SECS = 5
DOWNLOAD_LOG_INTERVAL_SECS = 3

# =============================================================================
# Magic Numbers
# =============================================================================
DOWNLOAD_CHUNK_SIZE = 4096
BYTES_PER_MB = 1048576
FILE_PERMISSION_MODE = 0o755
SECONDS_PER_DAY = 24 * 3600

# =============================================================================
# Directory & File Names
# =============================================================================
SACLIENT_DIR = "saclient"
TARGET_DIR = "target"
REPORTS_DIR = "reports"
SACLIENT_ZIP_FILENAME = "saclient.zip"
SCAN_RESULTS_FILENAME = "scan_results.txt"
SCAN_ENV_FILENAME = "scan_env.sh"
REPORT_PATHS_FILENAME = "report_paths.txt"

# =============================================================================
# Scan Name Validation
# =============================================================================
SCAN_NAME_VALID_CHARS_REGEX = r'[^a-zA-Z0-9\s_\-\.]'
SCAN_NAME_REPLACEMENT_CHAR = '_'

# =============================================================================
# Report Configuration Defaults
# =============================================================================
DEFAULT_REPORT_TITLE = "HCL ASoC SAST Security Report"
DEFAULT_REPORT_FILE_TYPE = "Html"

# =============================================================================
# User-Facing Messages
# =============================================================================
MSG_PIPE_NAME = "Executing Pipe: HCL AppScan on Cloud SAST"
MSG_PIPELINE_ERROR = "Error Running ASoC SAST Pipeline"
MSG_PIPELINE_SUCCESS = "ASoC SAST Pipeline Complete"
MSG_BOTH_OSO_SAO = "Both OSO and SAO selected"
MSG_SCAN_COMMENT = "This scan was created via BitBucket Pipeline"
MSG_ERROR_SUBMITTING_SCAN = "Error submitting scan"
MSG_ASOC_REPORT_STATUS = "ASoC Report Status"
MSG_ASOC_APP_SUMMARY_ERROR = "ASoC App Summary Error Response"

# =============================================================================
# Timestamp Format
# =============================================================================
TIMESTAMP_FORMAT = '%Y-%m-%d_%H-%M-%S'
CLIENT_TYPE_FORMAT = "bitbucket-<os>-<plugin-version>"
CLIENT_TYPE_A360_FORMAT = "bitbucket-<plugin-version>"
