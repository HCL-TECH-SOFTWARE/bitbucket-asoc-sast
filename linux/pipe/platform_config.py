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
Platform-specific constants for the Linux ASoC SAST Bitbucket Pipe.
"""

SACLIENT_TOOL_TYPE = "linux"
SACLIENT_DOWNLOAD_ENDPOINT = f"/api/v4/Tools/SAClientUtilByType?toolType={SACLIENT_TOOL_TYPE}"
APPSCAN_BIN_NAME = "appscan.sh"
