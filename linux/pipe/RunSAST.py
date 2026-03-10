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
Linux entry point for the AppScan on Cloud SAST Bitbucket Pipe.

Provides only the two platform-specific overrides; all shared logic
lives in common/RunSASTBase.py.
"""

import os
from constants import REPORTS_DIR
from platform_config import APPSCAN_BIN_NAME
from RunSASTBase import AppScanOnCloudSASTBase, schema


class AppScanOnCloudSAST(AppScanOnCloudSASTBase):
    """Linux-specific SAST pipe."""

    def _get_reports_dir(self):
        """On Linux the reports directory is relative to the working directory."""
        return self._safe_path_join(self.cwd, REPORTS_DIR)

    def _resolve_appscan_path(self, saclientPath, dirEntry):
        """On Linux the appscan binary is under saclientPath/<version>/bin/."""
        return self._safe_path_join(saclientPath, dirEntry, "bin", APPSCAN_BIN_NAME)


if __name__ == '__main__':
    pipe = AppScanOnCloudSAST(pipe_metadata='/pipe.yml', schema=schema)
    pipe.run()
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    